"""
🚀 DEDIKKA ULTRA LOAD BALANCER & RESILIENCE PROXY (app.py)
==========================================================
Load Balancer tout-en-un de niveau production, 100% autonome.
Ne modifie aucun fichier de votre application actuelle.

Fonctionnalités intégrées :
1. Algorithme « Least Connections » (Route toujours vers le serveur le moins chargé).
2. Auto-Retry Transparent (Bascule instantanée sur un autre serveur en cas de 502/Timeout).
3. Gestion CORS ultra-rapide en 0 ms (Traite les requêtes OPTIONS directement).
4. Protection Anti-DDoS & Rate Limiting en mémoire.
5. Surveillance active & Ping toutes les 10 minutes sur /api/v1/health.
6. Alertes automatiques Telegram & Discord.
7. Dashboard visuel HTML en direct sur : /_balancer/dashboard
8. Logs rotatifs par heure / jour / mois avec affichage en live.
9. Résistant à 2 Go de bande passante/jour sur Render.

Lancement :
   python app.py
   ou en prod : uvicorn app:app --host 0.0.0.0 --port 8080 --workers 2
"""

import asyncio
import gzip
import json
import os
import sys
import time
import logging
import threading

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, HTMLResponse

# ==============================================================================
# CONFIGURATION GÉNÉRALE & VARIABLES D'ENVIRONNEMENT
# ==============================================================================

DEFAULT_SERVERS = [
    "https://dedikka.onrender.com",
    # Ajoutez d'autres instances :
    # "https://dedikka-api-2.onrender.com",
]

env_backends = os.getenv("BACKEND_URLS")
BACKEND_SERVERS: List[str] = (
    [u.strip().rstrip("/") for u in env_backends.split(",") if u.strip()]
    if env_backends else DEFAULT_SERVERS
)

HEALTH_ENDPOINT        = os.getenv("HEALTH_ENDPOINT", "/api/v1/health")
PING_INTERVAL_SECONDS  = int(os.getenv("PING_INTERVAL_SECONDS", "600"))
PING_TIMEOUT_SECONDS   = float(os.getenv("PING_TIMEOUT_SECONDS", "10.0"))
MAX_RETRIES            = int(os.getenv("MAX_RETRIES", "2"))
PROXY_TIMEOUT_SECONDS  = float(os.getenv("PROXY_TIMEOUT_SECONDS", "45.0"))
RATE_LIMIT_PER_MINUTE  = int(os.getenv("RATE_LIMIT_PER_MINUTE", "120"))
RATE_LIMIT_ENABLED     = os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true"
TELEGRAM_BOT_TOKEN     = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID       = os.getenv("TELEGRAM_CHAT_ID", "")
DISCORD_WEBHOOK_URL    = os.getenv("DISCORD_WEBHOOK_URL", "")
VERIFY_SSL             = os.getenv("VERIFY_SSL", "true").lower() == "true"

# Sécurité : Clé admin OBLIGATOIREMENT via variable d'environnement BALANCER_ADMIN_KEY sur Render.
# Si absente au démarrage, une clé aléatoire forte est générée et affichée UNE SEULE FOIS dans les logs.
import secrets as _secrets
BALANCER_ADMIN_KEY = os.getenv("BALANCER_ADMIN_KEY", "").strip()
if not BALANCER_ADMIN_KEY:
    BALANCER_ADMIN_KEY = _secrets.token_urlsafe(32)
    print(
        f"\n⚠️  SÉCURITÉ — BALANCER_ADMIN_KEY non définie dans les variables d'environnement !\n"
        f"   Clé temporaire générée pour cette session uniquement :\n"
        f"   👉  {BALANCER_ADMIN_KEY}\n"
        f"   → Ajoutez BALANCER_ADMIN_KEY dans vos variables Render pour la fixer définitivement.\n",
        flush=True
    )

DEFAULT_ALLOWED_ORIGINS = {
    "https://dedikka.web.app",
    "https://dedikka.firebaseapp.com",
    "https://loadpage.onrender.com",  # Load Balancer lui-même (dashboard externe)
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:5000",
    "http://127.0.0.1:5000",
}
env_origins = os.getenv("ALLOWED_ORIGINS", "")
ALLOWED_ORIGINS = set(
    [o.strip().rstrip("/") for o in env_origins.split(",") if o.strip()]
) if env_origins else DEFAULT_ALLOWED_ORIGINS

# ==============================================================================
# SYSTÈME DE LOGS ROTATIFS PAR HEURE / JOUR / MOIS
# ==============================================================================

LOGS_BASE_DIR = Path(os.getenv("LOGS_DIR", "logs"))
LOG_MAX_SIZE_MB = int(os.getenv("LOG_MAX_SIZE_MB", "50"))   # Rotation si fichier dépasse 50 Mo
LOG_COMPRESS_AFTER_HOURS = int(os.getenv("LOG_COMPRESS_AFTER_HOURS", "2"))  # Compresse après 2h

_log_write_lock = threading.Lock()

# Compteurs en mémoire pour les rapports agrégés
_stats_lock = threading.Lock()
_hourly_stats: Dict[str, dict] = {}   # clé: "2026-10-22T20"
_daily_stats: Dict[str, dict]  = {}   # clé: "2026-10-22"
_monthly_stats: Dict[str, dict] = {}  # clé: "2026-10"

def _now_local() -> datetime:
    """Heure locale de la machine (sur Render = UTC, adaptez TZ si besoin)."""
    return datetime.now(timezone.utc).astimezone()

def _log_paths(dt: datetime) -> dict:
    """Retourne les chemins des fichiers de log pour un instant donné."""
    month_dir  = LOGS_BASE_DIR / dt.strftime("%Y-%m")
    day_dir    = month_dir / dt.strftime("%Y-%m-%d")
    hour_key   = dt.strftime("%Hh")
    return {
        "month_dir": month_dir,
        "day_dir":   day_dir,
        "hourly":    day_dir   / f"{hour_key}.log",
        "daily":     day_dir   / "daily.log",
        "monthly":   month_dir / "monthly.log",
    }

def _ensure_dirs(paths: dict):
    paths["day_dir"].mkdir(parents=True, exist_ok=True)
    paths["month_dir"].mkdir(parents=True, exist_ok=True)

def _rotate_if_needed(path: Path):
    """Compresse et archive le fichier si trop volumineux."""
    try:
        if path.exists() and path.stat().st_size > LOG_MAX_SIZE_MB * 1024 * 1024:
            archive = path.with_suffix(f".{int(time.time())}.log.gz")
            with open(path, "rb") as f_in, gzip.open(archive, "wb") as f_out:
                f_out.writelines(f_in)
            path.unlink()
    except Exception:
        pass

def _write_log_line(entry: dict):
    """Écrit une ligne JSON dans les 3 fichiers (heure / jour / mois) de manière thread-safe."""
    dt = _now_local()
    paths = _log_paths(dt)
    line = json.dumps(entry, ensure_ascii=False) + "\n"

    with _log_write_lock:
        _ensure_dirs(paths)
        for key in ("hourly", "daily", "monthly"):
            p = paths[key]
            _rotate_if_needed(p)
            try:
                with open(p, "a", encoding="utf-8") as f:
                    f.write(line)
            except Exception:
                pass

def _update_stats(entry: dict):
    """Met à jour les compteurs agrégés en mémoire."""
    dt   = _now_local()
    hkey = dt.strftime("%Y-%m-%dT%H")
    dkey = dt.strftime("%Y-%m-%d")
    mkey = dt.strftime("%Y-%m")

    status = entry.get("status_code", 0)
    lat    = entry.get("latency_ms", 0)
    size   = entry.get("response_bytes", 0)

    with _stats_lock:
        for store, key in ((_hourly_stats, hkey), (_daily_stats, dkey), (_monthly_stats, mkey)):
            if key not in store:
                store[key] = {"requests": 0, "errors": 0, "total_bytes": 0,
                               "total_latency_ms": 0, "peak_concurrent": 0}
            s = store[key]
            s["requests"]        += 1
            s["total_bytes"]     += size
            s["total_latency_ms"] += lat
            if status >= 400:
                s["errors"] += 1

async def log_request(request: Request, status_code: int, latency_ms: float,
                      backend_url: str, response_bytes: int = 0, retried: bool = False):
    """Enregistre une requête complète dans les logs et les stats."""
    dt = _now_local()
    forwarded = request.headers.get("x-forwarded-for")
    client_ip = forwarded.split(",")[0].strip() if forwarded else (
        request.client.host if request.client else "unknown"
    )
    entry = {
        "ts":             dt.strftime("%Y-%m-%d %H:%M:%S"),
        "ts_epoch":       dt.timestamp(),
        "ip":             client_ip,
        "method":         request.method,
        "path":           str(request.url.path),
        "query":          str(request.url.query) or None,
        "status_code":    status_code,
        "latency_ms":     round(latency_ms, 2),
        "response_bytes": response_bytes,
        "backend":        backend_url,
        "retried":        retried,
        "user_agent":     request.headers.get("user-agent", "")[:120],
    }
    # Écriture non-bloquante dans un thread séparé
    asyncio.get_event_loop().run_in_executor(None, _write_log_line, entry)
    asyncio.get_event_loop().run_in_executor(None, _update_stats, entry)

# Logging console standard (gardé pour Render dashboard)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [DedikkaBalancer] %(message)s"
)
logger = logging.getLogger("DedikkaBalancer")

# ==============================================================================
# ÉTAT DES SERVEURS (MÉTRIQUES & MOINDRE CONNEXION)
# ==============================================================================

class BackendServer:
    def __init__(self, url: str):
        self.url = url
        self.is_healthy: bool = True
        self.active_connections: int = 0
        self.total_routed_requests: int = 0
        self.total_retried_requests: int = 0
        self.last_check_time: Optional[float] = None
        self.last_latency_ms: Optional[float] = None
        self.last_status_code: Optional[int] = None
        self.consecutive_failures: int = 0
        self.last_error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "url":                self.url,
            "status":             "ONLINE" if self.is_healthy else "OFFLINE",
            "active_connections": self.active_connections,
            "total_requests":     self.total_routed_requests,
            "total_retries":      self.total_retried_requests,
            "last_latency":       f"{self.last_latency_ms:.1f} ms" if self.last_latency_ms else "N/A",
            "last_status_code":   self.last_status_code,
            "last_check_ago":     f"{int(time.time() - self.last_check_time)}s" if self.last_check_time else "Jamais",
            "consecutive_failures": self.consecutive_failures,
            "last_error":         self.last_error,
        }

backends: Dict[str, BackendServer] = {url: BackendServer(url) for url in BACKEND_SERVERS}
http_client: Optional[httpx.AsyncClient] = None
balancer_start_time = time.time()
last_ping_time: Optional[float] = None
next_ping_time: Optional[float] = None

# ==============================================================================
# ALERTES TELEGRAM & DISCORD
# ==============================================================================

async def send_alert_notification(message: str):
    logger.warning(f"📢 Alerte : {message}")
    async with httpx.AsyncClient(timeout=8.0) as client:
        if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
            try:
                await client.post(
                    f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                    json={"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "Markdown"}
                )
            except Exception as e:
                logger.error(f"Telegram alert failed: {e}")
        if DISCORD_WEBHOOK_URL:
            try:
                await client.post(DISCORD_WEBHOOK_URL, json={"content": message})
            except Exception as e:
                logger.error(f"Discord alert failed: {e}")

# ==============================================================================
# ALGORITHME LEAST CONNECTIONS
# ==============================================================================

def select_best_backend(exclude_urls: Optional[set] = None) -> Optional[BackendServer]:
    exclude   = exclude_urls or set()
    available = [b for b in backends.values() if b.is_healthy and b.url not in exclude]
    if not available:
        available = [b for b in backends.values() if b.url not in exclude]
    if not available:
        return None
    available.sort(key=lambda b: (b.active_connections, b.total_routed_requests))
    return available[0]

# ==============================================================================
# ANTI-DDOS / RATE LIMITING
# ==============================================================================

rate_limit_records = defaultdict(list)
rate_limit_lock    = asyncio.Lock()
EXEMPT_PATHS       = ("/api/v1/payments/", "/api/v1/webhooks/", "/_balancer/", "/health", "/ping", "/healthz")

async def is_rate_limited(ip: str, path: str, user_agent: str = "") -> bool:
    if not RATE_LIMIT_ENABLED:
        return False
    if "uptimerobot" in user_agent.lower():
        return False
    if any(path.startswith(p) for p in EXEMPT_PATHS):
        return False
    now          = time.time()
    window_start = now - 60.0
    async with rate_limit_lock:
        rate_limit_records[ip] = [t for t in rate_limit_records[ip] if t > window_start]
        if len(rate_limit_records[ip]) >= RATE_LIMIT_PER_MINUTE:
            return True
        rate_limit_records[ip].append(now)
        return False

# ==============================================================================
# SURVEILLANCE & PING (ANTI-VEILLE RENDER)
# ==============================================================================

async def check_backend_health(client: httpx.AsyncClient, backend: BackendServer):
    target_url = f"{backend.url}{HEALTH_ENDPOINT}"
    start      = time.time()
    try:
        response = await client.get(target_url, timeout=PING_TIMEOUT_SECONDS)
        latency  = (time.time() - start) * 1000
        backend.last_check_time  = time.time()
        backend.last_latency_ms  = latency
        backend.last_status_code = response.status_code

        if 200 <= response.status_code < 400:
            if not backend.is_healthy:
                asyncio.create_task(send_alert_notification(
                    f"✅ *RÉTABLISSEMENT DEDIKKA* : `{backend.url}` est de nouveau ONLINE — Latence : {latency:.1f}ms."
                ))
            backend.is_healthy          = True
            backend.consecutive_failures = 0
            backend.last_error          = None
        else:
            raise Exception(f"HTTP {response.status_code}")

    except Exception as exc:
        latency = (time.time() - start) * 1000
        backend.last_check_time  = time.time()
        backend.last_latency_ms  = latency
        backend.last_status_code = None
        backend.consecutive_failures += 1
        backend.last_error = str(exc)
        if backend.is_healthy:
            backend.is_healthy = False
            asyncio.create_task(send_alert_notification(
                f"🚨 *PANNE DEDIKKA* : `{backend.url}` ne répond plus !\nErreur : `{exc}`."
            ))

async def execute_cluster_ping() -> dict:
    global last_ping_time, next_ping_time
    last_ping_time = time.time()
    next_ping_time = last_ping_time + PING_INTERVAL_SECONDS
    logger.info("🛰️ [PING 10 MIN] Ping de santé & anti-veille Render en cours...")
    async with httpx.AsyncClient(verify=VERIFY_SSL) as client:
        await asyncio.gather(*[check_backend_health(client, b) for b in backends.values()])
    online = sum(1 for b in backends.values() if b.is_healthy)
    logger.info(f"📊 [PING 10 MIN] {online}/{len(backends)} serveurs ONLINE. Prochain ping dans {PING_INTERVAL_SECONDS // 60} min.")
    return {
        "status":              "success",
        "online_servers":      online,
        "total_servers":       len(backends),
        "last_ping_time":      time.strftime("%H:%M:%S", time.localtime(last_ping_time)),
        "next_ping_in_minutes": PING_INTERVAL_SECONDS / 60,
    }

async def periodic_health_monitor():
    await asyncio.sleep(2)
    while True:
        try:
            await execute_cluster_ping()
        except Exception as e:
            logger.error(f"Erreur cycle ping : {e}")
        await asyncio.sleep(PING_INTERVAL_SECONDS)

# ==============================================================================
# CYCLE DE VIE FASTAPI
# ==============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    global http_client
    LOGS_BASE_DIR.mkdir(parents=True, exist_ok=True)
    limits      = httpx.Limits(max_keepalive_connections=300, max_connections=1200)
    http_client = httpx.AsyncClient(limits=limits, timeout=PROXY_TIMEOUT_SECONDS, verify=VERIFY_SSL)
    monitor_task = asyncio.create_task(periodic_health_monitor())
    logger.info(f"✅ Dedikka Load Balancer démarré | Serveurs : {BACKEND_SERVERS} | Logs : {LOGS_BASE_DIR.resolve()}")
    yield
    monitor_task.cancel()
    if http_client:
        await http_client.aclose()

app = FastAPI(
    title="Dedikka High-Availability Load Balancer",
    description="Répartiteur de charge, anti-DDoS, CORS, logs rotatifs heure/jour/mois.",
    version="3.0.0",
    lifespan=lifespan
)

# ==============================================================================
# ACCÈS ADMIN (Clé secrète)
# ==============================================================================

def check_admin_access(request: Request) -> bool:
    key = (
        request.query_params.get("key")
        or request.headers.get("X-Balancer-Key")
        or request.cookies.get("balancer_admin_key")
    )
    return bool(key and key.strip() == BALANCER_ADMIN_KEY.strip())

def render_login_screen(error: str = "") -> str:
    err_html = f'<div style="background:#7f1d1d;color:#fca5a5;padding:10px 14px;border-radius:8px;margin-bottom:16px;font-size:13px;">{error}</div>' if error else ""
    return f"""<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><title>Dedikka — Accès Sécurisé</title>
    <style>body{{font-family:-apple-system,sans-serif;background:#070b14;color:#f3f4f6;margin:0;display:flex;align-items:center;justify-content:center;height:100vh}}
    .box{{width:380px;background:#0f172a;padding:32px;border-radius:12px;border:1px solid #1e293b;text-align:center}}
    h2{{color:#ff7a18;margin-top:0;font-size:20px}}p{{color:#94a3b8;font-size:13px;margin-bottom:20px}}
    input{{width:100%;box-sizing:border-box;background:#1e293b;border:1px solid #334155;color:#fff;padding:12px;border-radius:8px;font-size:14px;margin-bottom:16px;outline:none}}
    button{{width:100%;background:#ff7a18;color:#fff;border:none;padding:12px;border-radius:8px;font-weight:700;font-size:14px;cursor:pointer}}</style></head>
    <body><div class="box"><h2>🔐 Dedikka Balancer</h2><p>Clé d'administration requise.</p>{err_html}
    <form method="POST" action="/_balancer/dashboard"><input type="password" name="admin_key" placeholder="Clé d'administration..." required autofocus>
    <button type="submit">Déverrouiller</button></form></div></body></html>"""

# ==============================================================================
# ENDPOINTS UPTIMEROBOT / HEALTH CHECKS PUBLICS
# ==============================================================================

@app.api_route("/health",          methods=["GET", "HEAD"], tags=["health"])
@app.api_route("/ping",            methods=["GET", "HEAD"], tags=["health"])
@app.api_route("/healthz",         methods=["GET", "HEAD"], tags=["health"])
@app.api_route("/_balancer/health",methods=["GET", "HEAD"], tags=["health"])
async def health_endpoint():
    online = sum(1 for b in backends.values() if b.is_healthy)
    return Response(content="OK", status_code=200, media_type="text/plain",
                    headers={"X-Balancer-Status": "ONLINE",
                             "X-Backends-Online": f"{online}/{len(backends)}",
                             "Cache-Control": "no-cache"})

# ==============================================================================
# DASHBOARD & MONITORING
# ==============================================================================

@app.get("/_balancer/ping-now", tags=["monitoring"])
@app.post("/_balancer/ping-now", tags=["monitoring"])
async def trigger_ping_now(request: Request):
    if not check_admin_access(request):
        return JSONResponse(status_code=401, content={"error": "Accès refusé. ?key=..."})
    result = await execute_cluster_ping()
    if "text/html" in request.headers.get("accept", "") and request.method == "GET":
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/_balancer/dashboard", status_code=303)
    return JSONResponse(result)

@app.get("/_balancer/status", tags=["monitoring"])
async def balancer_status(request: Request):
    if not check_admin_access(request):
        return JSONResponse(status_code=401, content={"error": "Accès refusé. ?key=..."})
    uptime_sec     = int(time.time() - balancer_start_time)
    sec_until_next = max(0, int(next_ping_time - time.time())) if next_ping_time else 0
    now            = _now_local()
    hkey           = now.strftime("%Y-%m-%dT%H")
    dkey           = now.strftime("%Y-%m-%d")
    mkey           = now.strftime("%Y-%m")
    with _stats_lock:
        hstats = dict(_hourly_stats.get(hkey, {}))
        dstats = dict(_daily_stats.get(dkey, {}))
        mstats = dict(_monthly_stats.get(mkey, {}))
    return JSONResponse({
        "service": "Dedikka Ultra Load Balancer v3",
        "uptime":  f"{uptime_sec // 3600}h {(uptime_sec % 3600) // 60}m {uptime_sec % 60}s",
        "ping_interval_minutes": PING_INTERVAL_SECONDS / 60,
        "next_ping_in_seconds":  sec_until_next,
        "last_ping":             time.strftime("%H:%M:%S", time.localtime(last_ping_time)) if last_ping_time else "—",
        "servers_online":        sum(1 for b in backends.values() if b.is_healthy),
        "servers_total":         len(backends),
        "backends":              [b.to_dict() for b in backends.values()],
        "stats": {
            "this_hour":  hstats,
            "today":      dstats,
            "this_month": mstats,
        }
    })

# ==============================================================================
# ENDPOINTS LOGS EN DIRECT
# ==============================================================================

def _read_log_tail(path: Path, max_lines: int = 500) -> List[dict]:
    """Lit les dernières lignes d'un fichier log JSON Lines."""
    entries = []
    if not path.exists():
        return entries
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except Exception:
                        pass
        return entries[-max_lines:]
    except Exception:
        return []

def _render_log_table(entries: List[dict], title: str, admin_key: str) -> str:
    """Génère une page HTML affichant les entrées de log sous forme de tableau."""
    rows = ""
    for e in reversed(entries):
        status  = e.get("status_code", "—")
        color   = "#10b981" if isinstance(status, int) and status < 400 else "#ef4444"
        retried = "⚡" if e.get("retried") else ""
        rows += f"""<tr style="border-bottom:1px solid #1e293b;">
            <td style="padding:8px 12px;font-size:12px;color:#94a3b8;">{e.get('ts','')}</td>
            <td style="padding:8px 12px;font-family:monospace;font-size:12px;">{e.get('ip','')}</td>
            <td style="padding:8px 12px;font-weight:700;color:#38bdf8;">{e.get('method','')}</td>
            <td style="padding:8px 12px;font-size:12px;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="{e.get('path','')}">{e.get('path','')}</td>
            <td style="padding:8px 12px;"><span style="background:{color};color:#fff;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:700;">{status}</span></td>
            <td style="padding:8px 12px;color:#fbbf24;">{e.get('latency_ms','—')} ms {retried}</td>
            <td style="padding:8px 12px;font-size:11px;color:#64748b;font-family:monospace;">{(e.get('backend') or '').replace('https://','')}</td>
        </tr>"""

    now      = _now_local()
    hour_key = now.strftime("%Hh")
    day_key  = now.strftime("%Y-%m-%d")
    month_key= now.strftime("%Y-%m")

    return f"""<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8">
    <title>Dedikka — Logs {title}</title>
    <meta http-equiv="refresh" content="15">
    <style>
        body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#070b14;color:#f3f4f6;margin:0;padding:24px}}
        .container{{max-width:1300px;margin:auto;background:#0f172a;border-radius:12px;padding:24px;border:1px solid #1e293b}}
        h1{{color:#ff7a18;font-size:22px;margin-top:0}}
        .nav{{display:flex;gap:10px;margin-bottom:20px;flex-wrap:wrap}}
        .nav a{{background:#1e293b;color:#94a3b8;text-decoration:none;padding:7px 14px;border-radius:8px;font-size:13px;font-weight:600}}
        .nav a:hover,.nav a.active{{background:#ff7a18;color:#fff}}
        table{{width:100%;border-collapse:collapse;font-size:13px}}
        th{{text-align:left;padding:10px 12px;background:#1e293b;color:#64748b;font-size:11px;text-transform:uppercase}}
        .info{{font-size:12px;color:#64748b;margin-bottom:12px}}
        .count{{background:#1e293b;padding:4px 12px;border-radius:8px;font-size:13px;color:#38bdf8;margin-left:8px}}
    </style></head>
    <body><div class="container">
    <h1>📋 Dedikka Logs <span style="font-size:16px;color:#94a3b8;">{title}</span>
        <span class="count">{len(entries)} entrées</span></h1>
    <div class="nav">
        <a href="/_balancer/logs/hour/{hour_key}?key={admin_key}" class="{'active' if 'h' in title else ''}">⏰ Cette heure ({hour_key})</a>
        <a href="/_balancer/logs/day/{day_key}?key={admin_key}" class="{'active' if day_key in title else ''}">📅 Aujourd'hui</a>
        <a href="/_balancer/logs/month/{month_key}?key={admin_key}" class="{'active' if month_key in title else ''}">🗓️ Ce mois</a>
        <a href="/_balancer/logs/browse?key={admin_key}">📁 Parcourir</a>
        <a href="/_balancer/dashboard?key={admin_key}">⚖️ Dashboard</a>
    </div>
    <p class="info">Actualisation automatique toutes les 15s</p>
    <table><thead><tr><th>Heure</th><th>IP</th><th>Méthode</th><th>Route</th><th>Statut</th><th>Latence</th><th>Backend</th></tr></thead>
    <tbody>{rows if rows else '<tr><td colspan="7" style="padding:20px;text-align:center;color:#64748b;">Aucune requête enregistrée pour cette période.</td></tr>'}</tbody>
    </table></div></body></html>"""

@app.get("/_balancer/logs/hour/{hour}", response_class=HTMLResponse, tags=["logs"])
async def logs_by_hour(hour: str, request: Request):
    """Affiche les logs d'une heure précise (format: 20h → logs de 20:00 à 20:59)."""
    if not check_admin_access(request):
        return HTMLResponse(content=render_login_screen(), status_code=401)
    now  = _now_local()
    date = request.query_params.get("date", now.strftime("%Y-%m-%d"))
    path = LOGS_BASE_DIR / date[:7] / date / f"{hour}.log"
    admin_key = request.query_params.get("key", "")
    return HTMLResponse(_render_log_table(_read_log_tail(path, 1000), f"{hour} du {date}", admin_key))

# ── ENDPOINTS JSON POUR LE DASHBOARD EXTERNE ──────────────────────────────────

@app.get("/_balancer/logs/json/hour/{hour}", tags=["logs-json"])
async def logs_json_hour(hour: str, request: Request):
    """Retourne les logs d'une heure au format JSON (pour le dashboard externe)."""
    if not check_admin_access(request):
        return JSONResponse(status_code=401, content={"error": "Accès refusé"})
    now  = _now_local()
    date = request.query_params.get("date", now.strftime("%Y-%m-%d"))
    path = LOGS_BASE_DIR / date[:7] / date / f"{hour}.log"
    return JSONResponse(_read_log_tail(path, 1000))

@app.get("/_balancer/logs/json/day/{date}", tags=["logs-json"])
async def logs_json_day(date: str, request: Request):
    """Retourne les logs d'une journée au format JSON (pour le dashboard externe)."""
    if not check_admin_access(request):
        return JSONResponse(status_code=401, content={"error": "Accès refusé"})
    path = LOGS_BASE_DIR / date[:7] / date / "daily.log"
    return JSONResponse(_read_log_tail(path, 2000))

@app.get("/_balancer/logs/json/month/{month}", tags=["logs-json"])
async def logs_json_month(month: str, request: Request):
    """Retourne les logs d'un mois au format JSON (pour le dashboard externe)."""
    if not check_admin_access(request):
        return JSONResponse(status_code=401, content={"error": "Accès refusé"})
    path = LOGS_BASE_DIR / month / "monthly.log"
    return JSONResponse(_read_log_tail(path, 3000))

@app.get("/_balancer/logs/day/{date}", response_class=HTMLResponse, tags=["logs"])
async def logs_by_day(date: str, request: Request):
    """Affiche tous les logs d'une journée (format: 2026-10-22)."""
    if not check_admin_access(request):
        return HTMLResponse(content=render_login_screen(), status_code=401)
    path = LOGS_BASE_DIR / date[:7] / date / "daily.log"
    admin_key = request.query_params.get("key", "")
    return HTMLResponse(_render_log_table(_read_log_tail(path, 2000), f"Journée {date}", admin_key))

@app.get("/_balancer/logs/month/{month}", response_class=HTMLResponse, tags=["logs"])
async def logs_by_month(month: str, request: Request):
    """Affiche le résumé mensuel des logs (format: 2026-10)."""
    if not check_admin_access(request):
        return HTMLResponse(content=render_login_screen(), status_code=401)
    path = LOGS_BASE_DIR / month / "monthly.log"
    admin_key = request.query_params.get("key", "")
    return HTMLResponse(_render_log_table(_read_log_tail(path, 3000), f"Mois {month}", admin_key))

@app.get("/_balancer/logs/browse", response_class=HTMLResponse, tags=["logs"])
async def logs_browse(request: Request):
    """Parcourir l'arborescence complète des fichiers de logs disponibles."""
    if not check_admin_access(request):
        return HTMLResponse(content=render_login_screen(), status_code=401)
    admin_key = request.query_params.get("key", "")
    files = sorted(LOGS_BASE_DIR.rglob("*.log"), reverse=True) if LOGS_BASE_DIR.exists() else []
    rows  = ""
    for f in files[:100]:
        rel  = f.relative_to(LOGS_BASE_DIR)
        size = f"{f.stat().st_size // 1024} Ko" if f.exists() else "—"
        # Génère le lien selon le type de fichier
        parts = rel.parts
        if len(parts) == 3 and parts[2].endswith("h.log"):
            hour = parts[2].replace(".log", "")
            link = f"/_balancer/logs/hour/{hour}?date={parts[1]}&key={admin_key}"
        elif len(parts) == 3 and parts[2] == "daily.log":
            link = f"/_balancer/logs/day/{parts[1]}?key={admin_key}"
        elif len(parts) == 2 and parts[1] == "monthly.log":
            link = f"/_balancer/logs/month/{parts[0]}?key={admin_key}"
        else:
            link = "#"
        rows += f'<tr style="border-bottom:1px solid #1e293b;"><td style="padding:10px 14px;font-family:monospace;font-size:13px;"><a href="{link}" style="color:#38bdf8;text-decoration:none;">{rel}</a></td><td style="padding:10px 14px;color:#94a3b8;">{size}</td></tr>'

    html = f"""<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><title>Dedikka — Parcourir les Logs</title>
    <style>body{{font-family:-apple-system,sans-serif;background:#070b14;color:#f3f4f6;margin:0;padding:24px}}
    .container{{max-width:800px;margin:auto;background:#0f172a;border-radius:12px;padding:24px;border:1px solid #1e293b}}
    h1{{color:#ff7a18;margin-top:0}}a{{color:#38bdf8}}table{{width:100%;border-collapse:collapse}}
    th{{text-align:left;padding:10px 14px;background:#1e293b;color:#64748b;font-size:11px;text-transform:uppercase}}</style></head>
    <body><div class="container"><h1>📁 Fichiers de Logs Disponibles</h1>
    <p><a href="/_balancer/dashboard?key={admin_key}">⬅ Dashboard</a></p>
    <table><thead><tr><th>Fichier</th><th>Taille</th></tr></thead><tbody>
    {rows if rows else '<tr><td colspan="2" style="padding:20px;text-align:center;color:#64748b;">Aucun log disponible encore.</td></tr>'}
    </tbody></table></div></body></html>"""
    return HTMLResponse(html)

@app.api_route("/", methods=["GET", "POST"], response_class=HTMLResponse, tags=["dashboard"])
@app.api_route("/_balancer/dashboard", methods=["GET", "POST"], response_class=HTMLResponse, tags=["monitoring"])
async def balancer_dashboard(request: Request):
    """Dashboard principal avec métriques en direct."""
    if request.method == "POST":
        form_data  = await request.form()
        entered_key = str(form_data.get("admin_key", "")).strip()
        if entered_key == BALANCER_ADMIN_KEY.strip():
            resp = HTMLResponse(content='<meta http-equiv="refresh" content="0;url=/_balancer/dashboard">')
            resp.set_cookie(key="balancer_admin_key", value=entered_key,
                            httponly=True, samesite="lax", max_age=86400 * 7)
            return resp
        return HTMLResponse(content=render_login_screen(error="Clé incorrecte."), status_code=401)

    if not check_admin_access(request):
        return HTMLResponse(content=render_login_screen(), status_code=401)

    admin_key = (
        request.query_params.get("key")
        or request.headers.get("X-Balancer-Key")
        or request.cookies.get("balancer_admin_key", "")
    )

    now      = _now_local()
    hour_key = now.strftime("%Hh")
    day_key  = now.strftime("%Y-%m-%d")
    month_key= now.strftime("%Y-%m")
    hkey_s   = now.strftime("%Y-%m-%dT%H")

    with _stats_lock:
        hstats = _hourly_stats.get(hkey_s, {})
        dstats = _daily_stats.get(day_key, {})
        mstats = _monthly_stats.get(month_key, {})

    def mb(b): return f"{b / 1024 / 1024:.2f} Mo" if b else "0 Mo"

    rows = ""
    for b in backends.values():
        badge_color = "#10b981" if b.is_healthy else "#ef4444"
        badge_text  = "ONLINE" if b.is_healthy else "OFFLINE"
        rows += f"""<tr style="border-bottom:1px solid #1f2937;">
            <td style="padding:14px 18px;font-weight:600;font-family:monospace;">{b.url}</td>
            <td style="padding:14px 18px;"><span style="background:{badge_color};color:#fff;padding:4px 12px;border-radius:12px;font-size:12px;font-weight:700;">{badge_text}</span></td>
            <td style="padding:14px 18px;color:#38bdf8;font-weight:700;">{b.active_connections}</td>
            <td style="padding:14px 18px;">{b.total_routed_requests} req</td>
            <td style="padding:14px 18px;color:#fbbf24;">{b.total_retried_requests}</td>
            <td style="padding:14px 18px;">{f'{b.last_latency_ms:.1f} ms' if b.last_latency_ms else '—'}</td>
            <td style="padding:14px 18px;color:#9ca3af;font-size:13px;">{b.last_error or 'Aucune anomalie'}</td></tr>"""

    uptime_sec      = int(time.time() - balancer_start_time)
    sec_until_next  = max(0, int(next_ping_time - time.time())) if next_ping_time else PING_INTERVAL_SECONDS
    next_ping_disp  = f"{sec_until_next // 60}m {sec_until_next % 60}s"
    last_ping_disp  = time.strftime("%H:%M:%S", time.localtime(last_ping_time)) if last_ping_time else "Au démarrage"

    html = f"""<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8">
    <title>Dedikka — Load Balancer Dashboard</title>
    <meta http-equiv="refresh" content="15">
    <style>
        body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#070b14;color:#f3f4f6;margin:0;padding:30px}}
        .container{{max-width:1200px;margin:auto;background:#0f172a;border-radius:14px;padding:28px;border:1px solid #1e293b;box-shadow:0 20px 40px rgba(0,0,0,.6)}}
        h1{{margin-top:0;color:#ff7a18;font-size:24px;display:flex;align-items:center;justify-content:space-between}}
        .stats-bar{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:20px 0}}
        .stat-card{{background:#1e293b;padding:14px 18px;border-radius:10px;border-left:4px solid #ff7a18}}
        .stat-label{{font-size:11px;color:#94a3b8;text-transform:uppercase;font-weight:600}}
        .stat-value{{font-size:20px;font-weight:700;color:#fff;margin-top:4px}}
        .stat-sub{{font-size:11px;color:#64748b;margin-top:2px}}
        .btn{{background:#ff7a18;color:#fff;text-decoration:none;padding:7px 14px;border-radius:8px;font-weight:700;font-size:13px;margin-left:8px}}
        .btn:hover{{background:#e0660f}}
        .btn-blue{{background:#1d4ed8}}
        .btn-blue:hover{{background:#1e40af}}
        table{{width:100%;border-collapse:collapse;margin-top:20px}}
        th{{text-align:left;padding:12px 18px;background:#1e293b;color:#94a3b8;font-size:11px;text-transform:uppercase;font-weight:700}}
        .anti-veille{{background:#132438;border:1px solid #1d4ed8;padding:12px 18px;border-radius:8px;margin:14px 0;font-size:13px;color:#93c5fd}}
        .log-bar{{display:flex;gap:10px;margin:14px 0;flex-wrap:wrap}}
        .log-bar a{{background:#1e293b;color:#94a3b8;text-decoration:none;padding:7px 14px;border-radius:8px;font-size:13px;font-weight:600}}
        .log-bar a:hover{{background:#334155;color:#fff}}
    </style></head>
    <body><div class="container">
    <h1>⚖️ Dedikka Ultra Load Balancer
        <span>
            <a href="/_balancer/ping-now?key={admin_key}" class="btn">⚡ Pinger</a>
            <a href="/_balancer/logs/hour/{hour_key}?key={admin_key}" class="btn btn-blue">📋 Logs {hour_key}</a>
            <a href="/_balancer/logs/browse?key={admin_key}" class="btn btn-blue">📁 Tous les logs</a>
        </span>
    </h1>

    <div class="anti-veille">
        📡 <b>Anti-Veille Render :</b> Dernier ping à <b>{last_ping_disp}</b> | Prochain dans : <b>{next_ping_disp}</b>
    </div>

    <div class="log-bar">
        <a href="/_balancer/logs/hour/{hour_key}?key={admin_key}">⏰ Logs {hour_key} ({hstats.get('requests',0)} req)</a>
        <a href="/_balancer/logs/day/{day_key}?key={admin_key}">📅 Logs aujourd'hui ({dstats.get('requests',0)} req)</a>
        <a href="/_balancer/logs/month/{month_key}?key={admin_key}">🗓️ Logs {month_key} ({mstats.get('requests',0)} req)</a>
    </div>

    <div class="stats-bar">
        <div class="stat-card">
            <div class="stat-label">Serveurs Online</div>
            <div class="stat-value">{sum(1 for b in backends.values() if b.is_healthy)} / {len(backends)}</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Requêtes — Heure</div>
            <div class="stat-value">{hstats.get('requests',0)}</div>
            <div class="stat-sub">Erreurs : {hstats.get('errors',0)} | {mb(hstats.get('total_bytes',0))}</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Requêtes — Aujourd'hui</div>
            <div class="stat-value">{dstats.get('requests',0)}</div>
            <div class="stat-sub">Bande passante : {mb(dstats.get('total_bytes',0))}</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Requêtes — Ce Mois</div>
            <div class="stat-value">{mstats.get('requests',0)}</div>
            <div class="stat-sub">Total : {mb(mstats.get('total_bytes',0))}</div>
        </div>
    </div>

    <table>
        <thead><tr><th>Serveur</th><th>Statut</th><th>Connexions</th><th>Requêtes</th><th>Auto-Retries</th><th>Latence</th><th>Dernière Alerte</th></tr></thead>
        <tbody>{rows}</tbody>
    </table>

    <p style="font-size:11px;color:#334155;margin-top:18px;text-align:right;">
        Uptime : {uptime_sec // 3600}h {(uptime_sec % 3600) // 60}m | Algorithme : Least Connections | Logs : {LOGS_BASE_DIR}
    </p>
    </div></body></html>"""
    return HTMLResponse(html)

# ==============================================================================
# PROXY INVERSE TRANSPARENT (CORS + RATE-LIMIT + LEAST CONN + AUTO-RETRY + LOGS)
# ==============================================================================

EXCLUDED_HEADERS = {
    "host",
    "content-length",
    # Ask upstream for an uncompressed body. Some upstream/proxy responses
    # advertise gzip while returning bytes that httpx cannot decode; browsers
    # then surface the body-decoding failure as a generic "Failed to fetch".
    "accept-encoding",
    # httpx transparently decompresses response.content; forwarding the old
    # encoding header makes the browser try to decompress the body a second time.
    "content-encoding",
    "transfer-encoding",
    "connection",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-expose-headers",
}

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def dynamic_proxy(request: Request, path: str):
    req_start = time.time()

    # 1. CORS OPTIONS — réponse immédiate en 0 ms
    origin            = request.headers.get("origin", "")
    is_allowed_origin = origin in ALLOWED_ORIGINS if origin else False
    cors_origin        = origin if is_allowed_origin else (list(ALLOWED_ORIGINS)[0] if ALLOWED_ORIGINS else "")

    if request.method == "OPTIONS":
        req_hdrs = request.headers.get("access-control-request-headers", "Authorization, Content-Type, X-CSRF-Token, X-Requested-With, Accept, Origin")
        return Response(status_code=204, headers={
            "Access-Control-Allow-Origin":      origin if is_allowed_origin else (cors_origin or "*"),
            "Access-Control-Allow-Methods":     "GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD",
            "Access-Control-Allow-Headers":     req_hdrs,
            "Access-Control-Allow-Credentials": "true" if is_allowed_origin else "false",
            "Access-Control-Max-Age":           "86400",
        })

    # 2. RATE LIMITING ANTI-DDOS
    forwarded_for = request.headers.get("x-forwarded-for")
    client_ip     = forwarded_for.split(",")[0].strip() if forwarded_for else (
        request.client.host if request.client else "127.0.0.1"
    )
    user_agent = request.headers.get("user-agent", "")
    if await is_rate_limited(client_ip, f"/{path}", user_agent=user_agent):
        logger.warning(f"🛡️ Rate limit IP={client_ip} path=/{path}")
        await log_request(request, 429, (time.time() - req_start) * 1000, "rate_limiter")
        return JSONResponse(status_code=429,
                            content={"error": "Trop de requêtes. Protection Anti-DDoS active."})

    # 3. PRÉPARATION HEADERS PROXY
    headers = {k: v for k, v in request.headers.items() if k.lower() not in EXCLUDED_HEADERS}
    headers["accept-encoding"] = "identity"
    headers["x-forwarded-for"]   = f"{headers.get('x-forwarded-for', '')}, {client_ip}".strip(", ")
    headers["x-forwarded-proto"] = request.url.scheme

    body      = await request.body()
    query_str = f"?{request.url.query}" if request.url.query else ""

    # 4. PROXY AVEC LEAST CONNECTIONS + AUTO-RETRY + LOG
    attempted_servers = set()
    last_exception    = None
    retried           = False

    for attempt in range(MAX_RETRIES + 1):
        backend = select_best_backend(exclude_urls=attempted_servers)
        if not backend:
            break

        attempted_servers.add(backend.url)
        if attempt > 0:
            retried = True
        target_url = f"{backend.url}/{path}{query_str}"

        backend.active_connections    += 1
        backend.total_routed_requests += 1

        try:
            global http_client
            if http_client is None:
                http_client = httpx.AsyncClient(verify=VERIFY_SSL, timeout=PROXY_TIMEOUT_SECONDS)

            req = http_client.build_request(
                method=request.method, url=target_url,
                headers=headers, content=body, timeout=PROXY_TIMEOUT_SECONDS
            )
            response = await http_client.send(req)

            if response.status_code in (502, 503, 504) and attempt < MAX_RETRIES:
                backend.total_retried_requests += 1
                logger.warning(f"⚠️ {backend.url} → HTTP {response.status_code}, retry #{attempt+1}")
                continue

            resp_content = response.content
            latency_ms   = (time.time() - req_start) * 1000

            # Log de la requête
            asyncio.create_task(log_request(
                request, response.status_code, latency_ms,
                backend.url, len(resp_content), retried
            ))

            resp_headers = {k: v for k, v in response.headers.items() if k.lower() not in EXCLUDED_HEADERS}
            if is_allowed_origin:
                resp_headers["Access-Control-Allow-Origin"]      = origin
                resp_headers["Access-Control-Allow-Credentials"] = "true"

            return Response(content=resp_content, status_code=response.status_code, headers=resp_headers)

        except (httpx.ConnectError, httpx.TimeoutException, httpx.NetworkError) as exc:
            last_exception = exc
            backend.total_retried_requests += 1
            backend.is_healthy = False
            logger.warning(f"⚠️ Réseau {backend.url}: {exc} — bascule...")
            continue

        finally:
            backend.active_connections = max(0, backend.active_connections - 1)

    latency_ms = (time.time() - req_start) * 1000
    asyncio.create_task(log_request(request, 502, latency_ms, "all_failed", 0, retried))
    logger.error(f"❌ Tous les serveurs ont échoué pour /{path}")
    return JSONResponse(status_code=502,
                        content={"error": f"Service temporairement indisponible ({last_exception})."})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8080, reload=False)
