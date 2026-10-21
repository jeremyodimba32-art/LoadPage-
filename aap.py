"""
🚀 DEDIKKA ULTRA LOAD BALANCER & RESILIENCE PROXY (aap.py)
==========================================================
Load Balancer tout-en-un de niveau production, 100% autonome.
Ne modifie aucun fichier de votre application actuelle.

Fonctionnalités intégrées :
1. Algorithme « Least Connections » (Route toujours vers le serveur le moins chargé).
2. Auto-Retry Transparent (Bascule instantanée sur un autre serveur en cas de 502/Timeout).
3. Gestion CORS ultra-rapide en 0 ms (Traite les requêtes OPTIONS directement au niveau du balancer).
4. Protection Anti-DDoS & Rate Limiting en mémoire (Bloque les attaques de requêtes abusives par IP).
5. Surveillance active & Ping toutes les 10 minutes sur /api/v1/health.
6. Alertes automatiques en direct (Support natif Telegram & Discord Webhooks).
7. Dashboard visuel HTML en direct sur : /_balancer/dashboard
8. Endpoint d'état JSON pour monitoring : /_balancer/status

Lancement :
   python aap.py
   ou en prod : uvicorn aap:app --host 0.0.0.0 --port 8080 --workers 2
"""

import asyncio
import os
import time
import logging
from typing import Dict, List, Optional
from collections import defaultdict
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, HTMLResponse

# Configuration des logs
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [DedikkaBalancer] %(message)s"
)
logger = logging.getLogger("DedikkaBalancer")

# ==============================================================================
# CONFIGURATION GÉNÉRALE & VARIABLES D'ENVIRONNEMENT
# ==============================================================================

# Liste des serveurs cibles (peut être surchargée par variable d'environnement BACKEND_URLS)
DEFAULT_SERVERS = [
    "https://dedikka.onrender.com",
    # Ajoutez ici vos instances supplémentaires, ex:
    # "https://dedikka-api-2.onrender.com",
    # "https://dedikka-api-3.onrender.com",
]

env_backends = os.getenv("BACKEND_URLS")
BACKEND_SERVERS: List[str] = (
    [url.strip().rstrip("/") for url in env_backends.split(",") if url.strip()]
    if env_backends
    else DEFAULT_SERVERS
)

# Surveillance & Ping (10 minutes = 600 secondes)
HEALTH_ENDPOINT = os.getenv("HEALTH_ENDPOINT", "/api/v1/health")
PING_INTERVAL_SECONDS = int(os.getenv("PING_INTERVAL_SECONDS", "600"))
PING_TIMEOUT_SECONDS = float(os.getenv("PING_TIMEOUT_SECONDS", "10.0"))

# Auto-Retry
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "2"))
PROXY_TIMEOUT_SECONDS = float(os.getenv("PROXY_TIMEOUT_SECONDS", "45.0"))

# Rate Limiting (Nombre max de requêtes par minute par IP)
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "120"))
RATE_LIMIT_ENABLED = os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true"

# Canaux d'alertes instantanées (optionnels)
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")

# Sécurité : Origines autorisées CORS (Whitelist stricte)
DEFAULT_ALLOWED_ORIGINS = {
    "https://dedikka.web.app",
    "https://dedikka.firebaseapp.com",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:5000",
    "http://127.0.0.1:5000",
}
env_origins = os.getenv("ALLOWED_ORIGINS", "")
ALLOWED_ORIGINS = set(
    [o.strip().rstrip("/") for o in env_origins.split(",") if o.strip()]
) if env_origins else DEFAULT_ALLOWED_ORIGINS

# Sécurité : Vérification stricte des certificats SSL (MitM protection)
VERIFY_SSL = os.getenv("VERIFY_SSL", "true").lower() == "true"

# Sécurité : Clé d'accès administrateur pour le Dashboard et le contrôle manuel
BALANCER_ADMIN_KEY = os.getenv("BALANCER_ADMIN_KEY", "dedikka-admin-2026")

# ==============================================================================
# ÉTAT DES SERVEURS (MÉTRIQUES & MOINDRE CONNEXION)
# ==============================================================================

class BackendServer:
    def __init__(self, url: str):
        self.url = url
        self.is_healthy: bool = True
        self.active_connections: int = 0  # Utilisé pour l'algorithme Least Connections
        self.total_routed_requests: int = 0
        self.total_retried_requests: int = 0
        self.last_check_time: Optional[float] = None
        self.last_latency_ms: Optional[float] = None
        self.last_status_code: Optional[int] = None
        self.consecutive_failures: int = 0
        self.last_error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "status": "ONLINE" if self.is_healthy else "OFFLINE",
            "active_connections": self.active_connections,
            "total_requests": self.total_routed_requests,
            "total_retries": self.total_retried_requests,
            "last_latency": f"{self.last_latency_ms:.1f} ms" if self.last_latency_ms else "N/A",
            "last_status_code": self.last_status_code,
            "last_check_ago": f"{int(time.time() - self.last_check_time)}s" if self.last_check_time else "Jamais",
            "consecutive_failures": self.consecutive_failures,
            "last_error": self.last_error,
        }

backends: Dict[str, BackendServer] = {url: BackendServer(url) for url in BACKEND_SERVERS}
http_client: Optional[httpx.AsyncClient] = None
balancer_start_time = time.time()
last_ping_time: Optional[float] = None
next_ping_time: Optional[float] = None

# ==============================================================================
# SYSTÈME D'ALERTES (TELEGRAM & DISCORD)
# ==============================================================================

async def send_alert_notification(message: str):
    """Envoie une notification d'alerte en cas de panne ou de rétablissement de serveur."""
    logger.warning(f"📢 Notification d'alerte : {message}")
    async with httpx.AsyncClient(timeout=8.0) as client:
        # Envoi Telegram si configuré
        if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
            try:
                tg_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
                await client.post(tg_url, json={
                    "chat_id": TELEGRAM_CHAT_ID,
                    "text": message,
                    "parse_mode": "Markdown"
                })
            except Exception as e:
                logger.error(f"Échec envoi alerte Telegram : {e}")

        # Envoi Discord si configuré
        if DISCORD_WEBHOOK_URL:
            try:
                await client.post(DISCORD_WEBHOOK_URL, json={"content": message})
            except Exception as e:
                logger.error(f"Échec envoi alerte Discord : {e}")

# ==============================================================================
# ALGORITHME DE RÉPARTITION : LEAST CONNECTIONS (Moindre Connexion)
# ==============================================================================

def select_best_backend(exclude_urls: Optional[set] = None) -> Optional[BackendServer]:
    """
    Sélectionne le serveur en ligne ayant le moins de requêtes en cours de traitement.
    Permet de contourner les serveurs qui ont déjà échoué lors d'un retry.
    """
    exclude = exclude_urls or set()
    available = [b for b in backends.values() if b.is_healthy and b.url not in exclude]

    if not available:
        # Si aucun serveur en ligne hors exclusion, tente sur tous les serveurs déclarés
        available = [b for b in backends.values() if b.url not in exclude]

    if not available:
        return None

    # Trie par nombre de connexions actives, puis par total de requêtes (tie-breaker)
    available.sort(key=lambda b: (b.active_connections, b.total_routed_requests))
    return available[0]

# ==============================================================================
# ANTI-DDOS / RATE LIMITING EN MÉMOIRE
# ==============================================================================

rate_limit_records = defaultdict(list)
rate_limit_lock = asyncio.Lock()

# Chemins exemptés de limitation (paiements, webhooks, et pings UptimeRobot)
EXEMPT_PATHS = ("/api/v1/payments/", "/api/v1/webhooks/", "/_balancer/", "/health", "/ping", "/healthz")

async def is_rate_limited(ip: str, path: str, user_agent: str = "") -> bool:
    """Vérifie si une adresse IP a dépassé le plafond autorisé de requêtes."""
    if not RATE_LIMIT_ENABLED:
        return False
    # Ne jamais bloquer les requêtes de surveillance UptimeRobot
    if "uptimerobot" in user_agent.lower():
        return False
    if any(path.startswith(p) for p in EXEMPT_PATHS):
        return False

    now = time.time()
    window_start = now - 60.0

    async with rate_limit_lock:
        timestamps = rate_limit_records[ip]
        # Nettoyage des requêtes de plus de 60 secondes
        rate_limit_records[ip] = [t for t in timestamps if t > window_start]
        if len(rate_limit_records[ip]) >= RATE_LIMIT_PER_MINUTE:
            return True
        rate_limit_records[ip].append(now)
        return False

# ==============================================================================
# MONITORING & PING PÉRIODIQUE (TOUTES LES 10 MINUTES)
# ==============================================================================

async def check_backend_health(client: httpx.AsyncClient, backend: BackendServer):
    """Interroge /api/v1/health sur un serveur et déclenche une alerte si changement d'état."""
    target_url = f"{backend.url}{HEALTH_ENDPOINT}"
    start_time = time.time()
    try:
        response = await client.get(target_url, timeout=PING_TIMEOUT_SECONDS)
        latency = (time.time() - start_time) * 1000
        backend.last_check_time = time.time()
        backend.last_latency_ms = latency
        backend.last_status_code = response.status_code

        is_up = (200 <= response.status_code < 400)
        if is_up:
            if not backend.is_healthy:
                # Alerte de rétablissement
                asyncio.create_task(send_alert_notification(
                    f"✅ *RÉTABLISSEMENT DEDIKKA* : Le serveur `{backend.url}` est de nouveau en ligne ! Latence : {latency:.1f}ms."
                ))
            backend.is_healthy = True
            backend.consecutive_failures = 0
            backend.last_error = None
        else:
            raise Exception(f"Statut HTTP {response.status_code}")

    except Exception as exc:
        latency = (time.time() - start_time) * 1000
        backend.last_check_time = time.time()
        backend.last_latency_ms = latency
        backend.last_status_code = None
        backend.consecutive_failures += 1
        backend.last_error = str(exc)

        # Dès le premier échec, déclenchement de l'alerte
        if backend.is_healthy:
            backend.is_healthy = False
            asyncio.create_task(send_alert_notification(
                f"🚨 *ALERTE PANNE DEDIKKA* : Le serveur `{backend.url}` ne répond plus !\nErreur : `{exc}`. Trafic basculé sur les autres serveurs."
            ))

async def execute_cluster_ping() -> dict:
    """Exécute un cycle de ping immédiat sur tous les serveurs du cluster."""
    global last_ping_time, next_ping_time
    last_ping_time = time.time()
    next_ping_time = last_ping_time + PING_INTERVAL_SECONDS
    logger.info("🛰️ [PING 10 MIN] Exécution du ping de santé & anti-veille Render...")
    async with httpx.AsyncClient(verify=VERIFY_SSL) as client:
        tasks = [check_backend_health(client, b) for b in backends.values()]
        await asyncio.gather(*tasks)
    online = sum(1 for b in backends.values() if b.is_healthy)
    logger.info(f"📊 [PING 10 MIN] Terminé : {online}/{len(backends)} serveurs ONLINE. Prochain ping dans {PING_INTERVAL_SECONDS // 60} min.")
    return {
        "status": "success",
        "online_servers": online,
        "total_servers": len(backends),
        "last_ping_time": time.strftime("%H:%M:%S", time.localtime(last_ping_time)),
        "next_ping_in_minutes": PING_INTERVAL_SECONDS / 60
    }

async def periodic_health_monitor():
    """Boucle infinie exécutant un ping sur chaque serveur toutes les 10 minutes (Anti-veille active)."""
    await asyncio.sleep(2)  # Attente du démarrage complet
    while True:
        try:
            await execute_cluster_ping()
        except Exception as e:
            logger.error(f"Erreur durant le cycle de ping : {e}")

        await asyncio.sleep(PING_INTERVAL_SECONDS)

# ==============================================================================
# CYCLE DE VIE FASTAPI
# ==============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    global http_client
    # Pool de connexions HTTP haute performance (jusqu'à 1000 connexions parallèles)
    limits = httpx.Limits(max_keepalive_connections=300, max_connections=1200)
    http_client = httpx.AsyncClient(limits=limits, timeout=PROXY_TIMEOUT_SECONDS, verify=VERIFY_SSL)
    monitor_task = asyncio.create_task(periodic_health_monitor())
    yield
    monitor_task.cancel()
    if http_client:
        await http_client.aclose()

app = FastAPI(
    title="Dedikka High-Availability Load Balancer",
    description="Répartiteur de charge, anti-DDoS, CORS immédiat et auto-retry.",
    version="2.0.0",
    lifespan=lifespan
)

# ==============================================================================
# ENDPOINTS HEALTHCHECK DÉDIÉS UPTIMEROBOT & MONITEURS EXTERNES
# ==============================================================================

@app.api_route("/health", methods=["GET", "HEAD"], tags=["uptimerobot"])
@app.api_route("/ping", methods=["GET", "HEAD"], tags=["uptimerobot"])
@app.api_route("/healthz", methods=["GET", "HEAD"], tags=["uptimerobot"])
@app.api_route("/_balancer/health", methods=["GET", "HEAD"], tags=["uptimerobot"])
async def uptimerobot_endpoint():
    """
    Endpoint ultra-rapide dédié à UptimeRobot et aux outils de surveillance externes.
    Répond 200 OK immédiatement en 0 ms sans surcharger les serveurs de backend.
    """
    online_count = sum(1 for b in backends.values() if b.is_healthy)
    return Response(
        content="OK",
        status_code=200,
        media_type="text/plain",
        headers={
            "X-Balancer-Status": "ONLINE",
            "X-Backends-Online": f"{online_count}/{len(backends)}",
            "Cache-Control": "no-cache, no-store, must-revalidate"
        }
    )

def check_admin_access(request: Request) -> bool:
    """Vérifie si la requête possède la clé d'administration secrète."""
    key = (
        request.query_params.get("key")
        or request.headers.get("X-Balancer-Key")
        or request.cookies.get("balancer_admin_key")
    )
    return bool(key and key.strip() == BALANCER_ADMIN_KEY.strip())

def render_login_screen(error: str = "") -> str:
    """Formulaire de connexion épuré et sécurisé pour déverrouiller le Dashboard."""
    err_html = f'<div style="background:#7f1d1d; color:#fca5a5; padding:10px 14px; border-radius:8px; margin-bottom:16px; font-size:13px;">{error}</div>' if error else ""
    return f"""
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <title>Dedikka — Accès Sécurisé Balancer</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #070b14; color: #f3f4f6; margin: 0; display: flex; align-items: center; justify-content: center; height: 100vh; }}
            .box {{ width: 380px; background: #0f172a; padding: 32px; border-radius: 12px; border: 1px solid #1e293b; box-shadow: 0 20px 40px rgba(0,0,0,0.7); text-align: center; }}
            h2 {{ color: #ff7a18; margin-top: 0; font-size: 20px; }}
            p {{ color: #94a3b8; font-size: 13px; margin-bottom: 20px; }}
            input {{ width: 100%; box-sizing: border-box; background: #1e293b; border: 1px solid #334155; color: #fff; padding: 12px; border-radius: 8px; font-size: 14px; margin-bottom: 16px; outline: none; }}
            button {{ width: 100%; background: #ff7a18; color: #fff; border: none; padding: 12px; border-radius: 8px; font-weight: 700; font-size: 14px; cursor: pointer; }}
            button:hover {{ background: #e0660f; }}
        </style>
    </head>
    <body>
        <div class="box">
            <h2>🔐 Dedikka Balancer — Accès Protégé</h2>
            <p>Veuillez entrer votre clé d'administration pour afficher les métriques du cluster.</p>
            {err_html}
            <form method="POST" action="/_balancer/dashboard">
                <input type="password" name="admin_key" placeholder="Clé d'administration..." required autofocus>
                <button type="submit">Déverrouiller le Dashboard</button>
            </form>
        </div>
    </body>
    </html>
    """

@app.get("/_balancer/ping-now", tags=["monitoring"])
@app.post("/_balancer/ping-now", tags=["monitoring"])
async def trigger_ping_now(request: Request):
    """Déclenche un cycle de ping immédiat sans attendre l'intervalle de 10 minutes."""
    if not check_admin_access(request):
        return JSONResponse(status_code=401, content={"error": "Accès refusé. Clé d'administration invalide ou manquante (?key=...)"})

    result = await execute_cluster_ping()
    # Si appelé depuis un navigateur, redirection fluide vers le dashboard
    accept = request.headers.get("accept", "")
    if "text/html" in accept and request.method == "GET":
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/_balancer/dashboard", status_code=303)
    return JSONResponse(result)

@app.get("/_balancer/status", tags=["monitoring"])
async def balancer_status(request: Request):
    """Statut JSON complet du répartiteur et de tous ses serveurs."""
    if not check_admin_access(request):
        return JSONResponse(status_code=401, content={"error": "Accès refusé. Clé d'administration invalide ou manquante (?key=...)"})

    uptime_sec = int(time.time() - balancer_start_time)
    sec_until_next = max(0, int(next_ping_time - time.time())) if next_ping_time else 0
    return JSONResponse({
        "service": "Dedikka Ultra Load Balancer",
        "uptime": f"{uptime_sec // 3600}h {(uptime_sec % 3600) // 60}m {uptime_sec % 60}s",
        "ping_interval_minutes": PING_INTERVAL_SECONDS / 60,
        "next_ping_in_seconds": sec_until_next,
        "last_ping": time.strftime("%H:%M:%S", time.localtime(last_ping_time)) if last_ping_time else "En cours...",
        "rate_limit_per_minute": RATE_LIMIT_PER_MINUTE,
        "servers_total": len(backends),
        "servers_online": sum(1 for b in backends.values() if b.is_healthy),
        "backends": [b.to_dict() for b in backends.values()]
    })

@app.api_route("/_balancer/dashboard", methods=["GET", "POST"], response_class=HTMLResponse, tags=["monitoring"])
async def balancer_dashboard(request: Request):
    """Interface visuelle moderne en direct affichant les métriques du cluster."""
    if request.method == "POST":
        form_data = await request.form()
        entered_key = str(form_data.get("admin_key", "")).strip()
        if entered_key == BALANCER_ADMIN_KEY.strip():
            response = HTMLResponse(content='<meta http-equiv="refresh" content="0;url=/_balancer/dashboard">')
            response.set_cookie(key="balancer_admin_key", value=entered_key, httponly=True, samesite="lax", max_age=86400 * 7)
            return response
        else:
            return HTMLResponse(content=render_login_screen(error="Clé d'administration incorrecte."), status_code=401)

    if not check_admin_access(request):
        return HTMLResponse(content=render_login_screen(), status_code=401)
    """Interface visuelle moderne en direct affichant les métriques du cluster."""
    rows = ""
    for b in backends.values():
        badge_color = "#10b981" if b.is_healthy else "#ef4444"
        badge_text = "ONLINE" if b.is_healthy else "OFFLINE"
        rows += f"""
        <tr style="border-bottom: 1px solid #1f2937;">
            <td style="padding: 14px 18px; font-weight: 600; font-family: monospace;">{b.url}</td>
            <td style="padding: 14px 18px;">
                <span style="background:{badge_color}; color:#fff; padding:4px 12px; border-radius:12px; font-size:12px; font-weight:700;">
                    {badge_text}
                </span>
            </td>
            <td style="padding: 14px 18px; color: #38bdf8; font-weight: 700;">{b.active_connections}</td>
            <td style="padding: 14px 18px;">{b.total_routed_requests} req</td>
            <td style="padding: 14px 18px; color: #fbbf24;">{b.total_retried_requests}</td>
            <td style="padding: 14px 18px;">{f'{b.last_latency_ms:.1f} ms' if b.last_latency_ms else '—'}</td>
            <td style="padding: 14px 18px; color:#9ca3af; font-size:13px;">{b.last_error or 'Aucune anomalie'}</td>
        </tr>
        """

    uptime_sec = int(time.time() - balancer_start_time)
    sec_until_next = max(0, int(next_ping_time - time.time())) if next_ping_time else PING_INTERVAL_SECONDS
    next_ping_display = f"{sec_until_next // 60}m {sec_until_next % 60}s"
    last_ping_display = time.strftime("%H:%M:%S", time.localtime(last_ping_time)) if last_ping_time else "Au démarrage"

    html = f"""
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <title>Dedikka — Tableau de Bord Load Balancer</title>
        <meta http-equiv="refresh" content="15">
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #070b14; color: #f3f4f6; margin: 0; padding: 30px; }}
            .container {{ max-width: 1100px; margin: auto; background: #0f172a; border-radius: 14px; padding: 28px; border: 1px solid #1e293b; box-shadow: 0 20px 40px rgba(0,0,0,0.6); }}
            h1 {{ margin-top: 0; color: #ff7a18; font-size: 26px; display: flex; align-items: center; justify-content: space-between; }}
            .stats-bar {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 20px 0; }}
            .stat-card {{ background: #1e293b; padding: 14px 18px; border-radius: 10px; border-left: 4px solid #ff7a18; }}
            .stat-label {{ font-size: 12px; color: #94a3b8; text-transform: uppercase; font-weight: 600; }}
            .stat-value {{ font-size: 22px; font-weight: 700; color: #fff; margin-top: 4px; }}
            .btn-ping {{ background: #ff7a18; color: #fff; text-decoration: none; padding: 8px 16px; border-radius: 8px; font-weight: 700; font-size: 13px; display: inline-flex; align-items: center; gap: 6px; }}
            .btn-ping:hover {{ background: #e0660f; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 25px; }}
            th {{ text-align: left; padding: 14px 18px; background: #1e293b; color: #94a3b8; font-size: 12px; text-transform: uppercase; font-weight: 700; }}
            .info {{ font-size: 13px; color: #94a3b8; margin-top: 6px; }}
            .anti-veille {{ background: #132438; border: 1px solid #1d4ed8; padding: 12px 18px; border-radius: 8px; margin: 15px 0; font-size: 13px; color: #93c5fd; display: flex; justify-content: space-between; align-items: center; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>
                <span>⚖️ Dedikka Ultra Load Balancer & Health Monitor</span>
                <a href="/_balancer/ping-now" class="btn-ping">⚡ Pinger Maintenant</a>
            </h1>
            <p class="info">Actualisation automatique chaque 15s | Algorithme : <b>Least Connections</b></p>
            
            <div class="anti-veille">
                <div>
                    📡 <b>Surveillance 10 min (Anti-Veille Render) :</b> Dernier ping à <b>{last_ping_display}</b> | Prochain ping automatique dans : <b>{next_ping_display}</b>
                </div>
            </div>

            <div class="stats-bar">
                <div class="stat-card">
                    <div class="stat-label">Serveurs En Ligne</div>
                    <div class="stat-value">{sum(1 for b in backends.values() if b.is_healthy)} / {len(backends)}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Connexions Actives</div>
                    <div class="stat-value">{sum(b.active_connections for b in backends.values())}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Total Requêtes Traitées</div>
                    <div class="stat-value">{sum(b.total_routed_requests for b in backends.values())}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Uptime Balancer</div>
                    <div class="stat-value">{uptime_sec // 3600}h {(uptime_sec % 3600) // 60}m</div>
                </div>
            </div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Total Requêtes Traitées</div>
                    <div class="stat-value">{sum(b.total_routed_requests for b in backends.values())}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Uptime Balancer</div>
                    <div class="stat-value">{uptime_sec // 3600}h {(uptime_sec % 3600) // 60}m</div>
                </div>
            </div>

            <table>
                <thead>
                    <tr>
                        <th>Serveur Backend</th>
                        <th>Statut</th>
                        <th>Connexions</th>
                        <th>Requêtes</th>
                        <th>Auto-Retries</th>
                        <th>Latence</th>
                        <th>Dernière Alerte</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html)

# ==============================================================================
# PROXY INVERSE TRANSPARENT : CORS + RATE-LIMIT + LEAST CONNECTIONS + AUTO-RETRY
# ==============================================================================

EXCLUDED_HEADERS = {"host", "content-length", "transfer-encoding", "connection"}

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def dynamic_proxy(request: Request, path: str):
    """
    Traite la requête en appliquant :
    1. Réponse immédiate CORS (OPTIONS) en 0 ms.
    2. Protection Anti-DDoS (Rate Limiting par IP).
    3. Sélection par Moindre Connexion (Least Connections).
    4. Auto-Retry transparent en cas de 502/Timeout.
    """
    # --------------------------------------------------------------------------
    # 1. RÉPONSE IMMÉDIATE CORS STRICTE (OPTIONS en 0 ms)
    # --------------------------------------------------------------------------
    origin = request.headers.get("origin", "")
    is_allowed_origin = (origin in ALLOWED_ORIGINS) if origin else False
    cors_origin = origin if is_allowed_origin else (list(ALLOWED_ORIGINS)[0] if ALLOWED_ORIGINS else "")

    if request.method == "OPTIONS":
        return Response(
            status_code=204,
            headers={
                "Access-Control-Allow-Origin": cors_origin or "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "Authorization, Content-Type, X-CSRF-Token, X-Requested-With",
                "Access-Control-Allow-Credentials": "true" if is_allowed_origin else "false",
                "Access-Control-Max-Age": "86400",
            }
        )

    # --------------------------------------------------------------------------
    # 2. RATE LIMITING ANTI-DDOS
    # --------------------------------------------------------------------------
    client_ip = request.client.host if request.client else "127.0.0.1"
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        client_ip = forwarded_for.split(",")[0].strip()

    user_agent = request.headers.get("user-agent", "")
    if await is_rate_limited(client_ip, f"/{path}", user_agent=user_agent):
        logger.warning(f"🛡️ Rate limit déclenché pour l'IP {client_ip} sur /{path}")
        return JSONResponse(
            status_code=429,
            content={"error": "Trop de requêtes. Veuillez patienter un instant (Protection Anti-DDoS)."}
        )

    # --------------------------------------------------------------------------
    # 3. PRÉPARATION DE LA REQUÊTE PROXY
    # --------------------------------------------------------------------------
    headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in EXCLUDED_HEADERS
    }
    headers["x-forwarded-for"] = f"{headers.get('x-forwarded-for', '')}, {client_ip}".strip(", ")
    headers["x-forwarded-proto"] = request.url.scheme

    body = await request.body()
    query_str = f"?{request.url.query}" if request.url.query else ""

    # --------------------------------------------------------------------------
    # 4. AUTO-RETRY TRANSPARENT AVEC LEAST CONNECTIONS
    # --------------------------------------------------------------------------
    attempted_servers = set()
    last_exception = None

    for attempt in range(MAX_RETRIES + 1):
        backend = select_best_backend(exclude_urls=attempted_servers)
        if not backend:
            break

        attempted_servers.add(backend.url)
        target_url = f"{backend.url}/{path}{query_str}"

        # Comptabilisation de la connexion active
        backend.active_connections += 1
        backend.total_routed_requests += 1

        try:
            req = http_client.build_request(
                method=request.method,
                url=target_url,
                headers=headers,
                content=body,
                timeout=PROXY_TIMEOUT_SECONDS
            )
            response = await http_client.send(req)

            # Si le backend répond par une erreur serveur temporaire (502, 503, 504), on tente un autre serveur
            if response.status_code in (502, 503, 504) and attempt < MAX_RETRIES:
                backend.total_retried_requests += 1
                logger.warning(f"⚠️ Serveur {backend.url} a renvoyé HTTP {response.status_code}. Auto-retry en cours...")
                continue

            resp_headers = {
                k: v for k, v in response.headers.items()
                if k.lower() not in EXCLUDED_HEADERS
            }
            # Injection des en-têtes CORS pour le client (uniquement si origine autorisée)
            if is_allowed_origin:
                resp_headers["Access-Control-Allow-Origin"] = origin
                resp_headers["Access-Control-Allow-Credentials"] = "true"

            return Response(
                content=response.content,
                status_code=response.status_code,
                headers=resp_headers
            )

        except (httpx.ConnectError, httpx.TimeoutException, httpx.NetworkError) as exc:
            last_exception = exc
            backend.total_retried_requests += 1
            backend.is_healthy = False
            logger.warning(f"⚠️ Échec réseau sur {backend.url} ({exc}). Bascule immédiate sur un autre serveur...")
            continue

        finally:
            backend.active_connections = max(0, backend.active_connections - 1)

    # Si tous les serveurs ont échoué après tous les retries
    logger.error(f"❌ Tous les serveurs ({len(attempted_servers)}) ont échoué pour /{path}")
    return JSONResponse(
        status_code=502,
        content={"error": f"Service temporairement indisponible après plusieurs tentatives ({last_exception})."}
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("aap:app", host="0.0.0.0", port=8080, reload=False)
