"""
DEDIKKA ULTRA LOAD BALANCER & RESILIENCE PROXY (aap.py) — version 3.0
=====================================================================
Répartiteur de charge pour les instances Dedikka hébergées sur Render.

Fonctionnalités :
 1. Least Connections parmi les backends disponibles.
 2. Circuit breaker par backend : isolement après des échecs répétés, puis
    requête test (semi-ouvert) avant de lui redonner du trafic.
 3. Retries seulement lorsqu'ils sont sans risque : méthodes sûres (GET, HEAD),
    requête portant un en-tête Idempotency-Key, ou connexion jamais établie.
 4. Health checks à seuils : pas de mise hors service sur un échec isolé,
    rétablissement vérifié après des succès consécutifs.
 5. Rate limiting par IP, X-Forwarded-For lu uniquement via le proxy de confiance.
 6. Dashboard et API d'administration : clé obligatoire, session signée,
    limitation des tentatives de connexion.
 7. Métriques : latence p50/p95, taux d'erreur, bascules, disponibilité.
 8. Anti-veille Render : ping périodique avec délai adapté au réveil d'un backend.

Variables d'environnement obligatoires :
  BACKEND_URLS          URL des backends, séparées par des virgules
  BALANCER_ADMIN_KEY    clé d'administration (24 caractères minimum, aucune valeur par défaut)

Lancement :
  python aap.py
  En production, un seul worker (l'état est en mémoire) :
  uvicorn aap:app --host 0.0.0.0 --port $PORT --workers 1
"""

import asyncio
import functools
import hashlib
import hmac
import html
import logging
import os
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from typing import Dict, List, Optional, Set, Tuple

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [DedikkaBalancer] %(message)s",
)
logger = logging.getLogger("DedikkaBalancer")

# ==============================================================================
# CONFIGURATION (variables d'environnement)
# ==============================================================================

def _env(name: str, default: str = "") -> str:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip()


def env_int(name: str, default: int) -> int:
    return int(_env(name, str(default)))


def env_float(name: str, default: float) -> float:
    return float(_env(name, str(default)))


def env_bool(name: str, default: bool) -> bool:
    """Valeur stricte : une valeur inconnue fait échouer le démarrage au lieu de désactiver silencieusement."""
    value = _env(name, "true" if default else "false").lower()
    if value in ("1", "true", "yes", "on"):
        return True
    if value in ("0", "false", "no", "off"):
        return False
    raise RuntimeError(f"Valeur invalide pour {name} : {value!r} (attendu : true ou false)")


# Clé administrateur : obligatoire, aucune valeur par défaut
ADMIN_KEY = _env("BALANCER_ADMIN_KEY")
if len(ADMIN_KEY) < 24:
    raise RuntimeError("BALANCER_ADMIN_KEY est obligatoire (24 caractères minimum).")


def parse_backend_urls(raw: str) -> List[str]:
    urls: List[str] = []
    for item in raw.split(","):
        url = item.strip().rstrip("/")
        if not url:
            continue
        if not url.startswith(("https://", "http://")):
            raise RuntimeError(f"URL de backend invalide : {url!r}")
        if url not in urls:
            urls.append(url)
    return urls


BACKEND_SERVERS = parse_backend_urls(_env("BACKEND_URLS"))
if not BACKEND_SERVERS:
    raise RuntimeError("BACKEND_URLS est vide : indiquez les URL des backends, séparées par des virgules.")
if len(BACKEND_SERVERS) < 3:
    logger.warning("Seulement %d backend(s) dans BACKEND_URLS (attendu : 3).", len(BACKEND_SERVERS))

# Health checks et anti-veille Render
HEALTH_ENDPOINT = _env("HEALTH_ENDPOINT", "/api/v1/health")
PING_INTERVAL_SECONDS = env_int("PING_INTERVAL_SECONDS", 300)   # 5 min, sous le seuil de mise en veille de 15 min
PING_TIMEOUT_SECONDS = env_float("PING_TIMEOUT_SECONDS", 60.0)  # un backend endormi peut mettre près d'une minute
HEALTH_FAILURE_THRESHOLD = env_int("HEALTH_FAILURE_THRESHOLD", 2)
HEALTH_RECOVERY_THRESHOLD = env_int("HEALTH_RECOVERY_THRESHOLD", 2)

# Circuit breaker et proxy
CB_FAILURE_THRESHOLD = env_int("CB_FAILURE_THRESHOLD", 3)
CB_OPEN_SECONDS = env_float("CB_OPEN_SECONDS", 30.0)
MAX_RETRIES = env_int("MAX_RETRIES", 2)
PROXY_CONNECT_TIMEOUT_SECONDS = env_float("PROXY_CONNECT_TIMEOUT_SECONDS", 5.0)
PROXY_READ_TIMEOUT_SECONDS = env_float("PROXY_READ_TIMEOUT_SECONDS", 45.0)
PROXY_TOTAL_BUDGET_SECONDS = env_float("PROXY_TOTAL_BUDGET_SECONDS", 60.0)
MAX_CONCURRENT_REQUESTS = env_int("MAX_CONCURRENT_REQUESTS", 500)
MAX_BODY_BYTES = env_int("MAX_BODY_BYTES", 50 * 1024 * 1024)
# Nombre de proxys de confiance devant le balancer (1 sur Render, 0 si exposé directement)
TRUSTED_PROXY_HOPS = env_int("TRUSTED_PROXY_HOPS", 1)

# Rate limiting
RATE_LIMIT_ENABLED = env_bool("RATE_LIMIT_ENABLED", True)
RATE_LIMIT_PER_MINUTE = env_int("RATE_LIMIT_PER_MINUTE", 120)
SENSITIVE_RATE_LIMIT_PER_MINUTE = env_int("SENSITIVE_RATE_LIMIT_PER_MINUTE", 60)
SENSITIVE_PREFIXES = ("/api/v1/payments/", "/api/v1/webhooks/")
LOGIN_MAX_ATTEMPTS = env_int("LOGIN_MAX_ATTEMPTS", 5)
LOGIN_WINDOW_SECONDS = env_int("LOGIN_WINDOW_SECONDS", 900)

# Alertes
TELEGRAM_BOT_TOKEN = _env("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = _env("TELEGRAM_CHAT_ID")
DISCORD_WEBHOOK_URL = _env("DISCORD_WEBHOOK_URL")

# CORS et sécurité
DEFAULT_ALLOWED_ORIGINS = {
    "https://dedikka.web.app",
    "https://dedikka.firebaseapp.com",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:5000",
    "http://127.0.0.1:5000",
}
_origins_from_env = {o.strip().rstrip("/") for o in _env("ALLOWED_ORIGINS").split(",") if o.strip()}
ALLOWED_ORIGINS = _origins_from_env or DEFAULT_ALLOWED_ORIGINS
VERIFY_SSL = env_bool("VERIFY_SSL", True)
COOKIE_SECURE = env_bool("COOKIE_SECURE", True)
SESSION_COOKIE = "dedikka_balancer_session"
SESSION_TTL_SECONDS = 86400 * 7

NO_STORE = {"Cache-Control": "no-store, no-cache, must-revalidate", "X-Content-Type-Options": "nosniff"}

# ==============================================================================
# TÂCHES EN ARRIÈRE-PLAN, ALERTES
# ==============================================================================

background_tasks: Set[asyncio.Task] = set()


def spawn(coro) -> None:
    """Lance une tâche en gardant une référence, pour éviter qu'elle soit supprimée en cours de route."""
    task = asyncio.create_task(coro)
    background_tasks.add(task)
    task.add_done_callback(background_tasks.discard)


async def send_alert_notification(message: str) -> None:
    logger.warning("Alerte : %s", message)
    async with httpx.AsyncClient(timeout=8.0) as client:
        if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
            try:
                await client.post(
                    f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                    json={"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "Markdown"},
                )
            except Exception as exc:
                # On journalise seulement le type d'erreur : l'URL contient le jeton du bot
                logger.error("Échec envoi alerte Telegram (%s)", type(exc).__name__)
        if DISCORD_WEBHOOK_URL:
            try:
                await client.post(DISCORD_WEBHOOK_URL, json={"content": message})
            except Exception as exc:
                logger.error("Échec envoi alerte Discord (%s)", type(exc).__name__)


# ==============================================================================
# ÉTAT DES BACKENDS : CIRCUIT BREAKER + MÉTRIQUES
# ==============================================================================

CIRCUIT_CLOSED = "closed"        # trafic normal
CIRCUIT_OPEN = "open"            # isolé, aucun trafic pendant CB_OPEN_SECONDS
CIRCUIT_HALF_OPEN = "half_open"  # une seule requête test autorisée à la fois


def notify_transition(backend: "BackendServer", event: str, detail: str = "") -> None:
    if event == "down":
        message = (
            f"🚨 *ALERTE PANNE DEDIKKA* : `{backend.url}` est isolé après des échecs répétés. "
            f"Trafic redirigé vers les autres serveurs. Motif : {detail}"
        )
    else:
        message = f"✅ *RÉTABLISSEMENT DEDIKKA* : `{backend.url}` est de nouveau en ligne."
    spawn(send_alert_notification(message))


def _percentile(values, pct: float) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(round(pct / 100 * (len(ordered) - 1))))
    return ordered[index]


class BackendServer:
    def __init__(self, url: str):
        self.url = url
        self.circuit = CIRCUIT_CLOSED
        self.opened_at = 0.0
        self.probe_in_flight = False
        self.consecutive_failures = 0
        self.health_ok_streak = 0
        self.active_connections = 0
        self.total_routed_requests = 0
        self.total_retried_requests = 0
        self.total_errors = 0
        self.failovers = 0
        self.latencies = deque(maxlen=300)  # latences des requêtes proxifiées, en ms
        self.last_check_time: Optional[float] = None
        self.last_health_latency_ms: Optional[float] = None
        self.last_status_code: Optional[int] = None
        self.last_error: Optional[str] = None

    @property
    def is_healthy(self) -> bool:
        return self.circuit == CIRCUIT_CLOSED

    def can_receive(self) -> bool:
        """Lecture seule : indique si le backend peut recevoir une requête maintenant."""
        if self.circuit == CIRCUIT_CLOSED:
            return True
        if self.circuit == CIRCUIT_OPEN:
            return time.time() - self.opened_at >= CB_OPEN_SECONDS
        return not self.probe_in_flight

    def begin_request(self) -> bool:
        """Réserve le backend pour une requête. Retourne True si c'est une requête test."""
        if self.circuit == CIRCUIT_OPEN:
            self.circuit = CIRCUIT_HALF_OPEN
            self.probe_in_flight = False
        was_probe = self.circuit == CIRCUIT_HALF_OPEN
        if was_probe:
            self.probe_in_flight = True
        self.active_connections += 1
        self.total_routed_requests += 1
        return was_probe

    def finish(self, was_probe: bool) -> None:
        self.active_connections = max(0, self.active_connections - 1)
        if was_probe:
            self.probe_in_flight = False

    def record_success(self, source: str) -> None:
        self.consecutive_failures = 0
        self.last_error = None
        if source == "health":
            self.health_ok_streak += 1
            if self.circuit != CIRCUIT_CLOSED and self.health_ok_streak >= HEALTH_RECOVERY_THRESHOLD:
                self._close()
        elif self.circuit != CIRCUIT_CLOSED:
            self._close()

    def record_failure(self, source: str, reason: str) -> None:
        self.consecutive_failures += 1
        self.health_ok_streak = 0
        self.last_error = reason
        if self.circuit == CIRCUIT_HALF_OPEN:
            self._open(reason)
            return
        threshold = CB_FAILURE_THRESHOLD if source == "proxy" else HEALTH_FAILURE_THRESHOLD
        if self.circuit == CIRCUIT_CLOSED and self.consecutive_failures >= threshold:
            self._open(reason)

    def _open(self, reason: str) -> None:
        self.circuit = CIRCUIT_OPEN
        self.opened_at = time.time()
        self.probe_in_flight = False
        self.failovers += 1
        notify_transition(self, "down", reason)

    def _close(self) -> None:
        was_open = self.circuit != CIRCUIT_CLOSED
        self.circuit = CIRCUIT_CLOSED
        self.probe_in_flight = False
        self.health_ok_streak = 0
        if was_open:
            notify_transition(self, "up")

    def to_dict(self) -> dict:
        status = {CIRCUIT_CLOSED: "ONLINE", CIRCUIT_OPEN: "OFFLINE", CIRCUIT_HALF_OPEN: "TEST"}[self.circuit]
        p50 = _percentile(self.latencies, 50)
        p95 = _percentile(self.latencies, 95)
        error_rate = (self.total_errors / self.total_routed_requests * 100) if self.total_routed_requests else 0.0
        return {
            "url": self.url,
            "status": status,
            "active_connections": self.active_connections,
            "total_requests": self.total_routed_requests,
            "total_retries": self.total_retried_requests,
            "total_errors": self.total_errors,
            "error_rate_percent": round(error_rate, 2),
            "failovers": self.failovers,
            "latency_p50_ms": round(p50, 1) if p50 is not None else None,
            "latency_p95_ms": round(p95, 1) if p95 is not None else None,
            "health_latency_ms": round(self.last_health_latency_ms, 1) if self.last_health_latency_ms is not None else None,
            "last_status_code": self.last_status_code,
            "last_check_ago_s": int(time.time() - self.last_check_time) if self.last_check_time else None,
            "consecutive_failures": self.consecutive_failures,
            "last_error": self.last_error,
        }


backends: Dict[str, BackendServer] = {url: BackendServer(url) for url in BACKEND_SERVERS}
http_client: Optional[httpx.AsyncClient] = None
balancer_start_time = time.time()
last_ping_time: Optional[float] = None
next_ping_time: Optional[float] = None


def select_backend(exclude: Set[str]) -> Optional[BackendServer]:
    """Least Connections parmi les backends qui peuvent recevoir du trafic."""
    candidates = [b for b in backends.values() if b.url not in exclude and b.can_receive()]
    if not candidates:
        return None
    candidates.sort(key=lambda b: (b.active_connections, b.total_routed_requests))
    return candidates[0]


# ==============================================================================
# RATE LIMITING EN MÉMOIRE (avec nettoyage)
# ==============================================================================

class SlidingWindowLimiter:
    def __init__(self, window_seconds: float):
        self.window = window_seconds
        self.records: Dict[str, deque] = defaultdict(deque)
        self.lock = asyncio.Lock()
        self.last_sweep = time.time()

    async def is_limited(self, key: str, limit: int) -> bool:
        now = time.time()
        async with self.lock:
            if now - self.last_sweep >= self.window:
                self._sweep(now)
                self.last_sweep = now
            q = self.records[key]
            cutoff = now - self.window
            while q and q[0] <= cutoff:
                q.popleft()
            if len(q) >= limit:
                return True
            q.append(now)
            return False

    def _sweep(self, now: float) -> None:
        """Supprime les clés dont toutes les requêtes sont sorties de la fenêtre."""
        cutoff = now - self.window
        stale = [k for k, q in self.records.items() if not q or q[-1] <= cutoff]
        for key in stale:
            del self.records[key]


request_limiter = SlidingWindowLimiter(60.0)
login_limiter = SlidingWindowLimiter(float(LOGIN_WINDOW_SECONDS))


class ConcurrencyGate:
    """Plafonne les requêtes simultanées : au-delà, le balancer répond 503 au lieu de saturer."""

    def __init__(self, limit: int):
        self.limit = limit
        self.current = 0

    def try_enter(self) -> bool:
        if self.current >= self.limit:
            return False
        self.current += 1
        return True

    def leave(self) -> None:
        self.current = max(0, self.current - 1)


gate = ConcurrencyGate(MAX_CONCURRENT_REQUESTS)


def get_client_ip(request: Request) -> str:
    """
    L'IP réelle est lue dans X-Forwarded-For uniquement pour les derniers sauts
    ajoutés par les proxys de confiance. La partie gauche est contrôlée par le client.
    """
    peer = request.client.host if request.client else "0.0.0.0"
    forwarded = request.headers.get("x-forwarded-for", "")
    if TRUSTED_PROXY_HOPS <= 0 or not forwarded:
        return peer
    hops = [h.strip() for h in forwarded.split(",") if h.strip()]
    if len(hops) < TRUSTED_PROXY_HOPS:
        return peer
    return hops[-TRUSTED_PROXY_HOPS]


def is_sensitive(path: str) -> bool:
    return path.startswith(SENSITIVE_PREFIXES)


# ==============================================================================
# AUTHENTIFICATION ADMINISTRATEUR (session signée, comparaison à temps constant)
# ==============================================================================

def _safe_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _sign(payload: str) -> str:
    return hmac.new(ADMIN_KEY.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def make_session_token() -> str:
    expires = str(int(time.time()) + SESSION_TTL_SECONDS)
    return f"{expires}.{_sign('session:' + expires)}"


def is_valid_session(token: Optional[str]) -> bool:
    if not token or "." not in token:
        return False
    expires, signature = token.split(".", 1)
    if not expires.isdigit() or int(expires) < time.time():
        return False
    return _safe_equal(signature, _sign("session:" + expires))


def check_admin_access(request: Request) -> bool:
    """Accepte l'en-tête X-Balancer-Key (scripts) ou la session du dashboard. Jamais la clé dans l'URL."""
    header_key = request.headers.get("x-balancer-key", "").strip()
    if header_key and _safe_equal(header_key, ADMIN_KEY):
        return True
    return is_valid_session(request.cookies.get(SESSION_COOKIE))


# ==============================================================================
# HEALTH CHECKS ET ANTI-VEILLE RENDER
# ==============================================================================

async def check_backend_health(client: httpx.AsyncClient, backend: BackendServer) -> None:
    started = time.time()
    backend.last_check_time = started
    try:
        response = await client.get(f"{backend.url}{HEALTH_ENDPOINT}", timeout=PING_TIMEOUT_SECONDS)
        backend.last_health_latency_ms = (time.time() - started) * 1000
        backend.last_status_code = response.status_code
        if 200 <= response.status_code < 400:
            backend.record_success("health")
        else:
            backend.record_failure("health", f"HTTP {response.status_code}")
    except Exception as exc:
        backend.last_status_code = None
        backend.last_health_latency_ms = (time.time() - started) * 1000
        reason = type(exc).__name__
        logger.warning("Health check échoué sur %s (%s)", backend.url, reason)
        backend.record_failure("health", reason)


async def execute_cluster_ping() -> dict:
    global last_ping_time, next_ping_time
    last_ping_time = time.time()
    next_ping_time = last_ping_time + PING_INTERVAL_SECONDS
    logger.info("[PING] Vérification de %d backend(s) (anti-veille)", len(backends))
    await asyncio.gather(
        *(check_backend_health(http_client, b) for b in backends.values()),
        return_exceptions=True,
    )
    online = sum(1 for b in backends.values() if b.is_healthy)
    logger.info("[PING] Terminé : %d/%d backend(s) en ligne", online, len(backends))
    return {
        "status": "success",
        "online_servers": online,
        "total_servers": len(backends),
        "last_ping_time": time.strftime("%H:%M:%S", time.localtime(last_ping_time)),
        "next_ping_in_seconds": PING_INTERVAL_SECONDS,
    }


async def periodic_health_monitor() -> None:
    await asyncio.sleep(2)
    while True:
        try:
            await execute_cluster_ping()
        except Exception:
            logger.exception("Erreur durant le cycle de ping")
        await asyncio.sleep(PING_INTERVAL_SECONDS)


# ==============================================================================
# CYCLE DE VIE FASTAPI
# ==============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    global http_client
    http_client = httpx.AsyncClient(
        limits=httpx.Limits(max_keepalive_connections=300, max_connections=1200),
        timeout=httpx.Timeout(
            connect=PROXY_CONNECT_TIMEOUT_SECONDS,
            read=PROXY_READ_TIMEOUT_SECONDS,
            write=30.0,
            pool=5.0,
        ),
        verify=VERIFY_SSL,
    )
    monitor_task = asyncio.create_task(periodic_health_monitor())
    yield
    monitor_task.cancel()
    try:
        await monitor_task
    except asyncio.CancelledError:
        pass
    await http_client.aclose()


app = FastAPI(
    title="Dedikka High-Availability Load Balancer",
    description="Répartiteur de charge avec circuit breaker, rate limiting et retries sécurisés.",
    version="3.0.0",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# ==============================================================================
# ENDPOINTS LOCAUX (non proxifiés) : UPTIMEROBOT ET MONITEURS EXTERNES
# ==============================================================================

@app.api_route("/health", methods=["GET", "HEAD"])
@app.api_route("/ping", methods=["GET", "HEAD"])
@app.api_route("/healthz", methods=["GET", "HEAD"])
@app.api_route("/_balancer/health", methods=["GET", "HEAD"])
async def uptimerobot_endpoint():
    return Response(
        content="OK",
        status_code=200,
        media_type="text/plain",
        headers={**NO_STORE, "X-Balancer-Status": "ONLINE"},
    )


# ==============================================================================
# ADMINISTRATION : LOGIN, LOGOUT, STATUT, PING, DASHBOARD
# ==============================================================================

LOGIN_CSS = """
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #070b14; color: #f3f4f6; margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 16px; box-sizing: border-box; }
.box { width: 100%; max-width: 380px; background: #0f172a; padding: 32px; border-radius: 12px; border: 1px solid #1e293b; text-align: center; }
h2 { color: #ff7a18; margin-top: 0; font-size: 20px; }
p { color: #94a3b8; font-size: 13px; margin-bottom: 20px; }
input { width: 100%; box-sizing: border-box; background: #1e293b; border: 1px solid #334155; color: #fff; padding: 12px; border-radius: 8px; font-size: 14px; margin-bottom: 16px; }
button { width: 100%; background: #ff7a18; color: #fff; border: none; padding: 12px; border-radius: 8px; font-weight: 700; font-size: 14px; cursor: pointer; }
.error { background: #7f1d1d; color: #fca5a5; padding: 10px 14px; border-radius: 8px; margin-bottom: 16px; font-size: 13px; }
"""

DASHBOARD_CSS = """
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #070b14; color: #f3f4f6; margin: 0; padding: 24px; }
.container { max-width: 1200px; margin: auto; background: #0f172a; border-radius: 14px; padding: 24px; border: 1px solid #1e293b; }
.header { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 12px; }
h1 { margin: 0; color: #ff7a18; font-size: 24px; }
.actions { display: flex; gap: 10px; align-items: center; }
.btn { background: #ff7a18; color: #fff; border: none; padding: 8px 14px; border-radius: 8px; font-weight: 700; font-size: 13px; cursor: pointer; text-decoration: none; }
.btn-ghost { background: #1e293b; color: #cbd5e1; }
.info { font-size: 13px; color: #94a3b8; }
.antiveille { background: #132438; border: 1px solid #1d4ed8; padding: 12px 16px; border-radius: 8px; margin: 14px 0; font-size: 13px; color: #93c5fd; }
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin: 16px 0; }
.card { background: #1e293b; padding: 14px 16px; border-radius: 10px; border-left: 4px solid #ff7a18; }
.label { font-size: 12px; color: #94a3b8; text-transform: uppercase; font-weight: 600; }
.value { font-size: 22px; font-weight: 700; margin-top: 4px; }
.table-wrap { overflow-x: auto; margin-top: 16px; }
table { width: 100%; border-collapse: collapse; font-size: 14px; }
th { text-align: left; padding: 12px; background: #1e293b; color: #94a3b8; font-size: 12px; text-transform: uppercase; white-space: nowrap; }
td { padding: 12px; border-bottom: 1px solid #1f2937; vertical-align: top; }
.mono { font-family: monospace; word-break: break-all; }
.badge { color: #fff; padding: 4px 10px; border-radius: 12px; font-size: 12px; font-weight: 700; white-space: nowrap; }
.blue { color: #38bdf8; font-weight: 700; }
.amber { color: #fbbf24; }
.muted { color: #9ca3af; font-size: 13px; }
@media (max-width: 640px) { body { padding: 12px; } .container { padding: 14px; } }
"""


def render_login_screen(error: str = "") -> str:
    error_html = f'<div class="error">{html.escape(error)}</div>' if error else ""
    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Dedikka — Accès Balancer</title>
    <style>{LOGIN_CSS}</style>
</head>
<body>
    <div class="box">
        <h2>Dedikka Balancer — Accès protégé</h2>
        <p>Saisissez la clé d'administration pour afficher le tableau de bord.</p>
        {error_html}
        <form method="POST" action="/_balancer/login">
            <input type="password" name="admin_key" placeholder="Clé d'administration" required autofocus autocomplete="current-password">
            <button type="submit">Déverrouiller</button>
        </form>
    </div>
</body>
</html>"""


def render_dashboard() -> str:
    server_list = list(backends.values())
    online = sum(1 for b in server_list if b.is_healthy)
    total_requests = sum(b.total_routed_requests for b in server_list)
    in_flight = gate.current

    rows = ""
    for b in server_list:
        d = b.to_dict()
        color = {"ONLINE": "#10b981", "OFFLINE": "#ef4444", "TEST": "#f59e0b"}[d["status"]]
        p95 = f"{d['latency_p95_ms']} ms" if d["latency_p95_ms"] is not None else "—"
        last_error = html.escape(b.last_error or "Aucune anomalie")
        rows += f"""
            <tr>
                <td class="mono">{html.escape(b.url)}</td>
                <td><span class="badge" style="background:{color}">{d['status']}</span></td>
                <td class="blue">{b.active_connections}</td>
                <td>{b.total_routed_requests}</td>
                <td class="amber">{b.total_retried_requests}</td>
                <td>{p95}</td>
                <td>{d['error_rate_percent']} %</td>
                <td>{b.failovers}</td>
                <td class="muted">{last_error}</td>
            </tr>"""

    uptime = int(time.time() - balancer_start_time)
    uptime_display = f"{uptime // 3600}h {(uptime % 3600) // 60}m"
    next_in = max(0, int(next_ping_time - time.time())) if next_ping_time else PING_INTERVAL_SECONDS
    next_display = f"{next_in // 60}m {next_in % 60}s"
    last_ping_display = time.strftime("%H:%M:%S", time.localtime(last_ping_time)) if last_ping_time else "au démarrage"

    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="refresh" content="15">
    <title>Dedikka — Tableau de bord Balancer</title>
    <style>{DASHBOARD_CSS}</style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>⚖️ Dedikka Load Balancer</h1>
            <div class="actions">
                <form method="POST" action="/_balancer/ping-now" style="margin:0">
                    <button class="btn" type="submit">⚡ Pinger maintenant</button>
                </form>
                <a class="btn btn-ghost" href="/_balancer/logout">Déconnexion</a>
            </div>
        </div>
        <p class="info">Actualisation toutes les 15 s · Least Connections · Circuit breaker actif</p>
        <div class="antiveille">
            📡 Anti-veille : dernier ping à <b>{last_ping_display}</b> · prochain dans <b>{next_display}</b>
            (intervalle {PING_INTERVAL_SECONDS // 60} min)
        </div>
        <div class="stats">
            <div class="card"><div class="label">Serveurs en ligne</div><div class="value">{online} / {len(server_list)}</div></div>
            <div class="card"><div class="label">Requêtes en cours</div><div class="value">{in_flight}</div></div>
            <div class="card"><div class="label">Requêtes traitées</div><div class="value">{total_requests}</div></div>
            <div class="card"><div class="label">Uptime</div><div class="value">{uptime_display}</div></div>
        </div>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Backend</th><th>Statut</th><th>Connexions</th><th>Requêtes</th>
                        <th>Retries</th><th>Latence p95</th><th>Erreurs</th><th>Bascules</th><th>Dernière anomalie</th>
                    </tr>
                </thead>
                <tbody>{rows}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>"""


@app.post("/_balancer/login")
async def balancer_login(request: Request):
    ip = get_client_ip(request)
    if await login_limiter.is_limited(f"login:{ip}", LOGIN_MAX_ATTEMPTS):
        logger.warning("Trop de tentatives de connexion depuis %s", ip)
        return HTMLResponse(
            content=render_login_screen("Trop de tentatives. Réessayez dans quelques minutes."),
            status_code=429,
            headers=NO_STORE,
        )

    form = await request.form()
    entered = str(form.get("admin_key", "")).strip()
    if not _safe_equal(entered, ADMIN_KEY):
        logger.warning("Connexion administrateur refusée depuis %s", ip)
        return HTMLResponse(
            content=render_login_screen("Clé d'administration incorrecte."),
            status_code=401,
            headers=NO_STORE,
        )

    response = RedirectResponse(url="/_balancer/dashboard", status_code=303, headers=NO_STORE)
    response.set_cookie(
        key=SESSION_COOKIE,
        value=make_session_token(),
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=SESSION_TTL_SECONDS,
        path="/_balancer",
    )
    return response


@app.get("/_balancer/logout")
async def balancer_logout():
    response = RedirectResponse(url="/_balancer/dashboard", status_code=303, headers=NO_STORE)
    response.delete_cookie(SESSION_COOKIE, path="/_balancer", secure=COOKIE_SECURE, httponly=True, samesite="lax")
    return response


@app.post("/_balancer/ping-now")
async def trigger_ping_now(request: Request):
    if not check_admin_access(request):
        return JSONResponse(status_code=401, content={"error": "Accès refusé."}, headers=NO_STORE)
    result = await execute_cluster_ping()
    if "text/html" in request.headers.get("accept", ""):
        return RedirectResponse(url="/_balancer/dashboard", status_code=303, headers=NO_STORE)
    return JSONResponse(result, headers=NO_STORE)


@app.get("/_balancer/status")
async def balancer_status(request: Request):
    if not check_admin_access(request):
        return JSONResponse(status_code=401, content={"error": "Accès refusé."}, headers=NO_STORE)
    uptime = int(time.time() - balancer_start_time)
    next_in = max(0, int(next_ping_time - time.time())) if next_ping_time else 0
    return JSONResponse(
        {
            "service": "Dedikka Ultra Load Balancer",
            "version": app.version,
            "uptime_seconds": uptime,
            "ping_interval_seconds": PING_INTERVAL_SECONDS,
            "last_ping": time.strftime("%H:%M:%S", time.localtime(last_ping_time)) if last_ping_time else None,
            "next_ping_in_seconds": next_in,
            "rate_limit_per_minute": RATE_LIMIT_PER_MINUTE,
            "max_concurrent_requests": MAX_CONCURRENT_REQUESTS,
            "in_flight_requests": gate.current,
            "servers_total": len(backends),
            "servers_online": sum(1 for b in backends.values() if b.is_healthy),
            "backends": [b.to_dict() for b in backends.values()],
        },
        headers=NO_STORE,
    )


@app.get("/_balancer/dashboard", response_class=HTMLResponse)
async def balancer_dashboard(request: Request):
    if not check_admin_access(request):
        return HTMLResponse(content=render_login_screen(), status_code=401, headers=NO_STORE)
    return HTMLResponse(content=render_dashboard(), headers=NO_STORE)


@app.api_route(
    "/_balancer/{rest:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
)
async def balancer_unknown_route(rest: str):
    """Les chemins /_balancer/* ne sont jamais transmis aux backends."""
    return JSONResponse(status_code=404, content={"error": "Route d'administration inconnue."})


# ==============================================================================
# PROXY INVERSE : CORS + RATE LIMITING + LEAST CONNECTIONS + RETRIES SÛRS
# ==============================================================================

EXCLUDED_REQUEST_HEADERS = {
    "host", "content-length", "transfer-encoding", "connection", "keep-alive", "te", "trailer",
    "upgrade", "proxy-authorization", "proxy-connection",
    "x-forwarded-for", "x-forwarded-proto", "x-real-ip",
}
EXCLUDED_RESPONSE_HEADERS = {
    "content-length", "transfer-encoding", "connection", "keep-alive", "te", "trailer", "upgrade",
    "proxy-authenticate", "proxy-authorization",
    "access-control-allow-origin", "access-control-allow-credentials", "access-control-allow-methods",
    "access-control-allow-headers", "access-control-max-age", "access-control-expose-headers",
}
SAFE_METHODS = {"GET", "HEAD"}
RETRYABLE_STATUS = {502, 503, 504}
PROXY_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]


def build_upstream_headers(request: Request, client_ip: str) -> List[Tuple[str, str]]:
    peer = request.client.host if request.client else ""
    incoming_xff = request.headers.get("x-forwarded-for", "")
    headers: List[Tuple[str, str]] = []
    for key, value in request.headers.items():
        lower = key.lower()
        if lower in EXCLUDED_REQUEST_HEADERS:
            continue
        if lower == "cookie":
            # Le cookie de session du dashboard ne doit jamais atteindre les backends
            value = "; ".join(
                part.strip() for part in value.split(";")
                if part.strip() and part.strip().split("=", 1)[0] != SESSION_COOKIE
            )
            if not value:
                continue
        headers.append((key, value))
    headers.append(("X-Forwarded-For", f"{incoming_xff}, {peer}" if incoming_xff else peer))
    headers.append(("X-Real-IP", client_ip))
    headers.append(("X-Forwarded-Proto", request.url.scheme))
    return headers


async def read_body(request: Request) -> Optional[bytes]:
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > MAX_BODY_BYTES:
        return None
    chunks: List[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > MAX_BODY_BYTES:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


def network_error_is_retry_safe(exc: httpx.HTTPError, idempotent: bool) -> bool:
    """Une connexion jamais établie n'a rien envoyé : rejouer est sans risque, quelle que soit la méthode."""
    if isinstance(exc, (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout)):
        return True
    return idempotent


def _release_stream(backend: BackendServer, was_probe: bool) -> None:
    backend.finish(was_probe)
    gate.leave()


def build_streamed_response(upstream: httpx.Response, on_done, cors: Dict[str, str]) -> StreamingResponse:
    """Relaie la réponse en flux brut : pas de décompression, en-têtes dupliqués (Set-Cookie) conservés."""

    async def relay():
        try:
            async for chunk in upstream.aiter_raw():
                yield chunk
        finally:
            await upstream.aclose()
            on_done()

    response = StreamingResponse(relay(), status_code=upstream.status_code)
    for key, value in upstream.headers.multi_items():
        if key.lower() not in EXCLUDED_RESPONSE_HEADERS:
            response.raw_headers.append((key.encode("latin-1"), value.encode("latin-1")))
    for key, value in cors.items():
        response.headers[key] = value
    return response


@app.api_route("/{path:path}", methods=PROXY_METHODS)
async def dynamic_proxy(request: Request, path: str):
    # 1. CORS : réponse immédiate aux preflights, uniquement pour les origines autorisées
    origin = request.headers.get("origin", "")
    origin_allowed = bool(origin) and origin in ALLOWED_ORIGINS
    cors: Dict[str, str] = {"Vary": "Origin"}
    if origin_allowed:
        cors["Access-Control-Allow-Origin"] = origin
        cors["Access-Control-Allow-Credentials"] = "true"

    if request.method == "OPTIONS":
        return Response(
            status_code=204,
            headers={
                **cors,
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "Authorization, Content-Type, X-CSRF-Token, X-Requested-With, Idempotency-Key",
                "Access-Control-Max-Age": "86400",
            },
        )

    full_path = f"/{path}"
    client_ip = get_client_ip(request)

    # 2. Rate limiting : pas d'exemption par User-Agent ; paiements et webhooks ont une limite dédiée
    if RATE_LIMIT_ENABLED:
        sensitive = is_sensitive(full_path)
        bucket = "sensitive" if sensitive else "general"
        limit = SENSITIVE_RATE_LIMIT_PER_MINUTE if sensitive else RATE_LIMIT_PER_MINUTE
        if await request_limiter.is_limited(f"{bucket}:{client_ip}", limit):
            logger.warning("Rate limit atteint pour %s sur %s", client_ip, full_path)
            return JSONResponse(
                status_code=429,
                content={"error": "Trop de requêtes. Réessayez dans une minute."},
                headers={**cors, "Retry-After": "60"},
            )

    # 3. Corps de requête borné en taille
    body = await read_body(request)
    if body is None:
        return JSONResponse(status_code=413, content={"error": "Requête trop volumineuse."}, headers=cors)

    # 4. Limite de concurrence
    if not gate.try_enter():
        return JSONResponse(
            status_code=503,
            content={"error": "Service surchargé. Réessayez dans quelques secondes."},
            headers={**cors, "Retry-After": "5"},
        )

    handed_off = False
    try:
        idempotent = request.method in SAFE_METHODS or "idempotency-key" in request.headers
        upstream_headers = build_upstream_headers(request, client_ip)
        query = f"?{request.url.query}" if request.url.query else ""
        attempted: Set[str] = set()
        started = time.time()

        for attempt in range(MAX_RETRIES + 1):
            if time.time() - started > PROXY_TOTAL_BUDGET_SECONDS:
                break
            backend = select_backend(attempted)
            if backend is None:
                break
            attempted.add(backend.url)
            can_retry = attempt < MAX_RETRIES

            upstream_request = http_client.build_request(
                method=request.method,
                url=f"{backend.url}{full_path}{query}",
                headers=upstream_headers,
                content=body,
            )
            was_probe = backend.begin_request()
            t0 = time.time()

            try:
                upstream = await http_client.send(upstream_request, stream=True)
            except httpx.HTTPError as exc:
                backend.finish(was_probe)
                backend.total_errors += 1
                backend.record_failure("proxy", type(exc).__name__)
                logger.warning("Échec réseau sur %s (%s)", backend.url, type(exc).__name__)
                if can_retry and network_error_is_retry_safe(exc, idempotent):
                    backend.total_retried_requests += 1
                    continue
                break
            except BaseException:
                backend.finish(was_probe)
                raise

            latency_ms = (time.time() - t0) * 1000
            status = upstream.status_code
            backend.last_status_code = status
            backend.latencies.append(latency_ms)

            gateway_error = status in RETRYABLE_STATUS
            if gateway_error:
                backend.total_errors += 1
                backend.record_failure("proxy", f"HTTP {status}")
            else:
                backend.record_success("proxy")

            # Nouvelle tentative uniquement si elle est sans risque
            if gateway_error and can_retry and idempotent:
                await upstream.aclose()
                backend.finish(was_probe)
                backend.total_retried_requests += 1
                logger.warning("%s a renvoyé HTTP %s : nouvelle tentative", backend.url, status)
                continue

            # La réponse est transmise au client : la libération se fait à la fin du flux
            handed_off = True
            on_done = functools.partial(_release_stream, backend, was_probe)
            return build_streamed_response(upstream, on_done, cors)

        error_body = {"error": "Service temporairement indisponible. Réessayez dans quelques instants."}
        if not attempted:
            logger.error("Aucun backend disponible pour %s", full_path)
            return JSONResponse(status_code=503, content=error_body, headers={**cors, "Retry-After": "10"})
        logger.error("Échec sur les %d backend(s) essayés pour %s", len(attempted), full_path)
        return JSONResponse(status_code=502, content=error_body, headers={**cors, "Retry-After": "10"})

    finally:
        if not handed_off:
            gate.leave()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("aap:app", host="0.0.0.0", port=int(_env("PORT", "8080")), reload=False, workers=1)
