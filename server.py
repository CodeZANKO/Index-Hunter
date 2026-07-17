"""IndexHunter web backend (FastAPI).

Serves a Tailwind frontend and streams live scan events over SSE. The original
async scanning engine (scanner.py) is reused unchanged — its callbacks push
events into an in-process event bus that SSE clients consume.

Run:
    python indexhunter.py --web            # http://127.0.0.1:8000
    python server.py                    # same
"""
import asyncio
import base64
import hashlib
import hmac
import json
import os
import secrets
import tempfile
import time

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, StreamingResponse, FileResponse, JSONResponse, RedirectResponse
from starlette.background import BackgroundTask

import filters as filters_mod
from scanner import Scanner, ScanConfig
from exporter import export as export_findings

WEB_DIR = os.path.dirname(os.path.abspath(__file__))
INDEX = os.path.join(WEB_DIR, "templates", "index.html")
LOGIN = os.path.join(WEB_DIR, "templates", "login.html")

# ---------------------------------------------------------------- auth
# Simple, dependency-free session auth (HMAC-signed cookie).
SECRET_FILE = os.path.join(WEB_DIR, "indexhunter_secret.txt")
AUTH_FILE = os.path.join(WEB_DIR, "indexhunter_auth.json")
SCANS_FILE = os.path.join(WEB_DIR, "indexhunter_scans.json")
SESSION_TTL = 60 * 60 * 24 * 7  # 7 days

DEFAULT_USER = os.environ.get("DEEPSCAN_USER", "admin")
DEFAULT_PASS = os.environ.get("DEEPSCAN_PASS", "admin")


def _load_secret():
    if os.environ.get("DEEPSCAN_SECRET"):
        return os.environ["DEEPSCAN_SECRET"]
    if os.path.exists(SECRET_FILE):
        with open(SECRET_FILE, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    s = secrets.token_hex(32)
    with open(SECRET_FILE, "w", encoding="utf-8") as fh:
        fh.write(s)
    os.chmod(SECRET_FILE, 0o600)
    return s


SECRET = _load_secret()


def _hash_password(pw, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 100_000)
    return salt + "$" + dk.hex()


def _load_auth():
    if not os.path.exists(AUTH_FILE):
        data = {"username": DEFAULT_USER, "password": _hash_password(DEFAULT_PASS)}
        with open(AUTH_FILE, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        os.chmod(AUTH_FILE, 0o600)
        print(f"[auth] No credentials found — created default "
              f"user '{DEFAULT_USER}' / password '{DEFAULT_PASS}'. "
              f"Change it via Settings -> Change password.")
    else:
        with open(AUTH_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if "password" not in data and "password_hash" in data:
            data["password"] = data.pop("password_hash")  # normalize
    return data


def _save_auth(data):
    with open(AUTH_FILE, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    os.chmod(AUTH_FILE, 0o600)


def _load_scans():
    if not os.path.exists(SCANS_FILE):
        return []
    with open(SCANS_FILE, "r", encoding="utf-8") as fh:
        try:
            return json.load(fh)
        except Exception:
            return []


def _save_scans(scans):
    with open(SCANS_FILE, "w", encoding="utf-8") as fh:
        json.dump(scans, fh)
    os.chmod(SCANS_FILE, 0o600)


def _verify_password(pw, stored):
    salt, _, h = stored.partition("$")
    if not salt or not h:
        return False
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 100_000)
    return hmac.compare_digest(dk.hex(), h)


def create_session(username):
    ts = str(int(time.time()))
    payload = base64.urlsafe_b64encode(username.encode()).decode()
    sig = hmac.new(SECRET.encode(), (payload + "." + ts).encode(),
                   hashlib.sha256).hexdigest()
    return f"{payload}.{ts}.{sig}"


def verify_session(token):
    if not token:
        return None
    try:
        payload, ts, sig = token.split(".")
    except Exception:
        return None
    try:
        if int(time.time()) - int(ts) > SESSION_TTL:
            return None
    except Exception:
        return None
    exp = hmac.new(SECRET.encode(), (payload + "." + ts).encode(),
                   hashlib.sha256).hexdigest()
    if not hmac.compare_digest(exp, sig):
        return None
    try:
        return base64.urlsafe_b64decode(payload).decode()
    except Exception:
        return None


AUTH = _load_auth()


class AuthMiddleware:
    """Raw ASGI middleware that protects the JSON API with a bearer token
    (Authorization header or ?token= query param). The SPA shell at "/" is
    served publicly; index.html gates the UI client-side and redirects to
    /login when no token is present. Implemented at the ASGI layer (not
    BaseHTTPMiddleware) so it never buffers the SSE stream."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        # Public routes (login page + login API) stay open.
        if path in ("/login", "/api/login"):
            await self.app(scope, receive, send)
            return
        token = self._extract_token(scope)
        user = verify_session(token) if token else None
        if user:
            scope["indexhunter_user"] = user
            await self.app(scope, receive, send)
            return
        if path.startswith("/api"):
            await _send_json(send, 401, {"error": "unauthorized"})
        else:
            # Serve the SPA shell; index.html will redirect to /login if the
            # client has no token.
            await self.app(scope, receive, send)

    @staticmethod
    def _extract_token(scope):
        # 1) Authorization: Bearer <token>
        for raw in scope.get("headers", []):
            if raw[0].lower() == b"authorization":
                val = raw[1].decode("latin-1")
                if val.lower().startswith("bearer "):
                    return val[7:].strip()
        # 2) ?token= query param (used by EventSource / downloads)
        q = scope.get("query_string", b"").decode("latin-1")
        for kv in q.split("&"):
            k, _, v = kv.partition("=")
            if k == "token" and v:
                from urllib.parse import unquote
                return unquote(v)
        return None


async def _send_json(send, status, obj):
    import json as _json
    body = _json.dumps(obj).encode()
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [(b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode())],
    })
    await send({"type": "http.response.body", "body": body})


async def _send_redirect(send, location):
    await send({
        "type": "http.response.start",
        "status": 302,
        "headers": [(b"location", location.encode())],
    })
    await send({"type": "http.response.body", "body": b""})


app = FastAPI(title="IndexHunter")
app.add_middleware(AuthMiddleware)

# ---------------------------------------------------------------- event bus
class EventBus:
    def __init__(self):
        self.subs = set()

    def subscribe(self):
        q = asyncio.Queue()
        self.subs.add(q)
        return q

    def unsubscribe(self, q):
        self.subs.discard(q)

    def publish(self, event):
        for q in list(self.subs):
            try:
                q.put_nowait(event)
            except Exception:
                pass


bus = EventBus()


# ---------------------------------------------------------------- scan mgr
class ScanManager:
    def __init__(self):
        self.scanner = None
        self.task = None

    def _callbacks(self):
        return {
            "progress": lambda s: bus.publish({"type": "progress", "data": s}),
            "found": lambda f: bus.publish({"type": "found", "data": f}),
            "dir": lambda p: bus.publish({"type": "dir", "data": p}),
            "log": lambda m: bus.publish({"type": "log", "data": m}),
            "finished": lambda s: bus.publish({"type": "finished", "data": s}),
        }

    async def start(self, cfg_dict):
        if self.task and not self.task.done():
            return False
        resume_path = None
        if cfg_dict.get("resume"):
            resume_path = os.path.join(WEB_DIR, "indexhunter_resume.json")
        ignore_file = cfg_dict.get("ignore_file")
        if cfg_dict.get("ignore_text"):
            tf = tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt",
                                             encoding="utf-8")
            tf.write(cfg_dict["ignore_text"])
            tf.close()
            ignore_file = tf.name
        cfg = ScanConfig(
            base_url=cfg_dict["url"],
            workers=int(cfg_dict.get("workers", 10)),
            depth=int(cfg_dict.get("depth", 0)),
            full_scan=bool(cfg_dict.get("full")),
            respect_robots=bool(cfg_dict.get("robots", True)),
            yara_dir=cfg_dict.get("yara_dir") or os.path.join(WEB_DIR, "yara_rules"),
            plugins_dir=cfg_dict.get("plugins_dir") or os.path.join(WEB_DIR, "plugins"),
            ignore_file=ignore_file,
            resume_path=resume_path,
        )
        self.scanner = Scanner(cfg, callbacks=self._callbacks())
        self.task = asyncio.create_task(self.scanner.run())
        self.task.add_done_callback(self._task_done)
        return True

    def _task_done(self, task):
        try:
            task.result()
        except Exception as e:
            bus.publish({"type": "log", "data": f"[scan error] {e}"})

    def stop(self):
        if self.scanner:
            self.scanner.stop()

    def findings(self):
        return self.scanner.findings if self.scanner else []


mgr = ScanManager()


# ---------------------------------------------------------------- helpers
MEDIA = {
    "json": "application/json",
    "csv": "text/csv",
    "html": "text/html",
    "markdown": "text/markdown",
    "md": "text/markdown",
    "sarif": "application/json",
    "pdf": "application/pdf",
}


def _build_spec(q):
    spec = filters_mod.FilterSpec()
    sev = q.get("severity", "")
    if sev:
        spec.severities = {x.strip().lower() for x in sev.split(",") if x.strip()}
    cat = q.get("category", "")
    if cat:
        spec.categories = {x.strip().upper() for x in cat.split(",") if x.strip()}
    ext = q.get("ext", "")
    if ext:
        spec.extensions = {x.strip().lower() if x.startswith(".") else "." + x.strip().lower()
                           for x in ext.split(",") if x.strip()}
    spec.folder = q.get("folder", "") or ""
    spec.keyword = q.get("keyword", "") or ""
    spec.regex = q.get("regex", "") or ""
    spec.compile()
    return spec


def _filtered(q):
    spec = _build_spec(q)
    return [f for f in mgr.findings() if filters_mod.matches(f, spec)]


# ---------------------------------------------------------------- routes
@app.get("/", response_class=HTMLResponse)
def index():
    with open(INDEX, encoding="utf-8") as fh:
        return HTMLResponse(fh.read())


@app.get("/login", response_class=HTMLResponse)
def login_page():
    with open(LOGIN, encoding="utf-8") as fh:
        return HTMLResponse(fh.read())


@app.post("/api/login")
async def api_login(req: Request, response: Response):
    try:
        body = await req.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "invalid request"},
                            status_code=400)
    user = (body.get("username") or "").strip()
    pw = body.get("password") or ""
    if user == AUTH.get("username") and _verify_password(pw, AUTH.get("password", "")):
        token = create_session(user)
        return {"ok": True, "token": token}
    return JSONResponse({"ok": False, "error": "Invalid username or password"},
                        status_code=401)


@app.post("/api/logout")
def api_logout():
    # Token lives in the client (localStorage); logout just clears it client-side.
    return {"ok": True}


@app.post("/api/change_password")
async def api_change_password(req: Request, response: Response):
    auth = req.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
    else:
        token = req.query_params.get("token", "")
    user = verify_session(token)
    if not user:
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
    try:
        body = await req.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "invalid request"},
                            status_code=400)
    cur = body.get("current") or ""
    new = body.get("new") or ""
    if not _verify_password(cur, AUTH.get("password", "")):
        return JSONResponse({"ok": False, "error": "Current password is wrong"},
                            status_code=400)
    if len(new) < 4:
        return JSONResponse({"ok": False, "error": "Password too short (min 4)"},
                            status_code=400)
    AUTH["password"] = _hash_password(new)
    _save_auth(AUTH)
    # Return a fresh token so the client can replace the old one.
    new_token = create_session(user)
    return {"ok": True, "token": new_token}


@app.post("/api/scan")
async def start_scan(req: Request):
    try:
        body = await req.json()
        if not body.get("url"):
            return {"started": False, "error": "url required"}
        ok = await mgr.start(body)
        return {"started": ok}
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {"started": False, "error": str(e)}


@app.post("/api/stop")
async def stop_scan():
    mgr.stop()
    return {"stopped": True}


@app.get("/api/stream")
async def stream():
    q = bus.subscribe()

    async def gen():
        try:
            while True:
                ev = await q.get()
                yield f"data: {json.dumps(ev, default=str)}\n\n"
        except asyncio.CancelledError:
            bus.unsubscribe(q)

    return StreamingResponse(gen(), media_type="text/event-stream")


@app.get("/api/status")
def status():
    """Return current scan statistics (used by polling fallback)."""
    if mgr.scanner and not mgr.scanner.stats.get("finished"):
        s = mgr.scanner.stats
        return {
            "running": True,
            "scanned": s.get("scanned", 0),
            "queue": s.get("queue", 0),
            "critical": s.get("critical", 0),
            "high": s.get("high", 0),
            "medium": s.get("medium", 0),
            "low": s.get("low", 0),
            "folders": len(s.get("folders", set())),
            "files_total": s.get("files_total", 0),
            "requests": s.get("requests", 0),
            "current_folder": s.get("current_folder", ""),
            "current_file": s.get("current_file", ""),
            "speed": s.get("speed", 0),
            "memory": "n/a",
        }
    return {"running": False, "scanned": 0, "queue": 0}

@app.get("/api/findings")
def findings(severity: str = "", category: str = "", ext: str = "",
             folder: str = "", keyword: str = "", regex: str = ""):
    q = {"severity": severity, "category": category, "ext": ext,
         "folder": folder, "keyword": keyword, "regex": regex}
    data = _filtered(q)
    return {"count": len(data), "findings": data}


@app.get("/api/scans")
def list_scans():
    return {"scans": _load_scans()}


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str):
    scans = _load_scans()
    for scan in scans:
        if scan.get("id") == scan_id:
            return scan
    return JSONResponse({"error": "not found"}, status_code=404)


@app.delete("/api/scans/{scan_id}")
def delete_scan(scan_id: str):
    scans = _load_scans()
    scans = [s for s in scans if s.get("id") != scan_id]
    _save_scans(scans)
    return {"ok": True}


@app.post("/api/scans")
async def save_scan(req: Request):
    body = await req.json()
    scan = {
        "id": str(int(time.time() * 1000)),
        "url": body.get("url", ""),
        "config": body.get("config", {}),
        "findings": body.get("findings", []),
        "tree": body.get("tree", {}),
        "summary": body.get("summary", {}),
        "created": time.time(),
    }
    scans = _load_scans()
    scans.insert(0, scan)
    scans = scans[:50]  # keep last 50
    _save_scans(scans)
    return {"ok": True, "id": scan["id"]}


@app.get("/api/export")
def export(format: str = "json", severity: str = "", category: str = "",
           ext: str = "", folder: str = "", keyword: str = "", regex: str = ""):
    q = {"severity": severity, "category": category, "ext": ext,
         "folder": folder, "keyword": keyword, "regex": regex}
    data = _filtered(q)
    suffix = format.lower()
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix="." + suffix)
    tmp.close()
    try:
        export_findings(data, suffix, tmp.name)
    except Exception as e:
        os.unlink(tmp.name)
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail=str(e))
    media = MEDIA.get(suffix, "application/octet-stream")
    return FileResponse(tmp.name, filename=f"indexhunter_report.{suffix}",
                        media_type=media, background=BackgroundTask(os.unlink, tmp.name))
