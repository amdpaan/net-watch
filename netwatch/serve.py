"""netwatch serve: the dashboard and its JSON API on a small local web server (stdlib http.server).

Access rules:
- By default it binds 127.0.0.1, and requests must carry a localhost Host header. That stops DNS rebinding:
  a web page you visit can't point its own domain at 127.0.0.1 and read your device list.
- With --lan it binds 0.0.0.0 so your phone can open it. Requests from other machines then need the token
  (printed in the URL once, then kept in a SameSite cookie). Without it they get nothing, not even reads.
- Writes are POSTs with a JSON body. Browsers can't send those cross-site without a CORS preflight, which
  we never answer.
"""

import hmac
import ipaddress
import json
import re
import secrets
import subprocess
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import db, home, identify, netinfo, scanner

WEB = Path(__file__).parent / "web"
STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/icon.svg": ("icon.svg", "image/svg+xml"),
}
DEVICE_PATH = re.compile(r"^/api/devices/([0-9a-f]{2}(?::[0-9a-f]{2}){5})(/forget)?$")
COOKIE = "netwatch_token"
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
MAX_BODY = 10_000
HEADERS = {
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",  # the LAN token can be in the URL
    "Cache-Control": "no-store",
}


class Worker:
    """Runs scans one at a time (never two at once) and remembers how the last attempt went."""

    def __init__(self, detect=netinfo.detect, scan=scanner.scan_and_store, on_result=None):
        self.detect, self.scan, self.on_result = detect, scan, on_result
        self.lock = threading.Lock()
        self.status = {"state": "idle", "message": "No scan yet.", "ts": None}

    @property
    def scanning(self):
        return self.lock.locked()

    def run_once(self):
        """One scan if none is running. Returns the ScanResult, or None (busy, away, error)."""
        if not self.lock.acquire(blocking=False):
            return None
        try:
            info = self.detect()
            verdict, message = home.check(info)
            if verdict != home.HOME:
                self.status = {"state": verdict, "message": message, "ts": int(time.time())}
                return None
            result = self.scan(info, log=lambda *_: None)
            self.status = {"state": "ok", "ts": int(time.time()),
                           "message": "%d devices online." % len(result.devices)}
            if self.on_result:
                self.on_result(result)
            return result
        except netinfo.NoNetwork as e:
            self.status = {"state": "offline", "message": str(e), "ts": int(time.time())}
        except scanner.PermissionProblem as e:
            self.status = {"state": "permission", "message": str(e), "ts": int(time.time())}
        except Exception as e:  # keep serving; show what went wrong
            self.status = {"state": "error", "message": "Scan failed: %s" % e, "ts": int(time.time())}
        finally:
            self.lock.release()
        return None

    def start(self):
        if self.scanning:
            return False
        threading.Thread(target=self.run_once, daemon=True).start()
        return True

    def loop(self, minutes, stop=None, log=print):
        """Scan now and then every `minutes` until `stop` is set. Off the home network each attempt is a
        cheap no-op (detect + lock check), so it simply resumes when you get home."""
        stop = stop or threading.Event()
        last_state = None
        while not stop.is_set():
            self.run_once()
            state = self.status["state"]
            if state == "ok" or state != last_state:  # don't repeat "not home" every 5 minutes
                log("%s  %s" % (time.strftime("%Y-%m-%d %H:%M"), self.status["message"]))
            last_state = state
            stop.wait(max(1, minutes) * 60)


def device_json(d, now):
    return {
        "mac": d["mac"], "name": identify.display_name(d), "label": d["label"], "hostname": d["hostname"],
        "type": identify.guess_type(d), "type_set": bool(d["type"]),
        "vendor": identify.vendor_label(d), "private_mac": bool(d["is_random_mac"]),
        "ip": d["last_ip"], "online": d["online"], "is_self": d["is_self"], "is_gateway": d["is_gateway"],
        "first_seen": d["first_seen"], "last_seen": d["last_seen"], "offline_for": None if d["online"] else
        now - d["last_seen"],
    }


def counts(devices):
    """Cards: online now, known (you've labeled them), unknown (not labeled yet)."""
    known = sum(1 for d in devices if d["label"])
    return {"online": sum(1 for d in devices if d["online"]), "known": known, "unknown": len(devices) - known}


class App:
    def __init__(self, lan=False, token=None, worker=None, verbose=False):
        self.lan, self.token, self.verbose = lan, token, verbose
        self.worker = worker or Worker()

    def snapshot(self):
        con = db.connect()
        now = int(time.time())
        devices = db.devices(con)
        scan = db.last_scan(con)
        new_macs = {d["mac"] for d in db.recent_new(con, now=now)}
        cfg = home.load_config().get("home") or {}
        return {
            "now": now,
            "counts": counts(devices),
            "devices": [dict(device_json(d, now), new=d["mac"] in new_macs) for d in devices],
            "new": [device_json(d, now) for d in devices if d["mac"] in new_macs],
            "last_scan": dict(scan) if scan else None,
            "home_subnet": cfg.get("subnet"),
            "status": dict(self.worker.status, scanning=self.worker.scanning),
            "types": db.TYPES,
        }


class Handler(BaseHTTPRequestHandler):
    server_version = "net-watch"
    sys_version = ""
    app = None  # type: App

    def log_message(self, fmt, *args):
        if self.app.verbose:
            BaseHTTPRequestHandler.log_message(self, fmt, *args)

    # ---- plumbing
    def send(self, code, body=b"", ctype="text/plain; charset=utf-8", extra=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        for k, v in dict(HEADERS, **(extra or {})).items():
            self.send_header(k, v)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def json(self, obj, code=200):
        self.send(code, json.dumps(obj), "application/json")

    def error(self, code, message):
        self.json({"error": message}, code)

    def from_loopback(self):
        ip = ipaddress.ip_address(self.client_address[0])
        return ip.is_loopback or (getattr(ip, "ipv4_mapped", None) is not None and ip.ipv4_mapped.is_loopback)

    def host_name(self):
        host = (self.headers.get("Host") or "").strip().lower()
        if host.startswith("["):
            return host[1:].split("]")[0]
        return host.rsplit(":", 1)[0] if host.count(":") == 1 else host

    def cookie_token(self):
        for part in (self.headers.get("Cookie") or "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == COOKIE:
                return value
        return None

    def token_ok(self, value):
        return bool(value and self.app.token and hmac.compare_digest(value, self.app.token))

    def allowed(self, url):
        """Apply the access rules. Sends the refusal itself and returns False when not allowed."""
        if self.from_loopback():
            if self.host_name() in LOCAL_HOSTS:
                return True
            self.error(403, "Host not allowed. Open http://127.0.0.1:%d/" % self.server.server_port)
            return False
        if not self.app.lan:  # can't happen when bound to 127.0.0.1, but don't rely on it
            self.error(403, "LAN access is off.")
            return False
        query = urllib.parse.parse_qs(url.query)
        if self.token_ok((query.get("t") or [None])[0]):
            # Swap the token in the URL for a cookie, so it doesn't sit in history or get shared by accident
            self.send(302, extra={"Location": url.path or "/",
                                  "Set-Cookie": "%s=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=31536000"
                                                % (COOKIE, self.app.token)})
            return False
        if self.token_ok(self.cookie_token()):
            return True
        self.send(401, "net-watch: open the link with the token that `netwatch serve --lan` printed.")
        return False

    def body(self):
        if not (self.headers.get("Content-Type") or "").startswith("application/json"):
            raise ValueError("Content-Type must be application/json")
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            raise ValueError("Body too large")
        data = json.loads(self.rfile.read(length) or b"{}")
        if not isinstance(data, dict):
            raise ValueError("Body must be a JSON object")
        return data

    # ---- routes
    def do_GET(self):
        url = urllib.parse.urlsplit(self.path)
        if not self.allowed(url):
            return
        if url.path in STATIC:
            name, ctype = STATIC[url.path]
            return self.send(200, (WEB / name).read_bytes(), ctype)
        if url.path == "/api/devices":
            return self.json(self.app.snapshot())
        m = DEVICE_PATH.match(url.path)
        if m and not m.group(2):
            row = next((d for d in db.devices(db.connect()) if d["mac"] == m.group(1)), None)
            if not row:
                return self.error(404, "No such device")
            return self.json(device_json(row, int(time.time())))
        self.error(404, "Not found")

    do_HEAD = do_GET

    def do_POST(self):
        url = urllib.parse.urlsplit(self.path)
        if not self.allowed(url):
            return
        try:
            data = self.body()
        except ValueError as e:
            return self.error(400, str(e))
        if url.path == "/api/scan":
            started = self.app.worker.start()
            return self.json({"started": started, "scanning": True}, 202)
        if url.path == "/api/dismiss":
            db.set_meta(db.connect(), "dismissed_before", int(time.time()) + 1)
            return self.json({"ok": True})
        m = DEVICE_PATH.match(url.path)
        if m and m.group(2):
            if not db.forget(db.connect(), m.group(1)):
                return self.error(404, "No such device")
            return self.json({"ok": True})
        if m:
            label, type_ = data.get("label"), data.get("type")
            if label is not None and (not isinstance(label, str) or len(label) > 60):
                return self.error(400, "label must be text, at most 60 characters")
            try:
                if not db.set_label(db.connect(), m.group(1), label, type_):
                    return self.error(404, "No such device")
            except ValueError as e:
                return self.error(400, str(e))
            return self.json({"ok": True})
        self.error(404, "Not found")


def make_server(app, host="127.0.0.1", port=8765):
    handler = type("BoundHandler", (Handler,), {"app": app})
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    return server


def lan_token(rotate=False):
    """A stable token in config.json (so a phone bookmark keeps working); --new-token rotates it."""
    cfg = home.load_config()
    if rotate or not cfg.get("lan_token"):
        cfg["lan_token"] = secrets.token_urlsafe(18)
        home.save_config(cfg)
    return cfg["lan_token"]


def local_hostname():
    name = subprocess.run(["/usr/sbin/scutil", "--get", "LocalHostName"], capture_output=True,
                          text=True).stdout.strip()
    return (name + ".local") if name else None
