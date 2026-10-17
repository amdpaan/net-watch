"""Dashboard server: access rules (Host check, LAN token, JSON-only writes) and the API."""

import http.client
import ipaddress
import json
import threading
import time

import pytest

from netwatch import db, home, serve
from netwatch.netinfo import NetInfo
from netwatch.scanner import Device, ScanResult

INFO = NetInfo("en0", "192.168.50.10", "ee:00:00:00:00:01", ipaddress.IPv4Network("192.168.50.0/24"),
               "192.168.50.1", "00:00:5e:00:53:01")
TV = "00:00:5e:00:53:2a"


class IdleWorker:
    scanning = False
    status = {"state": "ok", "message": "", "ts": None}
    started = 0

    def start(self):
        IdleWorker.started += 1
        return True


@pytest.fixture
def seeded():
    con = db.connect()
    now = int(time.time())
    db.record_scan(con, ScanResult(INFO, [Device("192.168.50.1", INFO.gateway_mac, is_gateway=True)]), {}, now=now - 600)
    db.record_scan(con, ScanResult(INFO, [Device("192.168.50.1", INFO.gateway_mac, is_gateway=True),
                                          Device("192.168.50.20", TV, "<b>tv</b>")]), {}, now=now - 300)
    return con


def start(app, lan_client=False):
    server = serve.make_server(app, "127.0.0.1", 0)
    if lan_client:  # pretend requests come from another machine on the Wi-Fi
        server.RequestHandlerClass.from_loopback = lambda self: False
    threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()
    return server


def request(server, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    hdrs = {"Host": "127.0.0.1:%d" % server.server_port}
    hdrs.update(headers or {})
    data = None
    if body is not None:
        data = json.dumps(body)
        hdrs.setdefault("Content-Type", "application/json")
    conn.request(method, path, data, hdrs)
    resp = conn.getresponse()
    raw = resp.read()
    try:
        payload = json.loads(raw)
    except ValueError:
        payload = raw.decode()
    return resp.status, payload, resp


@pytest.fixture
def local(seeded):
    server = start(serve.App(worker=IdleWorker()))
    yield server
    server.shutdown()
    server.server_close()


def test_dashboard_and_api(local):
    status, page, resp = request(local, "GET", "/")
    assert status == 200 and "net-watch" in page
    assert "default-src 'self'" in resp.getheader("Content-Security-Policy")
    status, data, _ = request(local, "GET", "/api/devices")
    assert status == 200
    assert data["counts"] == {"online": 2, "known": 0, "unknown": 2}
    tv = next(d for d in data["devices"] if d["mac"] == TV)
    assert tv["online"] and tv["new"] and tv["name"] == "<b>tv</b>"  # raw text; the page uses textContent
    assert [d["mac"] for d in data["new"]] == [TV]


@pytest.mark.parametrize("host", ["evil.example", "evil.example:8765", "192.168.50.10:8765", ""])
def test_foreign_host_header_refused(local, host):
    status, _, _ = request(local, "GET", "/api/devices", headers={"Host": host})
    assert status == 403


def test_localhost_names_allowed(local):
    for host in ("localhost:%d" % local.server_port, "[::1]:%d" % local.server_port):
        assert request(local, "GET", "/api/devices", headers={"Host": host})[0] == 200


def test_label_via_api(local):
    status, _, _ = request(local, "POST", "/api/devices/" + TV, {"label": "Living room TV", "type": "tv"})
    assert status == 200
    d = db.get(db.connect(), TV)
    assert (d["label"], d["type"]) == ("Living room TV", "tv")
    _, data, _ = request(local, "GET", "/api/devices")
    assert data["counts"]["known"] == 1 and data["new"] == []  # labeled devices leave the banner


def test_writes_need_json(local):
    status, _, _ = request(local, "POST", "/api/devices/" + TV, None,
                           headers={"Content-Type": "application/x-www-form-urlencoded", "Content-Length": "7"})
    assert status == 400
    assert db.get(db.connect(), TV)["label"] is None


def test_bad_input(local):
    assert request(local, "POST", "/api/devices/" + TV, {"type": "toaster"})[0] == 400
    assert request(local, "POST", "/api/devices/" + TV, {"label": "x" * 61})[0] == 400
    assert request(local, "POST", "/api/devices/00:00:5e:00:53:77", {"label": "x"})[0] == 404
    assert request(local, "GET", "/api/devices/not-a-mac")[0] == 404
    assert request(local, "GET", "/../netwatch/db.py")[0] == 404


def test_forget_and_dismiss(local):
    assert request(local, "POST", "/api/dismiss", {})[0] == 200
    assert request(local, "GET", "/api/devices")[1]["new"] == []
    assert request(local, "POST", "/api/devices/%s/forget" % TV, {})[0] == 200
    assert db.get(db.connect(), TV) is None


def test_scan_button(local):
    before = IdleWorker.started
    assert request(local, "POST", "/api/scan", {})[0] == 202
    assert IdleWorker.started == before + 1


@pytest.fixture
def lan(seeded):
    server = start(serve.App(lan=True, token="s3cret-token", worker=IdleWorker()), lan_client=True)
    yield server
    server.shutdown()
    server.server_close()


def test_lan_needs_token_even_for_reads(lan):
    assert request(lan, "GET", "/api/devices")[0] == 401
    assert request(lan, "GET", "/")[0] == 401
    assert request(lan, "POST", "/api/devices/" + TV, {"label": "pwned"})[0] == 401
    assert request(lan, "GET", "/?t=wrong")[0] == 401
    assert db.get(db.connect(), TV)["label"] is None


def test_lan_token_link_sets_cookie(lan):
    status, _, resp = request(lan, "GET", "/?t=s3cret-token")
    assert status == 302 and resp.getheader("Location") == "/"
    cookie = resp.getheader("Set-Cookie")
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie
    jar = {"Cookie": cookie.split(";")[0]}
    assert request(lan, "GET", "/api/devices", headers=jar)[0] == 200
    assert request(lan, "POST", "/api/devices/" + TV, {"label": "TV"}, headers=jar)[0] == 200


def test_lan_token_persists_and_rotates():
    first = serve.lan_token()
    assert serve.lan_token() == first and len(first) >= 20
    assert serve.lan_token(rotate=True) != first


def test_worker_respects_lock():
    """The worker never scans away from home and reports why."""
    scans = []
    away = NetInfo(**dict(INFO.__dict__, gateway_mac="00:00:5e:00:53:99"))
    home.save_home(INFO)
    w = serve.Worker(detect=lambda: away, scan=lambda *a, **k: scans.append(1))
    assert w.run_once() is None
    assert scans == [] and w.status["state"] == home.AWAY


def test_worker_scans_at_home():
    home.save_home(INFO)
    results = []
    fake = ScanResult(INFO, [Device("192.168.50.1", INFO.gateway_mac)])
    w = serve.Worker(detect=lambda: INFO, scan=lambda info, log: fake, on_result=results.append)
    assert w.run_once() is fake
    assert results == [fake] and w.status["state"] == "ok"


def test_worker_one_scan_at_a_time():
    home.save_home(INFO)
    w = serve.Worker(detect=lambda: INFO, scan=lambda info, log: None)
    w.lock.acquire()
    assert w.run_once() is None and not w.start()
    w.lock.release()


def test_summary_endpoint(local):
    status, data, _ = request(local, "GET", "/api/summary")
    assert status == 200
    assert {k: data[k] for k in ("online", "known", "unknown")} == {"online": 2, "known": 0, "unknown": 2}
    assert "generated_at" in data and "on_home_network" in data


def test_timeline_endpoint(local):
    status, data, _ = request(local, "GET", "/api/devices/%s/timeline" % TV)
    assert status == 200 and len(data["days"]) == 7
    assert request(local, "GET", "/api/devices/00:00:5e:00:53:77/timeline")[0] == 404


def test_summary_needs_token_from_lan(lan):
    assert request(lan, "GET", "/api/summary")[0] == 401
