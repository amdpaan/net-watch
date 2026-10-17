import ipaddress
import threading

from netwatch import db, notify, serve
from netwatch.netinfo import NetInfo
from netwatch.scanner import Device, ScanResult

INFO = NetInfo("en0", "192.168.50.10", "ee:00:00:00:00:01", ipaddress.IPv4Network("192.168.50.0/24"),
               "192.168.50.1", "00:00:5e:00:53:01")
ROUTER = Device("192.168.50.1", INFO.gateway_mac, is_gateway=True)


class Outbox:
    def __init__(self):
        self.sent = []

    def __call__(self, title, message, url=None, group=None):
        self.sent.append((title, message))


def setup_network(devices_later, vendors=None):
    con = db.connect()
    db.record_scan(con, ScanResult(INFO, [ROUTER]), {}, now=1000)  # baseline
    new = db.record_scan(con, ScanResult(INFO, [ROUTER] + devices_later), vendors or {}, now=1300)
    return con, new


def test_one_alert_per_device():
    con, new = setup_network([Device("192.168.50.40", "00:00:5e:00:53:40")], {"00:00:5e:00:53:40": "Telly"})
    out = Outbox()
    assert notify.alert_new(con, new, sender=out) == 1
    assert out.sent == [("New device on your network", "Telly at 192.168.50.40")]
    assert notify.alert_new(con, new, sender=out) == 0  # already alerted
    assert len(out.sent) == 1


def test_baseline_never_alerts():
    con = db.connect()
    new = db.record_scan(con, ScanResult(INFO, [ROUTER, Device("192.168.50.40", "00:00:5e:00:53:40")]), {}, now=1000)
    out = Outbox()
    assert notify.alert_new(con, new, sender=out) == 0 and out.sent == []


def test_private_mac_flagged():
    con, new = setup_network([Device("192.168.50.41", "a2:00:00:00:00:41", "Galaxy-A55")],
                             {"a2:00:00:00:00:41": "Private MAC"})
    out = Outbox()
    notify.alert_new(con, new, sender=out)
    assert out.sent == [("New device on your network", "Galaxy-A55 (private MAC) at 192.168.50.41")]


def test_private_mac_unknown_name():
    con, new = setup_network([Device("192.168.50.42", "a2:00:00:00:00:42")], {"a2:00:00:00:00:42": "Private MAC"})
    out = Outbox()
    notify.alert_new(con, new, sender=out)
    assert out.sent == [("New device on your network", "Private MAC at 192.168.50.42")]


def test_rotated_private_mac_looks_like_labeled_device():
    con = db.connect()
    db.record_scan(con, ScanResult(INFO, [ROUTER, Device("192.168.50.21", "a2:00:00:00:00:21", "Sams-iPhone")]),
                   {}, now=1000)
    db.set_label(con, "a2:00:00:00:00:21", "Sam's iPhone")
    new = db.record_scan(con, ScanResult(INFO, [ROUTER, Device("192.168.50.33", "b6:00:00:00:00:33", "sams-iphone")]),
                         {}, now=1300)
    out = Outbox()
    notify.alert_new(con, new, sender=out)
    assert out.sent == [("Known device, new address", "Possibly Sam's iPhone with a new private address at 192.168.50.33.")]


def test_many_new_devices_one_notification():
    devs = [Device("192.168.50.%d" % (50 + i), "00:00:5e:00:53:%02x" % (0x50 + i)) for i in range(5)]
    con, new = setup_network(devs)
    out = Outbox()
    assert notify.alert_new(con, new, sender=out) == 5
    assert out.sent == [("5 new devices on your network", "Open the net-watch dashboard to see and label them.")]
    assert all(db.get(con, d.mac)["alerted"] for d in devs)


def test_send_passes_text_as_arguments(monkeypatch):
    """A hostname like `"; do shell script "…` must never become AppleScript code."""
    calls = []
    monkeypatch.setattr(notify.shutil, "which", lambda name: None)
    monkeypatch.setattr(notify.subprocess, "run", lambda cmd, **kw: calls.append(cmd))
    evil = 'x" & (do shell script "touch /tmp/pwned") & "'
    assert notify.send("New device", evil)
    cmd = calls[0]
    assert cmd[-1] == evil and all(evil not in part for part in cmd[:-1])


def test_terminal_notifier_used_when_installed(monkeypatch):
    calls = []
    monkeypatch.setattr(notify.shutil, "which", lambda name: "/opt/homebrew/bin/terminal-notifier")
    monkeypatch.setattr(notify.subprocess, "run", lambda cmd, **kw: calls.append(cmd))
    notify.send("T", "M", url="http://127.0.0.1:8765/", group="netwatch-x")
    assert calls[0][:5] == ["/opt/homebrew/bin/terminal-notifier", "-title", "T", "-message", "M"]
    assert "-open" in calls[0] and "-group" in calls[0]


def test_loop_scans_then_waits():
    runs, logs = [], []
    stop = threading.Event()
    w = serve.Worker()

    def fake_run():
        runs.append(1)
        w.status = {"state": "away", "message": "Not on your home network", "ts": 0}
        if len(runs) == 1:
            stop.set()

    w.run_once = fake_run
    w.loop(5, stop=stop, log=logs.append)
    assert runs == [1] and len(logs) == 1
