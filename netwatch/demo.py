"""`netwatch demo`: a made-up home network with a week of history, for screenshots and trying the dashboard.
Lives in <data>/demo/ and never scans anything."""

import ipaddress
import os
import random
import time

from . import db, home, paths
from .netinfo import NetInfo
from .scanner import Device, ScanResult

NETWORK = ipaddress.IPv4Network("192.168.50.0/24")
GATEWAY = "00:00:5e:00:53:01"
SELF = "ee:00:00:00:00:01"

# mac, ip, label, type, vendor, hostname, schedule
DEVICES = [
    (GATEWAY, ".1", None, None, "Example Router Co", None, "always"),
    (SELF, ".10", None, None, "Private MAC", "studio-macbook", "always"),
    ("a2:00:00:00:00:21", ".21", "My iPhone", "phone", "Private MAC", "Sams-iPhone", "awake"),
    ("00:00:5e:00:53:22", ".22", "Living room TV", "tv", "Telly Electronics", "living-room-tv", "evening"),
    ("00:00:5e:00:53:23", ".23", "Mum's iPad", "other", "Fruitco", None, "evening"),
    ("00:00:5e:00:53:24", ".24", "Printer", "other", "Inkjet Works", "office-printer", "always"),
    ("06:00:00:00:00:25", ".25", None, None, "Private MAC", "Galaxy-A55", "awake"),
    ("00:00:5e:00:53:26", ".26", "Work laptop", "laptop", "Example PC Maker", "WORK-LT-0042", "workday"),
    ("00:00:5e:00:53:27", ".27", None, None, "Smart Plug Ltd", None, "always"),
    ("00:00:5e:00:53:28", ".28", "Speaker", "other", "Fruitco", "kitchen-speaker", "awake"),
    ("00:00:5e:00:53:29", ".29", None, None, "Unknown vendor", None, "rare"),
]
NEWCOMER = ("da:00:00:00:00:31", ".31", None, None, "Private MAC", None, "new")


def online(schedule, ts, rnd):
    t = time.localtime(ts)
    h, weekday = t.tm_hour + t.tm_min / 60, t.tm_wday < 5
    if schedule == "always":
        return True
    if schedule == "awake":
        return 7 <= h < 23.5 and rnd.random() > 0.08
    if schedule == "evening":
        return 18 <= h < 23 and rnd.random() > 0.1
    if schedule == "workday":
        return weekday and 9 <= h < 18 and rnd.random() > 0.05
    if schedule == "rare":
        return rnd.random() < 0.03
    return False


def build(days=7, step=15 * 60, now=None):
    """Write the demo database and config into the current NETWATCH_HOME."""
    rnd = random.Random(42)
    now = int(now or time.time())
    for name in ("netwatch.db", "netwatch.db-wal", "netwatch.db-shm"):
        try:
            os.remove(str(paths.support() / name))
        except FileNotFoundError:
            pass
    info = NetInfo("en0", "192.168.50.10", SELF, NETWORK, "192.168.50.1", GATEWAY)
    home.save_home(info)
    con = db.connect()
    vendors = {d[0]: (None if d[4] in ("Unknown vendor",) else d[4]) for d in DEVICES + [NEWCOMER]}
    start = now - days * 86400
    start -= start % step
    ts = start
    while ts <= now:
        devs = [Device("192.168.50" + d[1], d[0], d[5], is_self=d[0] == SELF, is_gateway=d[0] == GATEWAY)
                for d in DEVICES if online(d[6], ts, rnd)]
        if now - ts < 40 * 60:  # someone's phone joined ~40 minutes ago
            devs.append(Device("192.168.50" + NEWCOMER[1], NEWCOMER[0]))
        db.record_scan(con, ScanResult(info, devs), vendors, duration=3.2, now=ts)
        ts += step
    for mac, _, label, type_, *_ in DEVICES:
        if label or type_:
            db.set_label(con, mac, label, type_)
    db.add_expected(con, "a2:00:00:00:00:41", "Grandma's tablet", "other", now=now - 3 * 86400)
    return con


def demo_home():
    """<real data folder>/demo, so demo data never mixes with yours."""
    return paths.support() / "demo"


class DemoWorker:
    """Stands in for the scanner in demo mode: nothing is ever sent on the network."""

    scanning = False
    status = {"state": "ok", "message": "Demo data.", "ts": None}

    def start(self):
        return False

    def run_once(self):
        return None
