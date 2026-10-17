"""SQLite storage: devices you've seen, and a sighting per device per scan (for "online" and the timeline)."""

import sqlite3
import time

from . import paths
from .netinfo import is_private_mac

TYPES = ("phone", "laptop", "tv", "router", "other")
KEEP_DAYS = 90

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    mac           TEXT PRIMARY KEY,
    label         TEXT,
    type          TEXT,              -- set by you; NULL means "guess from vendor/hostname"
    vendor        TEXT,
    hostname      TEXT,
    is_random_mac INTEGER NOT NULL DEFAULT 0,
    first_seen    INTEGER NOT NULL,
    last_seen     INTEGER NOT NULL,
    last_ip       TEXT,
    alerted       INTEGER NOT NULL DEFAULT 0   -- 1 once we've notified (or it was in the baseline scan)
);
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY,
    ts          INTEGER NOT NULL,
    network     TEXT,
    self_mac    TEXT,
    gateway_mac TEXT,
    online      INTEGER NOT NULL,
    duration    REAL
);
CREATE TABLE IF NOT EXISTS sightings (
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    mac     TEXT NOT NULL,
    ip      TEXT,
    ts      INTEGER NOT NULL,
    PRIMARY KEY (scan_id, mac)
);
CREATE INDEX IF NOT EXISTS sightings_mac_ts ON sightings (mac, ts);
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


def connect(path=None):
    con = sqlite3.connect(str(path or paths.db()), timeout=10)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")  # the dashboard reads while the scanner writes
    con.execute("PRAGMA foreign_keys=ON")
    con.executescript(SCHEMA)
    return con


def is_first_scan(con):
    return con.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 0


def record_scan(con, result, vendors, duration=None, now=None):
    """Store one scan. `vendors` = {mac: vendor}. Returns the MACs never seen before (empty on the very first
    scan: that one is the baseline, marked as already alerted)."""
    now = int(now or time.time())
    info = result.info
    baseline = is_first_scan(con) and get_meta(con, "baseline_ts") is None
    with con:
        if baseline:
            con.execute("INSERT OR REPLACE INTO meta VALUES ('baseline_ts', ?)", (str(now),))
        cur = con.execute(
            "INSERT INTO scans (ts, network, self_mac, gateway_mac, online, duration) VALUES (?,?,?,?,?,?)",
            (now, str(info.network), info.mac, info.gateway_mac, len(result.devices), duration))
        scan_id = cur.lastrowid
        new = []
        for d in result.devices:
            known = con.execute("SELECT 1 FROM devices WHERE mac=?", (d.mac,)).fetchone()
            vendor = vendors.get(d.mac)
            if known:
                con.execute("UPDATE devices SET last_seen=?, last_ip=?, vendor=COALESCE(?, vendor), "
                            "hostname=COALESCE(?, hostname) WHERE mac=?",
                            (now, d.ip, vendor, d.hostname, d.mac))
            else:
                con.execute("INSERT INTO devices (mac, vendor, hostname, is_random_mac, first_seen, last_seen, "
                            "last_ip, alerted) VALUES (?,?,?,?,?,?,?,?)",
                            (d.mac, vendor, d.hostname, int(is_private_mac(d.mac)), now, now, d.ip,
                             int(baseline or d.is_self or d.is_gateway)))
                if not baseline:
                    new.append(d.mac)
            con.execute("INSERT INTO sightings (scan_id, mac, ip, ts) VALUES (?,?,?,?)",
                        (scan_id, d.mac, d.ip, now))
    return new


def prune(con, days=KEEP_DAYS, now=None):
    cutoff = int(now or time.time()) - days * 86400
    with con:
        con.execute("DELETE FROM sightings WHERE ts < ?", (cutoff,))
        con.execute("DELETE FROM scans WHERE ts < ?", (cutoff,))


def get_meta(con, key, default=None):
    r = con.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return r[0] if r else default


def set_meta(con, key, value):
    with con:
        con.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (key, str(value)))


def recent_new(con, hours=24, now=None):
    """Devices that joined (after the baseline) in the last `hours` and haven't been labeled or dismissed."""
    now = int(now or time.time())
    since = max(now - hours * 3600, int(get_meta(con, "baseline_ts", 0)) + 1,
                int(get_meta(con, "dismissed_before", 0)))
    return [dict(r) for r in con.execute(
        "SELECT * FROM devices WHERE first_seen >= ? AND label IS NULL ORDER BY first_seen DESC", (since,))]


def last_scan(con):
    return con.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1").fetchone()


def devices(con):
    """All devices, each with `online` (seen in the latest scan), newest first-seen last."""
    scan = last_scan(con)
    online = set()
    if scan:
        online = {r[0] for r in con.execute("SELECT mac FROM sightings WHERE scan_id=?", (scan["id"],))}
    rows = []
    for r in con.execute("SELECT * FROM devices ORDER BY first_seen, mac"):
        d = dict(r)
        d["online"] = d["mac"] in online
        d["is_self"] = bool(scan and d["mac"] == scan["self_mac"])
        d["is_gateway"] = bool(scan and d["mac"] == scan["gateway_mac"])
        rows.append(d)
    return rows


def get(con, mac):
    r = con.execute("SELECT * FROM devices WHERE mac=?", (mac,)).fetchone()
    return dict(r) if r else None


def set_label(con, mac, label=None, type_=None):
    """Update label and/or type ('' clears). Returns False if the device doesn't exist."""
    if type_ not in (None, "") and type_ not in TYPES:
        raise ValueError("type must be one of: " + ", ".join(TYPES))
    with con:
        cur = con.execute("SELECT 1 FROM devices WHERE mac=?", (mac,))
        if not cur.fetchone():
            return False
        if label is not None:
            con.execute("UPDATE devices SET label=? WHERE mac=?", (label.strip() or None, mac))
        if type_ is not None:
            con.execute("UPDATE devices SET type=? WHERE mac=?", (type_ or None, mac))
    return True


def forget(con, mac):
    """Delete a device and its history. It'll count as new (and alert) if it shows up again."""
    with con:
        con.execute("DELETE FROM sightings WHERE mac=?", (mac,))
        return con.execute("DELETE FROM devices WHERE mac=?", (mac,)).rowcount > 0


def mark_alerted(con, mac):
    with con:
        con.execute("UPDATE devices SET alerted=1 WHERE mac=?", (mac,))
