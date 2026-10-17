import ipaddress

import pytest

from netwatch import db
from netwatch.netinfo import NetInfo
from netwatch.scanner import Device, ScanResult

INFO = NetInfo("en0", "192.168.50.10", "ee:00:00:00:00:01", ipaddress.IPv4Network("192.168.50.0/24"),
               "192.168.50.1", "00:00:5e:00:53:01")
ROUTER = Device("192.168.50.1", "00:00:5e:00:53:01", is_gateway=True)
SELF = Device("192.168.50.10", "ee:00:00:00:00:01", "my-mac", is_self=True)
TV = Device("192.168.50.20", "00:00:5e:00:53:2a", "living-room-tv")
PHONE = Device("192.168.50.21", "a2:11:22:33:44:55")


@pytest.fixture
def con():
    return db.connect()


def scan(con, devices, now, vendors=None):
    return db.record_scan(con, ScanResult(INFO, list(devices)), vendors or {}, now=now)


def test_first_scan_is_baseline(con):
    assert scan(con, [ROUTER, SELF, TV], now=1000) == []
    assert all(d["alerted"] for d in db.devices(con))


def test_new_device_after_baseline(con):
    scan(con, [ROUTER, SELF], now=1000)
    assert scan(con, [ROUTER, SELF, PHONE], now=1300) == [PHONE.mac]
    assert scan(con, [ROUTER, SELF, PHONE], now=1600) == []  # only new once
    phone = db.get(con, PHONE.mac)
    assert phone["is_random_mac"] == 1 and phone["alerted"] == 0
    assert phone["first_seen"] == 1300 and phone["last_seen"] == 1600


def test_online_and_offline(con):
    scan(con, [ROUTER, SELF, TV], now=1000)
    scan(con, [ROUTER, SELF], now=1300)
    by_mac = {d["mac"]: d for d in db.devices(con)}
    assert by_mac[ROUTER.mac]["online"] and by_mac[ROUTER.mac]["is_gateway"]
    assert by_mac[SELF.mac]["is_self"]
    assert not by_mac[TV.mac]["online"]
    assert by_mac[TV.mac]["last_seen"] == 1000


def test_hostname_and_vendor_kept_when_missing_later(con):
    scan(con, [TV], now=1000, vendors={TV.mac: "Telly"})
    scan(con, [Device(TV.ip, TV.mac)], now=1300)
    tv = db.get(con, TV.mac)
    assert tv["hostname"] == "living-room-tv" and tv["vendor"] == "Telly"


def test_ip_change_tracked(con):
    scan(con, [TV], now=1000)
    scan(con, [Device("192.168.50.99", TV.mac)], now=1300)
    assert db.get(con, TV.mac)["last_ip"] == "192.168.50.99"


def test_label_and_type(con):
    scan(con, [TV], now=1000)
    assert db.set_label(con, TV.mac, "  Living room TV ", "tv")
    tv = db.get(con, TV.mac)
    assert (tv["label"], tv["type"]) == ("Living room TV", "tv")
    db.set_label(con, TV.mac, "", "")
    tv = db.get(con, TV.mac)
    assert (tv["label"], tv["type"]) == (None, None)
    with pytest.raises(ValueError):
        db.set_label(con, TV.mac, type_="toaster")
    assert not db.set_label(con, "00:00:5e:00:53:77", "nobody")


def test_forget_makes_it_new_again(con):
    scan(con, [ROUTER, TV], now=1000)
    assert db.forget(con, TV.mac)
    assert not db.forget(con, TV.mac)
    assert scan(con, [ROUTER, TV], now=1300) == [TV.mac]
    assert con.execute("SELECT COUNT(*) FROM sightings WHERE mac=?", (TV.mac,)).fetchone()[0] == 1


def test_prune_old_sightings(con):
    scan(con, [TV], now=1000)
    scan(con, [TV], now=1000 + 100 * 86400)
    db.prune(con, days=90, now=1000 + 100 * 86400)
    assert con.execute("SELECT COUNT(*) FROM sightings").fetchone()[0] == 1
    assert con.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 1
    assert db.get(con, TV.mac)["first_seen"] == 1000  # the device itself is kept


def test_db_lives_in_data_home(data_home, con):
    assert (data_home / "netwatch.db").exists()
