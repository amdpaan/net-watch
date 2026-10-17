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


def test_timeline_buckets(con):
    import time as _t
    t = _t.localtime()
    noon = int(_t.mktime((t.tm_year, t.tm_mon, t.tm_mday - 1, 12, 0, 0, 0, 0, -1)))  # yesterday 12:00
    now = noon + 86400 - 60  # today 11:59
    scan(con, [ROUTER, TV], now=noon)
    scan(con, [ROUTER], now=noon + 600)      # same hour: TV in 1 of 2 scans
    scan(con, [ROUTER, TV], now=noon + 3600)  # 13:00: seen
    tl = db.timeline(con, TV.mac, now=now)
    assert len(tl["days"]) == 7
    yesterday = tl["days"][-2]["hours"]
    assert yesterday[12] == 0.5 and yesterday[13] == 1.0 and yesterday[14] is None
    assert tl["online_pct"] == pytest.approx(66.7)
    assert tl["now_hour"] == 11
    assert db.timeline(con, "00:00:5e:00:53:77", now=now)["online_pct"] == 0.0


def test_summary_counts(con):
    scan(con, [ROUTER, SELF], now=1000)
    scan(con, [ROUTER, SELF, TV], now=1300)
    db.set_label(con, ROUTER.mac, "Router")
    s = db.summary(con, on_home_network=True, now=1400)
    assert {k: s[k] for k in ("online", "known", "unknown", "new_today", "on_home_network")} == \
        {"online": 3, "known": 1, "unknown": 2, "new_today": 1, "on_home_network": True}


MUM = Device("192.168.50.40", "a2:00:00:00:00:40")


def test_prenamed_device_joins_silently(con):
    scan(con, [ROUTER, SELF], now=1000)  # baseline
    assert db.add_expected(con, MUM.mac, "Mum's phone", "phone", now=1100) == "expected"
    assert [e["label"] for e in db.expected(con)] == ["Mum's phone"]
    assert scan(con, [ROUTER, SELF, MUM], now=1300) == []  # not "new": no alert, no NEW marker
    mum = db.get(con, MUM.mac)
    assert (mum["label"], mum["type"], mum["alerted"]) == ("Mum's phone", "phone", 1)
    assert db.expected(con) == []  # off the waiting list
    assert db.recent_new(con, now=1400) == []  # and not in the banner


def test_prenamed_before_the_baseline(con):
    db.add_expected(con, MUM.mac, "Mum's phone", now=900)
    assert scan(con, [ROUTER, MUM], now=1000) == []
    assert db.get(con, MUM.mac)["label"] == "Mum's phone"


def test_other_new_devices_still_alert(con):
    scan(con, [ROUTER], now=1000)
    db.add_expected(con, MUM.mac, "Mum's phone")
    assert scan(con, [ROUTER, MUM, TV], now=1300) == [TV.mac]


def test_add_expected_for_a_device_already_seen_just_names_it(con):
    scan(con, [ROUTER, TV], now=1000)
    db.set_label(con, TV.mac, type_="tv")
    assert db.add_expected(con, TV.mac, "Living room TV") == "labeled"
    tv = db.get(con, TV.mac)
    assert (tv["label"], tv["type"]) == ("Living room TV", "tv")  # type kept
    assert db.expected(con) == []


@pytest.mark.parametrize("mac, label, type_", [
    ("a2:00:00:00:00:40", "", None),
    ("a2:00:00:00:00:40", "x" * 61, None),
    ("a2:00:00:00:00:40", "Mum", "toaster"),
    ("01:00:5e:00:00:fb", "Multicast", None),
    ("ff:ff:ff:ff:ff:ff", "Broadcast", None),
    ("00:00:00:00:00:00", "Zero", None),
])
def test_add_expected_validation(con, mac, label, type_):
    with pytest.raises(ValueError):
        db.add_expected(con, mac, label, type_)
    assert db.expected(con) == []


def test_forget_removes_a_waiting_device(con):
    scan(con, [ROUTER], now=1000)
    db.add_expected(con, MUM.mac, "Mum's phone")
    assert db.forget(con, MUM.mac)
    assert db.expected(con) == []
    assert scan(con, [ROUTER, MUM], now=1300) == [MUM.mac]  # unknown again → alerts
