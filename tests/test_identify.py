import pytest

from netwatch import identify


@pytest.mark.parametrize("device, type_", [
    ({"hostname": "Sams-iPhone"}, "phone"),
    ({"hostname": "Galaxy-S24"}, "phone"),
    ({"hostname": "living-room-tv"}, "tv"),
    ({"vendor": "Roku"}, "tv"),
    ({"hostname": "Work-MacBook-Air"}, "laptop"),
    ({"vendor": "TP-Link Systems"}, "router"),
    ({"is_gateway": True, "vendor": "Fruitco"}, "router"),
    ({"is_self": True}, "laptop"),
    ({"vendor": "Fruitco"}, "other"),
    ({"type": "tv", "hostname": "Sams-iPhone"}, "tv"),  # yours wins
])
def test_guess_type(device, type_):
    assert identify.guess_type(device) == type_


def test_display_name_order():
    d = {"vendor": "Telly", "is_random_mac": 0}
    assert identify.display_name(d) == "Telly"
    d["hostname"] = "living-room-tv"
    assert identify.display_name(d) == "living-room-tv"
    d["label"] = "TV"
    assert identify.display_name(d) == "TV"
    assert identify.display_name({"vendor": None}) == "Unknown device"
    assert identify.display_name({"vendor": "Private MAC", "is_random_mac": 1}) == "Unknown device"


def test_vendor_label():
    assert identify.vendor_label({"vendor": None, "is_random_mac": 1}) == "Private MAC"
    assert identify.vendor_label({"vendor": None, "is_random_mac": 0}) == "Unknown vendor"
