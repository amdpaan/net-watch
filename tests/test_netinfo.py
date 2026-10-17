import ipaddress

import pytest

from conftest import fixture
from netwatch import netinfo


def test_parse_route():
    assert netinfo.parse_route(fixture("route_default.txt")) == {"gateway": "192.168.50.1", "interface": "en0"}
    assert netinfo.parse_route(fixture("route_none.txt")) == {}


def test_parse_ifconfig_hex_netmask():
    info = netinfo.parse_ifconfig(fixture("ifconfig_en0.txt"))
    assert info == {"active": True, "mac": "ee:00:00:00:00:01", "ip": "192.168.50.10", "prefix": 24}
    assert netinfo.parse_ifconfig(fixture("ifconfig_campus.txt"))["prefix"] == 20


@pytest.mark.parametrize("raw, norm", [
    ("0:0:5e:0:53:1", "00:00:5e:00:53:01"),
    ("A2:11:22:33:44:55", "a2:11:22:33:44:55"),
    ("(incomplete)", None),
    ("00:11:22:33:44", None),
])
def test_normalize_mac(raw, norm):
    assert netinfo.normalize_mac(raw) == norm


def test_private_mac_bit():
    assert netinfo.is_private_mac("a2:11:22:33:44:55")
    assert netinfo.is_private_mac("ee:00:00:00:00:01")
    assert not netinfo.is_private_mac("00:00:5e:00:53:01")


def test_parse_arp_filters_junk():
    entries = netinfo.parse_arp(fixture("arp_an.txt"), "en0")
    ips = [e.ip for e in entries]
    # no incomplete, broadcast, multicast, or other-interface entries
    assert ips == ["192.168.50.1", "192.168.50.10", "192.168.50.20", "192.168.50.21", "192.168.50.30",
                   "169.254.12.34"]
    assert [e.ip for e in entries if e.permanent] == ["192.168.50.10"]
    assert entries[0].mac == "00:00:5e:00:53:01"


def test_detect(fake_system):
    info = netinfo.detect(fake_system())
    assert info.interface == "en0"
    assert info.ip == "192.168.50.10"
    assert info.network == ipaddress.IPv4Network("192.168.50.0/24")
    assert info.gateway_ip == "192.168.50.1"
    assert info.gateway_mac == "00:00:5e:00:53:01"
    assert info.mac == "ee:00:00:00:00:01"


def test_detect_pings_gateway_when_not_cached(fake_system):
    system = fake_system(arp=None)
    info = netinfo.detect(system)
    assert info.gateway_mac is None
    assert ["/sbin/ping", "-c1", "-t1", "192.168.50.1"] in system.calls


@pytest.mark.parametrize("route", ["route_none.txt", "route_vpn.txt"])
def test_detect_no_usable_route(fake_system, route):
    with pytest.raises(netinfo.NoNetwork):
        netinfo.detect(fake_system(route=route))
