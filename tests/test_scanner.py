import pytest

from conftest import fixture
from netwatch import home, netinfo, scanner


@pytest.fixture
def system(fake_system):
    return fake_system()


@pytest.fixture
def info(system):
    return netinfo.detect(system)


def no_names(ips):
    return {}


def test_refuses_without_home(info, system):
    pinged = []
    with pytest.raises(scanner.ScanRefused) as e:
        scanner.scan(info, pinger=lambda ip: pinged.append(ip) or (True, False), runner=system, resolve=no_names)
    assert e.value.verdict == home.NOT_SET
    assert pinged == []  # not a single packet before the lock passes


def test_refuses_away(info, system):
    home.save_home(info)
    info.gateway_mac = "00:00:5e:00:53:99"
    pinged = []
    with pytest.raises(scanner.ScanRefused):
        scanner.scan(info, pinger=lambda ip: pinged.append(ip) or (True, False), runner=system, resolve=no_names)
    assert pinged == []


def test_scan_home(info, system):
    home.save_home(info)
    pinged = []
    result = scanner.scan(info, pinger=lambda ip: pinged.append(ip) or (False, False), runner=system,
                          resolve=lambda ips: {"192.168.50.20": "living-room-tv"})
    assert len(pinged) == 253 and "192.168.50.10" not in pinged  # every host except this Mac
    assert [d.ip for d in result.devices] == ["192.168.50.1", "192.168.50.10", "192.168.50.20",
                                              "192.168.50.21", "192.168.50.30"]  # link-local dropped
    by_ip = {d.ip: d for d in result.devices}
    assert by_ip["192.168.50.1"].is_gateway
    assert by_ip["192.168.50.10"].is_self
    assert by_ip["192.168.50.20"].hostname == "living-room-tv"


def test_self_added_when_missing_from_arp(info, system):
    home.save_home(info)
    arp_without_self = "\n".join(l for l in fixture("arp_an.txt").splitlines() if "permanent" not in l)
    result = scanner.scan(info, pinger=lambda ip: (False, False), runner=lambda c, timeout=10: arp_without_self,
                          resolve=no_names)
    assert any(d.is_self and d.ip == "192.168.50.10" for d in result.devices)


def test_permission_problem(info, system):
    home.save_home(info)
    with pytest.raises(scanner.PermissionProblem):
        scanner.scan(info, pinger=lambda ip: (False, True), runner=lambda c, timeout=10: "", resolve=no_names)
