import ipaddress

import pytest

from netwatch import home
from netwatch.netinfo import NetInfo


def net(subnet="192.168.50.0/24", gw_mac="00:00:5e:00:53:01"):
    network = ipaddress.IPv4Network(subnet)
    return NetInfo("en0", str(network.network_address + 10), "ee:00:00:00:00:01", network,
                   str(network.network_address + 1), gw_mac)


def test_first_run_is_not_set_and_never_home():
    assert home.check(net())[0] == home.NOT_SET


def test_confirm_saves_home():
    assert home.confirm(net(), ask=lambda _: "y")
    assert home.check(net())[0] == home.HOME
    assert home.load_config()["home"]["gateway_mac"] == "00:00:5e:00:53:01"


@pytest.mark.parametrize("answer", ["", "n", "no", "maybe"])
def test_confirm_declined_saves_nothing(answer):
    assert not home.confirm(net(), ask=lambda _: answer)
    assert home.check(net())[0] == home.NOT_SET


def test_confirm_without_terminal_input():
    def eof(_):
        raise EOFError
    assert not home.confirm(net(), ask=eof)


def test_other_router_is_away():
    home.save_home(net())
    verdict, message = home.check(net(gw_mac="00:00:5e:00:53:99"))
    assert verdict == home.AWAY
    assert "Not on your home network" in message


def test_same_subnet_different_router_is_away():
    """A café using the same 192.168.50.0/24 isn't home: only the router MAC counts."""
    home.save_home(net())
    assert home.check(net(gw_mac="00:00:5e:00:53:02"))[0] == home.AWAY


@pytest.mark.parametrize("subnet", ["10.0.0.0/16", "172.16.0.0/20", "192.168.0.0/23"])
def test_bigger_than_slash_24_refused_even_if_home(subnet):
    cfg = home.save_home(net())
    verdict, message = home.check(net(subnet), cfg)
    assert verdict == home.REFUSED
    assert "larger than a /24" in message


@pytest.mark.parametrize("subnet", ["203.0.113.0/24", "100.64.1.0/24", "169.254.1.0/24"])
def test_non_rfc1918_subnet_refused(subnet):
    assert home.check(net(subnet))[0] == home.REFUSED


def test_unknown_router_mac_refused():
    assert home.check(net(gw_mac=None))[0] == home.REFUSED


def test_smaller_subnet_ok():
    home.save_home(net("192.168.50.0/26"))
    assert home.check(net("192.168.50.0/26"))[0] == home.HOME
