import argparse

import pytest

from netwatch import cli


def test_ago():
    assert cli.ago(5) == "5 s"
    assert cli.ago(125) == "2 min"
    assert cli.ago(3725) == "1 h"
    assert cli.ago(2 * 86400 + 5) == "2 d"


def test_mac_arg_accepts_common_spellings():
    assert cli.mac_arg("00-00-5E-00-53-2A") == "00:00:5e:00:53:2a"
    assert cli.mac_arg("0:0:5e:0:53:2a") == "00:00:5e:00:53:2a"
    with pytest.raises(argparse.ArgumentTypeError):
        cli.mac_arg("living-room-tv")


def test_table_alignment():
    out = cli.table([["192.168.50.1", "Router"], ["192.168.50.20", "TV"]], ["IP", "NAME"]).splitlines()
    assert out[0] == "IP             NAME"
    assert out[2] == "192.168.50.1   Router"


