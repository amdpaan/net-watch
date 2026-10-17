"""Shared fixtures. Tests never touch the real network or the real data folder."""

from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


def fixture(name):
    return (FIXTURES / name).read_text()


@pytest.fixture(autouse=True)
def data_home(tmp_path, monkeypatch):
    """Every test gets an empty NETWATCH_HOME."""
    monkeypatch.setenv("NETWATCH_HOME", str(tmp_path / "data"))
    return tmp_path / "data"


class FakeSystem:
    """Answers the commands netinfo/discover run, from fixture files."""

    def __init__(self, route="route_default.txt", ifconfig="ifconfig_en0.txt", arp="arp_an.txt"):
        self.files = {"route": route, "ifconfig": ifconfig, "arp": arp}
        self.calls = []

    def __call__(self, cmd, timeout=10):
        self.calls.append(cmd)
        name = cmd[0].rsplit("/", 1)[-1]
        if name == "arp" and not self.files["arp"]:
            return ""
        if name == "arp" and cmd[1] == "-n":  # `arp -n <ip>`: just that entry
            return "\n".join(l for l in fixture(self.files["arp"]).splitlines() if "(%s)" % cmd[2] in l)
        if name in self.files and self.files[name]:
            return fixture(self.files[name])
        return ""


@pytest.fixture
def fake_system():
    return FakeSystem
