"""install.sh / uninstall.sh against a fake $HOME, without touching launchctl."""

import os
import plistlib
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


def run(script, home, *args):
    env = dict(os.environ, HOME=str(home), NETWATCH_NO_LAUNCHCTL="1", NETWATCH_HOME=str(home / "nw"))
    return subprocess.run(["sh", str(REPO / script)] + list(args), env=env, capture_output=True, text=True)


def test_scripts_parse():
    for script in ("install.sh", "uninstall.sh", "bin/netwatch"):
        assert subprocess.run(["sh", "-n", str(REPO / script)]).returncode == 0


def test_install_command_only(tmp_path):
    p = run("install.sh", tmp_path)
    assert p.returncode == 0, p.stderr
    link = tmp_path / ".local/bin/netwatch"
    assert link.is_symlink() and Path(os.readlink(str(link))) == REPO / "bin/netwatch"
    assert not (tmp_path / "Library/LaunchAgents/com.netwatch.serve.plist").exists()


def test_install_agent(tmp_path):
    p = run("install.sh", tmp_path, "--agent", "--interval", "10")
    assert p.returncode == 0, p.stderr + p.stdout
    assert "won't scan" in p.stdout  # no home saved yet
    with open(str(tmp_path / "Library/LaunchAgents/com.netwatch.serve.plist"), "rb") as f:
        plist = plistlib.load(f)
    assert plist["Label"] == "com.netwatch.serve"
    assert plist["ProgramArguments"] == [str(REPO / "bin/netwatch"), "serve", "--interval", "10"]
    assert "--lan" not in plist["ProgramArguments"]  # the agent never exposes the dashboard to the LAN
    assert plist["RunAtLoad"] is True
    assert plist["EnvironmentVariables"]["NETWATCH_HOME"] == str(tmp_path / "nw")
    assert plist["StandardOutPath"].endswith("logs/serve.log")


@pytest.mark.parametrize("args", [["--interval", "abc"], ["--bogus"]])
def test_install_rejects_bad_options(tmp_path, args):
    assert run("install.sh", tmp_path, "--agent", *args).returncode != 0


def test_uninstall_keeps_data_unless_purge(tmp_path):
    run("install.sh", tmp_path, "--agent")
    (tmp_path / "nw" / "netwatch.db").write_text("x")
    p = run("uninstall.sh", tmp_path)
    assert p.returncode == 0
    assert not (tmp_path / ".local/bin/netwatch").exists()
    assert not (tmp_path / "Library/LaunchAgents/com.netwatch.serve.plist").exists()
    assert (tmp_path / "nw" / "netwatch.db").exists()
    run("uninstall.sh", tmp_path, "--purge")
    assert not (tmp_path / "nw").exists()
