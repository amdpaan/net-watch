"""Where everything lives. Nothing personal is ever written inside the repo."""

import os
from pathlib import Path


def support():
    """The data folder (override with NETWATCH_HOME). Read on every call so tests can point it elsewhere."""
    path = Path(os.environ.get("NETWATCH_HOME", Path.home() / "Library/Application Support/net-watch"))
    path.mkdir(parents=True, exist_ok=True)
    return path


def config():
    return support() / "config.json"


def db():
    return support() / "netwatch.db"


def oui_cache():
    return support() / "manuf"


def logs():
    path = support() / "logs"
    path.mkdir(exist_ok=True)
    return path
