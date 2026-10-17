"""The safety lock: only ever scan the network whose router MAC you confirmed as home."""

import ipaddress
import json
import time

from . import paths

MAX_HOSTS_PREFIX = 24  # never sweep anything bigger than a /24
# Home LANs use these. ipaddress's is_private also allows documentation, CGNAT-adjacent and other ranges.
RFC1918 = [ipaddress.IPv4Network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]

# check() verdicts
HOME = "home"
AWAY = "away"
NOT_SET = "not_set"
REFUSED = "refused"


def load_config():
    try:
        return json.loads(paths.config().read_text())
    except (OSError, ValueError):
        return {}


def save_config(cfg):
    path = paths.config()
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(cfg, indent=2) + "\n")
    tmp.replace(path)


def check(info, cfg=None):
    """(verdict, message) for this network. Only HOME may be scanned."""
    cfg = load_config() if cfg is None else cfg
    if info.prefix < MAX_HOSTS_PREFIX:
        return REFUSED, ("Subnet %s is larger than a /%d (%d addresses). net-watch only scans small home "
                         "networks." % (info.network, MAX_HOSTS_PREFIX, info.network.num_addresses))
    if not any(info.network.subnet_of(n) for n in RFC1918):
        return REFUSED, "Subnet %s isn't a private (RFC 1918) range. Not scanning." % info.network
    if not info.gateway_mac:
        return REFUSED, ("Couldn't read the router's MAC address (%s), so I can't tell whether this is your "
                         "home network. Not scanning." % info.gateway_ip)
    home = cfg.get("home")
    if not home:
        return NOT_SET, "No home network saved yet."
    if home.get("gateway_mac") != info.gateway_mac:
        return AWAY, ("Not on your home network (router %s isn't your home router). Not scanning."
                      % info.gateway_ip)
    return HOME, "On your home network (%s)." % info.network


def describe(info):
    return ("  Interface  %s\n  This Mac   %s\n  Subnet     %s\n  Router     %s (%s)"
            % (info.interface, info.ip, info.network, info.gateway_ip, info.gateway_mac))


def save_home(info, cfg=None):
    cfg = load_config() if cfg is None else cfg
    cfg["home"] = {"gateway_mac": info.gateway_mac, "gateway_ip": info.gateway_ip,
                   "subnet": str(info.network), "saved_at": int(time.time())}
    save_config(cfg)
    return cfg


def confirm(info, ask=input):
    """First run: ask whether the current network is home. True if saved."""
    print("net-watch only scans your home network. Current network:\n" + describe(info))
    try:
        answer = ask("Is this your home network? Save it as home [y/N] ").strip().lower()
    except EOFError:
        print()
        answer = ""
    if answer not in ("y", "yes"):
        print("Not saved. Nothing scanned.")
        return False
    save_home(info)
    print("Saved as home.")
    return True
