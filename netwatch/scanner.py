"""One scan: safety lock → discover → identify. Storing results comes in M2."""

import ipaddress
from dataclasses import dataclass
from typing import List, Optional

from . import discover, home, names, netinfo


class ScanRefused(Exception):
    """Not allowed to scan here (not home, too big, ...). `verdict` is one of home.AWAY/NOT_SET/REFUSED."""

    def __init__(self, verdict, message):
        super().__init__(message)
        self.verdict = verdict


class PermissionProblem(Exception):
    pass


@dataclass
class Device:
    ip: str
    mac: str
    hostname: Optional[str] = None
    is_self: bool = False
    is_gateway: bool = False


@dataclass
class ScanResult:
    info: netinfo.NetInfo
    devices: List[Device]


PERMISSION_HINT = (
    "macOS blocked the pings. Allow Local Network access for the app running net-watch\n"
    "(Terminal, iTerm, python3, ...) in System Settings → Privacy & Security → Local Network, then try again.")


def check_lock(info):
    verdict, message = home.check(info)
    if verdict != home.HOME:
        raise ScanRefused(verdict, message)


def scan(info, use_nmap=False, pinger=discover.ping, runner=netinfo.run, resolve=names.reverse_dns):
    """Scan the (already lock-checked) home network once."""
    check_lock(info)  # checked again here so no caller can skip it
    answered, denied = discover.sweep(info.network, skip={info.ip}, pinger=pinger)
    if use_nmap and discover.nmap_available():
        discover.nmap_sweep(info.network, runner)
    entries = discover.arp_entries(info, runner)
    if denied and not answered and len(entries) <= 1:
        raise PermissionProblem(PERMISSION_HINT)

    by_mac = {}
    for e in entries:
        by_mac.setdefault(e.mac, Device(e.ip, e.mac, is_self=e.permanent))
    if info.mac and info.mac not in by_mac:
        by_mac[info.mac] = Device(info.ip, info.mac, is_self=True)
    for d in by_mac.values():
        d.is_self = d.is_self or d.mac == info.mac
        d.is_gateway = d.ip == info.gateway_ip
    devices = sorted(by_mac.values(), key=lambda d: ipaddress.IPv4Address(d.ip))
    for ip, name in resolve([d.ip for d in devices]).items():
        for d in devices:
            if d.ip == ip:
                d.hostname = name
    return ScanResult(info, devices)
