"""One scan: safety lock → discover → identify → store."""

import ipaddress
import time
from dataclasses import dataclass, field
from typing import List, Optional

from . import db, discover, home, names, netinfo, oui


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
    new: List[str] = field(default_factory=list)  # MACs never seen before (filled by scan_and_store)
    baseline: bool = False                        # first scan ever: everything saved, nothing "new"
    duration: float = 0.0


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


def ensure_vendor_db(log=print):
    """Download the vendor list the first time. Scanning still works (without vendors) if that fails."""
    if oui.have_cache():
        return
    log("Downloading the MAC vendor list (Wireshark manuf, ~3 MB, once) ...")
    try:
        log("  %d vendor prefixes cached." % oui.download())
    except Exception as e:  # network down, site moved, ...: vendors just stay unknown
        log("  Couldn't download it (%s). Vendors stay unknown; retry with `netwatch update-oui`." % e)


def scan_and_store(info, use_nmap=False, con=None, log=print, **kw):
    """Scan, look up vendors, save to the database. Returns the ScanResult with `new` filled in."""
    check_lock(info)
    started = time.time()
    ensure_vendor_db(log)
    result = scan(info, use_nmap=use_nmap, **kw)
    result.duration = time.time() - started
    con = con or db.connect()
    result.baseline = db.get_meta(con, "baseline_ts") is None
    result.new = db.record_scan(con, result, {d.mac: oui.vendor(d.mac) for d in result.devices},
                                duration=result.duration)
    db.prune(con)
    return result
