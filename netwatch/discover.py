"""Find devices without sudo: ping every address so the ARP cache fills up, then read `arp -an`."""

import ipaddress
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor

from . import netinfo

WORKERS = 64


def ping(ip):
    """One echo request, ~1 s max. Returns (answered, denied); denied = macOS blocked us (Local Network)."""
    try:
        p = subprocess.run(["/sbin/ping", "-c1", "-W", "800", "-t", "1", "-q", ip],
                           capture_output=True, text=True, timeout=3)
    except (OSError, subprocess.TimeoutExpired):
        return False, False
    return p.returncode == 0, "No route to host" in p.stderr or "not permitted" in p.stderr


def sweep(network, skip=(), pinger=ping):
    """Ping every host address in parallel. Returns (answered_ips, denied_count)."""
    hosts = [str(ip) for ip in network.hosts() if str(ip) not in skip]
    with ThreadPoolExecutor(WORKERS) as pool:
        results = list(pool.map(pinger, hosts))
    answered = {ip for ip, (ok, _) in zip(hosts, results) if ok}
    return answered, sum(1 for _, denied in results if denied)


def nmap_available():
    return shutil.which("nmap") is not None


def nmap_sweep(network, runner=netinfo.run):
    """Optional extra: an unprivileged `nmap -sn` also fills the ARP cache (TCP connect probes on 80/443)."""
    runner(["nmap", "-sn", "-n", "-T4", str(network)], timeout=120)


def arp_entries(info, runner=netinfo.run):
    """Resolved ARP entries on this interface inside this subnet."""
    return [e for e in netinfo.parse_arp(runner(["/usr/sbin/arp", "-an"]), info.interface)
            if ipaddress.IPv4Address(e.ip) in info.network
            and e.ip not in (str(info.network.broadcast_address), str(info.network.network_address))]
