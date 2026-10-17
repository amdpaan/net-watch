"""Hostnames. socket.gethostbyaddr goes through mDNSResponder, so it answers from both the router's DNS and
Bonjour (.local) PTR records."""

import re
import socket
from concurrent.futures import ThreadPoolExecutor, wait


def _lookup(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return None


def clean(name):
    if not name:
        return None
    name = name.rstrip(".")
    for suffix in (".local", ".lan", ".home", ".localdomain"):
        if name.lower().endswith(suffix):
            name = name[: -len(suffix)]
    # A PTR that only spells out the address ("192-168-1-20" or the IP itself) tells us nothing
    if re.fullmatch(r"(ip-)?\d+[-.]\d+[-.]\d+[-.]\d+", name, re.I):
        return None
    return name or None


def reverse_dns(ips, timeout=3.0):
    """{ip: hostname} for the addresses that have one. Lookups have no timeout of their own, so give up on
    the slow ones after `timeout` seconds (the threads finish in the background)."""
    pool = ThreadPoolExecutor(32)
    futures = {pool.submit(_lookup, ip): ip for ip in ips}
    done, _ = wait(futures, timeout=timeout)
    pool.shutdown(wait=False)
    out = {}
    for f in done:
        name = clean(f.result())
        if name:
            out[futures[f]] = name
    return out
