"""Which network are we on? Parses route, ifconfig and arp output (macOS formats)."""

import ipaddress
import re
import subprocess
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

MAC_RE = re.compile(r"^[0-9a-f]{1,2}(:[0-9a-f]{1,2}){5}$", re.I)
ARP_RE = re.compile(r"\((?P<ip>[\d.]+)\) at (?P<mac>\S+) on (?P<iface>\S+)(?P<rest>.*)")


def run(cmd, timeout=10):
    """Run a command and return stdout ("" if it failed). The one place that touches the real system."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


Runner = Callable[[List[str]], str]


def normalize_mac(mac):
    """'0:1a:2b:3:4:5' (arp drops leading zeros) → '00:1a:2b:03:04:05'. None if it isn't a MAC."""
    if not mac or not MAC_RE.match(mac):
        return None
    return ":".join(part.zfill(2) for part in mac.lower().split(":"))


def is_private_mac(mac):
    """Locally administered bit set: a randomized "Private Wi-Fi Address" rather than a vendor's."""
    return bool(int(mac.split(":")[0], 16) & 0x02)


def is_multicast_mac(mac):
    return bool(int(mac.split(":")[0], 16) & 0x01)


def parse_route(text):
    """`route -n get default` → {'gateway': '192.168.1.1', 'interface': 'en0'}."""
    out = {}
    for line in text.splitlines():
        key, _, value = line.strip().partition(":")
        if key in ("gateway", "interface") and value.strip():
            out[key] = value.strip()
    return out


def parse_ifconfig(text):
    """`ifconfig en0` → {'mac', 'ip', 'prefix', 'active'} (first IPv4 address only)."""
    out = {"active": "status: active" in text}
    m = re.search(r"^\s*ether (\S+)", text, re.M)
    if m:
        out["mac"] = normalize_mac(m.group(1))
    m = re.search(r"^\s*inet (\d+\.\d+\.\d+\.\d+) netmask (0x[0-9a-f]+|[\d.]+)", text, re.M)
    if m:
        out["ip"] = m.group(1)
        mask = m.group(2)
        if mask.startswith("0x"):
            mask = str(ipaddress.IPv4Address(int(mask, 16)))
        out["prefix"] = ipaddress.IPv4Network("0.0.0.0/" + mask).prefixlen
    return out


@dataclass
class ArpEntry:
    ip: str
    mac: str
    interface: str
    permanent: bool  # macOS lists this Mac's own address as "permanent"


def parse_arp(text, interface=None):
    """`arp -an` → resolved unicast entries (no "(incomplete)", broadcast or multicast)."""
    entries = []
    for line in text.splitlines():
        m = ARP_RE.search(line)
        if not m:
            continue
        mac = normalize_mac(m.group("mac"))
        if mac is None or is_multicast_mac(mac):  # also catches ff:ff:ff:ff:ff:ff
            continue
        if interface and m.group("iface") != interface:
            continue
        ip = ipaddress.IPv4Address(m.group("ip"))
        if ip.is_multicast:
            continue
        entries.append(ArpEntry(str(ip), mac, m.group("iface"), "permanent" in m.group("rest")))
    return entries


@dataclass
class NetInfo:
    interface: str
    ip: str
    mac: Optional[str]
    network: ipaddress.IPv4Network
    gateway_ip: str
    gateway_mac: Optional[str]

    @property
    def prefix(self):
        return self.network.prefixlen


class NoNetwork(Exception):
    pass


def gateway_mac(gateway_ip, interface, runner: Runner = run):
    """The router's MAC from the ARP cache, pinging it once first if it isn't there yet."""
    for attempt in range(2):
        for entry in parse_arp(runner(["/usr/sbin/arp", "-n", gateway_ip]), interface):
            if entry.ip == gateway_ip:
                return entry.mac
        if attempt == 0:
            runner(["/sbin/ping", "-c1", "-t1", gateway_ip])
    return None


def detect(runner: Runner = run):
    """Interface, IP, subnet and gateway (IP + MAC) of the default route."""
    route = parse_route(runner(["/sbin/route", "-n", "get", "default"]))
    if "interface" not in route or "gateway" not in route:
        raise NoNetwork("No default route: not connected to a network.")
    iface = route["interface"]
    try:
        ipaddress.IPv4Address(route["gateway"])
    except ValueError:
        # e.g. a VPN whose default route points at an interface ("link#12") instead of a router
        raise NoNetwork("The default route goes through %s without an IPv4 gateway (VPN?)." % iface)
    info: Dict = parse_ifconfig(runner(["/sbin/ifconfig", iface]))
    if "ip" not in info:
        # ifconfig output can lag right after joining; ipconfig asks the DHCP client directly
        ip = runner(["/usr/sbin/ipconfig", "getifaddr", iface]).strip()
        if not ip:
            raise NoNetwork("%s has no IPv4 address." % iface)
        mask = runner(["/usr/sbin/ipconfig", "getoption", iface, "subnet_mask"]).strip()
        try:
            prefix = ipaddress.IPv4Network("0.0.0.0/" + mask).prefixlen
        except ValueError:
            raise NoNetwork("Couldn't read the subnet mask of %s." % iface)
        info["ip"], info["prefix"] = ip, prefix
    network = ipaddress.IPv4Interface("%s/%d" % (info["ip"], info["prefix"])).network
    return NetInfo(iface, info["ip"], info.get("mac"), network, route["gateway"],
                   gateway_mac(route["gateway"], iface, runner))
