"""MAC vendor lookup from Wireshark's `manuf` file (IEEE assignments), downloaded once and cached offline."""

import re
import urllib.request

from . import netinfo, paths

URL = "https://www.wireshark.org/download/automated/data/manuf"
PRIVATE = "Private MAC"
# Legal suffixes that only make the vendor column wider
SUFFIX_RE = re.compile(r"[,.]?\s+(inc|corp(oration)?|co|ltd|llc|gmbh|limited|s\.?a|ab|ag|b\.?v|"
                       r"co\.?,?\s*ltd)\.?$", re.I)

_table = None  # {nibble count: {hex prefix: vendor}}, loaded on first lookup


def parse(text):
    """manuf lines `00:1B:C5:00:10/36<TAB>Short<TAB>Long Name` → {nibbles: {prefix: name}} (24, 28, 36 bits)."""
    table = {6: {}, 7: {}, 9: {}}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("\t")]
        if len(parts) < 2:
            continue
        prefix, _, bits = parts[0].partition("/")
        nibbles = int(bits) // 4 if bits else 6
        if nibbles not in table:
            continue
        key = prefix.replace(":", "").replace("-", "").lower()[:nibbles]
        name = parts[2] if len(parts) > 2 and parts[2] else parts[1]
        table[nibbles][key] = name
    return table


def tidy(name):
    """'Apple, Inc.' → 'Apple', 'Samsung Electronics Co.,Ltd' → 'Samsung Electronics'."""
    for _ in range(3):
        shorter = SUFFIX_RE.sub("", name).strip(" ,.")
        if shorter == name or not shorter:
            break
        name = shorter
    return name


def load(path=None):
    global _table
    path = path or paths.oui_cache()
    try:
        _table = parse(path.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        _table = {6: {}, 7: {}, 9: {}}
    return _table


def have_cache():
    return paths.oui_cache().exists()


def download(url=URL, timeout=60):
    """Fetch the manuf file into the data folder (atomic). Returns the number of vendor prefixes."""
    req = urllib.request.Request(url, headers={"User-Agent": "net-watch"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read()
    table = parse(data.decode("utf-8", errors="replace"))
    count = sum(len(t) for t in table.values())
    if count < 1000:  # an error page or a truncated download: keep the old cache
        raise ValueError("The downloaded vendor list looks wrong (%d entries)." % count)
    tmp = paths.oui_cache().with_suffix(".tmp")
    tmp.write_bytes(data)
    tmp.replace(paths.oui_cache())
    load()
    return count


def vendor(mac):
    """Vendor name, 'Private MAC' for randomized addresses, or None if unknown."""
    if netinfo.is_private_mac(mac):
        return PRIVATE
    table = _table if _table is not None else load()
    hexmac = mac.replace(":", "").lower()
    for nibbles in (9, 7, 6):  # longest (most specific) assignment first
        name = table[nibbles].get(hexmac[:nibbles])
        if name:
            return tidy(name)
    return None
