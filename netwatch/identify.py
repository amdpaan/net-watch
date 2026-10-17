"""What is this device? A best guess at its type and a name to show, from what we know about it."""

import re

from . import oui

# (type, pattern on "hostname vendor"), first match wins
GUESSES = [
    ("phone", r"iphone|android|galaxy|pixel|redmi|oneplus|huawei|oppo|vivo|realme|nokia|motorola"),
    ("tv", r"\btv\b|-tv|tv-|appletv|apple-tv|chromecast|roku|bravia|firetv|fire-tv|webos|tizen|shield"),
    ("laptop", r"macbook|laptop|thinkpad|notebook|surface|zenbook|ideapad|xps|chromebook"),
    ("router", r"router|gateway|tp-?link|asus-?rt|netgear|ubiquiti|unifi|mikrotik|huawei.*hg|zte|fritz"),
]


def guess_type(device):
    """Type for a device dict (db row): what you set, else a guess, else 'other'."""
    if device.get("type"):
        return device["type"]
    if device.get("is_gateway"):
        return "router"
    if device.get("is_self"):
        return "laptop"
    text = " ".join(filter(None, [device.get("hostname"), device.get("vendor")])).lower()
    for type_, pattern in GUESSES:
        if re.search(pattern, text):
            return type_
    return "other"


def display_name(device):
    if device.get("label"):
        return device["label"]
    if device.get("hostname"):
        return device["hostname"]
    if device.get("is_self"):
        return "This Mac"
    if device.get("is_gateway"):
        return "Router"
    vendor = device.get("vendor")
    return vendor if vendor and vendor != oui.PRIVATE else "Unknown device"


def vendor_label(device):
    if device.get("is_random_mac"):
        return oui.PRIVATE
    return device.get("vendor") or "Unknown vendor"
