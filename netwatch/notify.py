"""New-device alerts as macOS notifications: terminal-notifier if installed (clickable, opens the dashboard),
otherwise osascript. At most one alert per device, ever."""

import shutil
import subprocess

from . import db, identify

GROUP_LIMIT = 3  # more new devices than this in one scan → one summary notification instead of many


def send(title, message, url=None, group=None):
    """Show a notification. Device names come from the network, so they're passed as arguments, never
    spliced into AppleScript source."""
    tn = shutil.which("terminal-notifier")
    try:
        if tn:
            cmd = [tn, "-title", title, "-message", message, "-sound", "default"]
            if url:
                cmd += ["-open", url]
            if group:
                cmd += ["-group", group]
            subprocess.run(cmd, capture_output=True, timeout=10)
        else:
            subprocess.run(["/usr/bin/osascript", "-e", "on run argv",
                            "-e", "display notification (item 2 of argv) with title (item 1 of argv)",
                            "-e", "end run", title, message], capture_output=True, timeout=10)
        return True
    except (OSError, subprocess.TimeoutExpired):
        return False


def look_alike(con, device):
    """A labeled device with the same hostname: probably the same phone with a new private address."""
    if not device["is_random_mac"] or not device["hostname"]:
        return None
    r = con.execute("SELECT label FROM devices WHERE hostname = ? COLLATE NOCASE AND mac != ? AND label IS NOT NULL "
                    "ORDER BY last_seen DESC LIMIT 1", (device["hostname"], device["mac"])).fetchone()
    return r[0] if r else None


def describe(con, device):
    """(title, message) for one new device."""
    where = " at %s" % device["last_ip"] if device["last_ip"] else ""
    twin = look_alike(con, device)
    if twin:
        return ("Known device, new address",
                "Possibly %s with a new private address%s." % (twin, where))
    name = device["hostname"] or identify.vendor_label(device)
    if device["is_random_mac"] and device["hostname"]:
        name += " (private MAC)"
    return "New device on your network", "%s%s" % (name, where)


def alert_new(con, macs, url=None, sender=send):
    """Notify about never-seen devices that haven't been alerted yet. Returns how many were alerted."""
    pending = [d for d in (db.get(con, m) for m in macs) if d and not d["alerted"]]
    if not pending:
        return 0
    if len(pending) > GROUP_LIMIT:
        sender("%d new devices on your network" % len(pending),
               "Open the net-watch dashboard to see and label them.", url, "netwatch-new")
    else:
        for d in pending:
            title, message = describe(con, d)
            sender(title, message, url, "netwatch-" + d["mac"])
    for d in pending:
        db.mark_alerted(con, d["mac"])
    return len(pending)
