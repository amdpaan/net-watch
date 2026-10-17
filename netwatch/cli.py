"""netwatch command line."""

import argparse
import sys
import time

from . import __version__, db, home, identify, netinfo, oui, scanner


def table(rows, headers):
    """Plain aligned columns; the last column isn't padded."""
    rows = [["" if c is None else str(c) for c in r] for r in rows]
    widths = [max([len(h)] + [len(r[i]) for r in rows]) for i, h in enumerate(headers)]
    fmt = lambda r: ("  ".join(c.ljust(w) for c, w in zip(r[:-1], widths)) + "  " + r[-1]).rstrip()
    return "\n".join([fmt(headers), fmt(["-" * w for w in widths])] + [fmt(r) for r in rows])


def ago(seconds):
    """3725 → '1 h', 90000 → '1 d'."""
    seconds = max(0, int(seconds))
    for unit, size in (("d", 86400), ("h", 3600), ("min", 60)):
        if seconds >= size:
            return "%d %s" % (seconds // size, unit)
    return "%d s" % seconds


def when(ts):
    return time.strftime("%d %b %H:%M", time.localtime(ts))


def mac_arg(text):
    mac = netinfo.normalize_mac(text.strip().replace("-", ":"))
    if not mac:
        raise argparse.ArgumentTypeError("not a MAC address: %r" % text)
    return mac


def detect_or_exit():
    try:
        return netinfo.detect()
    except netinfo.NoNetwork as e:
        sys.exit("net-watch: %s" % e)


def ensure_home(info, interactive):
    """Apply the safety lock. Returns True if this is home; otherwise explains and returns False."""
    verdict, message = home.check(info)
    if verdict == home.NOT_SET and interactive:
        return home.confirm(info)
    if verdict == home.NOT_SET:
        print("No home network saved yet. Run `netwatch home` in a terminal to confirm this one.")
    elif verdict != home.HOME:
        print(message)
    return verdict == home.HOME


def cmd_scan(args):
    info = detect_or_exit()
    if not ensure_home(info, sys.stdin.isatty()):
        return 0 if home.check(info)[0] in (home.AWAY, home.NOT_SET) else 2
    print("Scanning %s on %s ..." % (info.network, info.interface), flush=True)
    try:
        result = scanner.scan_and_store(info, use_nmap=args.nmap)
    except scanner.PermissionProblem as e:
        print(e, file=sys.stderr)
        return 1
    con = db.connect()
    stored = {d["mac"]: d for d in db.devices(con)}
    rows = []
    for d in result.devices:
        dev = stored[d.mac]
        note = "NEW" if d.mac in result.new else "this Mac" if d.is_self else "router" if d.is_gateway else ""
        rows.append([d.ip, identify.display_name(dev), identify.vendor_label(dev), d.mac, note])
    print(table(rows, ["IP", "NAME", "VENDOR", "MAC", ""]))
    print("\n%d devices in %.1f s" % (len(result.devices), result.duration))
    if result.baseline:
        print("First scan: these devices are saved as the baseline (no alerts for them).")
    elif result.new:
        print("%d new device%s." % (len(result.new), "" if len(result.new) == 1 else "s"))
    return 0


def cmd_devices(args):
    con = db.connect()
    rows, now = [], time.time()
    for d in db.devices(con):
        if args.online and not d["online"]:
            continue
        status = "online" if d["online"] else "offline %s" % ago(now - d["last_seen"])
        rows.append([identify.display_name(d), identify.guess_type(d), d["last_ip"], identify.vendor_label(d),
                     d["mac"], status, when(d["first_seen"])])
    if not rows:
        print("No devices yet. Run `netwatch scan` at home." if not args.online else "Nothing online.")
        return 0
    print(table(rows, ["NAME", "TYPE", "LAST IP", "VENDOR", "MAC", "STATUS", "FIRST SEEN"]))
    scan = db.last_scan(con)
    if scan:
        print("\nLast scan %s ago." % ago(now - scan["ts"]))
    return 0


def cmd_label(args):
    con = db.connect()
    try:
        ok = db.set_label(con, args.mac, args.name, args.type)
    except ValueError as e:
        sys.exit("net-watch: %s" % e)
    if not ok:
        sys.exit("net-watch: no device %s (see `netwatch devices`)." % args.mac)
    d = db.get(con, args.mac)
    print("%s → %s (%s)" % (args.mac, identify.display_name(d), identify.guess_type(d)))
    return 0


def cmd_forget(args):
    if db.forget(db.connect(), args.mac):
        print("Forgot %s and its history. If it shows up again it counts as new." % args.mac)
        return 0
    print("No device %s." % args.mac)
    return 1


def cmd_update_oui(args):
    try:
        print("%d vendor prefixes cached." % oui.download())
    except Exception as e:
        sys.exit("net-watch: couldn't download the vendor list: %s" % e)
    return 0


def cmd_home(args):
    info = detect_or_exit()
    cfg = home.load_config()
    if args.forget:
        cfg.pop("home", None)
        home.save_config(cfg)
        print("Home network forgotten. Nothing will be scanned until you confirm one again.")
        return 0
    verdict, message = home.check(info, cfg)
    if verdict == home.REFUSED:
        print(message)
        return 2
    if verdict == home.HOME and not args.reset:
        print(message + "\n" + home.describe(info))
        return 0
    if verdict == home.AWAY:
        saved = cfg["home"]
        print("Saved home: subnet %s, router %s (%s)" % (saved["subnet"], saved["gateway_ip"], saved["gateway_mac"]))
        if not args.reset:
            print(message + "\nUse `netwatch home --reset` if your router changed and this really is home.")
            return 0
    return 0 if home.confirm(info) else 1


def build_parser():
    p = argparse.ArgumentParser(prog="netwatch", description="Home network device dashboard for macOS.")
    p.add_argument("--version", action="version", version="net-watch " + __version__)
    sub = p.add_subparsers(dest="command", metavar="command")

    s = sub.add_parser("scan", help="scan the home network once and print the devices")
    s.add_argument("--nmap", action="store_true", help="also run an unprivileged `nmap -sn` (if installed)")
    s.set_defaults(func=cmd_scan)

    s = sub.add_parser("devices", help="list every device seen so far")
    s.add_argument("--online", action="store_true", help="only devices seen in the last scan")
    s.set_defaults(func=cmd_devices)

    s = sub.add_parser("label", help="name a device and/or set its type")
    s.add_argument("mac", type=mac_arg)
    s.add_argument("name", nargs="?", help="label ('' clears it)")
    s.add_argument("--type", choices=db.TYPES + ("",), help="device type ('' = guess again)")
    s.set_defaults(func=cmd_label)

    s = sub.add_parser("forget", help="delete a device and its history")
    s.add_argument("mac", type=mac_arg)
    s.set_defaults(func=cmd_forget)

    s = sub.add_parser("home", help="show, confirm or reset the home network (the safety lock)")
    g = s.add_mutually_exclusive_group()
    g.add_argument("--reset", action="store_true", help="save the current network as home (e.g. new router)")
    g.add_argument("--forget", action="store_true", help="forget the saved home network")
    s.set_defaults(func=cmd_home)

    s = sub.add_parser("update-oui", help="re-download the MAC vendor list")
    s.set_defaults(func=cmd_update_oui)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if not getattr(args, "func", None):
        build_parser().print_help()
        sys.exit(0)
    try:
        sys.exit(args.func(args))
    except KeyboardInterrupt:
        sys.exit(130)
