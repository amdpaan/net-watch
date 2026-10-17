"""netwatch command line."""

import argparse
import sys
import time

from . import __version__, home, netinfo, scanner


def table(rows, headers):
    """Plain aligned columns; the last column isn't padded."""
    rows = [["" if c is None else str(c) for c in r] for r in rows]
    widths = [max([len(h)] + [len(r[i]) for r in rows]) for i, h in enumerate(headers)]
    fmt = lambda r: "  ".join(c.ljust(w) for c, w in zip(r[:-1], widths)) + "  " + r[-1]
    return "\n".join([fmt(headers), fmt(["-" * w for w in widths])] + [fmt(r) for r in rows])


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
    started = time.time()
    try:
        result = scanner.scan(info, use_nmap=args.nmap)
    except scanner.PermissionProblem as e:
        print(e, file=sys.stderr)
        return 1
    rows = []
    for d in result.devices:
        note = "this Mac" if d.is_self else "router" if d.is_gateway else ""
        rows.append([d.ip, d.mac, d.hostname or "", note])
    print(table(rows, ["IP", "MAC", "HOSTNAME", ""]))
    print("\n%d devices in %.1f s" % (len(result.devices), time.time() - started))
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

    s = sub.add_parser("home", help="show, confirm or reset the home network (the safety lock)")
    g = s.add_mutually_exclusive_group()
    g.add_argument("--reset", action="store_true", help="save the current network as home (e.g. new router)")
    g.add_argument("--forget", action="store_true", help="forget the saved home network")
    s.set_defaults(func=cmd_home)
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
