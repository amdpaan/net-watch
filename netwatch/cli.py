"""netwatch command line."""

import argparse
import sys
import threading
import time

from . import __version__, db, home, identify, netinfo, notify, oui, scanner, serve


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
    except scanner.ScanInterrupted as e:
        print("%s Run `netwatch scan` again." % e, file=sys.stderr)
        return 1
    con = db.connect()
    stored = {d["mac"]: d for d in db.devices(con)}
    rows = []
    for d in result.devices:
        dev = stored[d.mac]
        note = "NEW" if d.mac in result.new else "this Mac" if d.is_self else "router" if d.is_gateway else ""
        rows.append([d.ip, identify.display_name(dev), identify.vendor_label(dev), d.mac, note])
    print(table(rows, ["IP", "NAME", "VENDOR", "MAC", ""]))
    n = len(result.devices)
    print("\n%d device%s in %.1f s" % (n, "" if n == 1 else "s", result.duration))
    if result.baseline:
        print("First scan: these devices are saved as the baseline (no alerts for them).")
    elif result.new:
        print("%d new device%s." % (len(result.new), "" if len(result.new) == 1 else "s"))
        if not args.no_notify:
            notify.alert_new(con, result.new)
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
    con = db.connect()
    waiting = any(e["mac"] == args.mac for e in db.expected(con))
    if db.forget(con, args.mac):
        if waiting:
            print("Removed the pre-named %s. If it joins, it counts as new." % args.mac)
        else:
            print("Forgot %s and its history. If it shows up again it counts as new." % args.mac)
        return 0
    print("No device %s." % args.mac)
    return 1


def cmd_add(args):
    con = db.connect()
    try:
        status = db.add_expected(con, args.mac, args.name, args.type)
    except ValueError as e:
        sys.exit("net-watch: %s" % e)
    if status == "labeled":
        print("%s is already on your list, so it's simply named %s now." % (args.mac, args.name))
    else:
        print("%s → %s. It'll be named automatically when it joins, with no alert." % (args.mac, args.name))
        if netinfo.is_private_mac(args.mac):
            print("This is a private (randomized) address: it only matches while that phone keeps it Fixed "
                  "for your Wi-Fi.")
    return 0


def cmd_expected(args):
    rows = [[e["label"], e["type"] or "", e["mac"], when(e["added_at"])] for e in db.expected(db.connect())]
    if not rows:
        print("No pre-named devices waiting. Add one with `netwatch add <mac> \"Name\" --type phone`.")
        return 0
    print(table(rows, ["NAME", "TYPE", "MAC", "ADDED"]))
    return 0


def cmd_update_oui(args):
    try:
        print("%d vendor prefixes cached." % oui.download())
    except Exception as e:
        sys.exit("net-watch: couldn't download the vendor list: %s" % e)
    return 0


def cmd_serve(args):
    # The dashboard works anywhere (it shows what's stored); scans only run on the home network.
    try:
        info = netinfo.detect()
        if home.check(info)[0] == home.NOT_SET and sys.stdin.isatty():
            home.confirm(info)
    except netinfo.NoNetwork:
        pass
    token = serve.lan_token(rotate=args.new_token) if args.lan else None
    url = "http://127.0.0.1:%d/" % args.port
    worker = serve.Worker(on_result=lambda r: notify.alert_new(db.connect(), r.new, url))
    app = serve.App(lan=args.lan, token=token, worker=worker, verbose=args.verbose)
    try:
        server = serve.make_server(app, "0.0.0.0" if args.lan else "127.0.0.1", args.port)
    except OSError as e:
        sys.exit("net-watch: can't listen on port %d (%s). Try --port." % (args.port, e.strerror or e))
    print("net-watch dashboard: http://127.0.0.1:%d/" % args.port)
    if args.lan:
        host = serve.local_hostname()
        print("On your phone (same Wi-Fi): http://%s:%d/?t=%s" % (host or "<this-mac-ip>", args.port, token))
        print("Anyone with that link can see and edit your devices. Rotate it with --new-token.")
    print("Scanning every %d min while on the home network. Ctrl-C to stop." % args.interval, flush=True)
    threading.Thread(target=worker.loop, args=(args.interval,), kwargs={"log": lambda m: print(m, flush=True)},
                     daemon=True).start()
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


def cmd_demo(args):
    import os
    from . import demo
    folder = demo.demo_home()
    os.environ["NETWATCH_HOME"] = str(folder)
    demo.build()
    print("Demo data written to %s" % folder)
    if args.no_serve:
        return 0
    app = serve.App(worker=demo.DemoWorker())
    server = serve.make_server(app, "127.0.0.1", args.port)
    print("Demo dashboard: http://127.0.0.1:%d/  (Ctrl-C to stop)" % args.port, flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()
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
    s.add_argument("--no-notify", action="store_true", help="don't send notifications for new devices")
    s.set_defaults(func=cmd_scan)

    s = sub.add_parser("serve", help="web dashboard (http://127.0.0.1:8765)")
    s.add_argument("--port", type=int, default=8765)
    s.add_argument("--interval", type=int, default=5, metavar="MIN", help="minutes between scans (default 5)")
    s.add_argument("--lan", action="store_true", help="also reachable from your phone on the same Wi-Fi (token)")
    s.add_argument("--new-token", action="store_true", help="with --lan: make a new access token")
    s.add_argument("-v", "--verbose", action="store_true", help="log every request")
    s.set_defaults(func=cmd_serve)

    s = sub.add_parser("devices", help="list every device seen so far")
    s.add_argument("--online", action="store_true", help="only devices seen in the last scan")
    s.set_defaults(func=cmd_devices)

    s = sub.add_parser("label", help="name a device and/or set its type")
    s.add_argument("mac", type=mac_arg)
    s.add_argument("name", nargs="?", help="label ('' clears it)")
    s.add_argument("--type", choices=db.TYPES + ("",), help="device type ('' = guess again)")
    s.set_defaults(func=cmd_label)

    s = sub.add_parser("add", help="name a device before it joins (it then joins silently)")
    s.add_argument("mac", type=mac_arg)
    s.add_argument("name")
    s.add_argument("--type", choices=db.TYPES)
    s.set_defaults(func=cmd_add)

    s = sub.add_parser("expected", help="list pre-named devices that haven't joined yet")
    s.set_defaults(func=cmd_expected)

    s = sub.add_parser("forget", help="delete a device and its history (or a pre-named one)")
    s.add_argument("mac", type=mac_arg)
    s.set_defaults(func=cmd_forget)

    s = sub.add_parser("home", help="show, confirm or reset the home network (the safety lock)")
    g = s.add_mutually_exclusive_group()
    g.add_argument("--reset", action="store_true", help="save the current network as home (e.g. new router)")
    g.add_argument("--forget", action="store_true", help="forget the saved home network")
    s.set_defaults(func=cmd_home)

    s = sub.add_parser("demo", help="dashboard with made-up devices (never scans)")
    s.add_argument("--port", type=int, default=8766)
    s.add_argument("--no-serve", action="store_true", help="only write the demo data")
    s.set_defaults(func=cmd_demo)

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
