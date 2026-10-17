# net-watch

[![tests](https://github.com/amdpaan/net-watch/actions/workflows/tests.yml/badge.svg)](https://github.com/amdpaan/net-watch/actions/workflows/tests.yml)

A home network device dashboard for macOS. net-watch scans your home Wi-Fi every few minutes, lists every
device it finds, remembers them, lets you label them and alerts you when an unknown device joins.

Everything runs locally on your Mac. It's free and open source, with no cloud, accounts or paid APIs, and it
uses only the Python that ships with macOS (`/usr/bin/python3`, standard library only).

> **Status:** M1 works: network detection, the safety lock and `netwatch scan`. Storage, vendors, the
> dashboard, alerts and the timeline are coming in the next milestones.

## Screenshots

_Coming with the dashboard (M3). Screenshots will use made-up devices and fake MAC addresses._

## How it works

1. **Which network am I on?** `route -n get default` gives the interface and router IP, `ifconfig` gives
   this Mac's IP and subnet (`ipconfig getifaddr` is the fallback), and the ARP cache gives the router's MAC.
2. **Safety lock.** net-watch only scans the network whose **router MAC** you confirmed as home. On any
   other network (university, café, a friend's place) it does nothing and says so, even if the subnet looks
   the same. It also refuses subnets larger than a /24 and anything outside the private RFC 1918 ranges.
3. **Discovery without sudo.** It sends one ping to every address in the subnet at the same time (64 in
   parallel, a few seconds for a /24). Even devices that ignore pings answer the ARP request that comes
   first, so the Mac's ARP cache fills up, and `arp -an` then lists every device. If `nmap` is installed,
   `netwatch scan --nmap` adds an unprivileged `nmap -sn` pass; it's optional.
4. **Names.** Reverse DNS goes through macOS's mDNSResponder, so it finds names from your router's DNS and
   from Bonjour (`.local`).

## Setup

Requirements: macOS (Apple Silicon or Intel) and the built-in `/usr/bin/python3`. Nothing to install.

```sh
git clone https://github.com/amdpaan/net-watch.git ~/Projects/net-watch
cd ~/Projects/net-watch
ln -sf "$PWD/bin/netwatch" ~/.local/bin/netwatch   # optional: put it on your PATH
netwatch home    # at home: confirm this network as home (saves the router's MAC)
netwatch scan    # scan once and print a table
```

### Local Network permission

macOS asks before an app talks to devices on your network. If the first scan says the pings were blocked,
open **System Settings → Privacy & Security → Local Network** and turn on the app you ran it from
(Terminal, iTerm, ...).

## Commands

```sh
netwatch scan            # one scan, prints a table (asks to confirm home on first run)
netwatch scan --nmap     # also run nmap -sn if installed
netwatch home            # show the saved home network
netwatch home --reset    # new router? save the current network as home
netwatch home --forget   # forget it (nothing gets scanned until you confirm again)
```

## Your data

Everything lives in `~/Library/Application Support/net-watch/` (override with `NETWATCH_HOME`), never in
the repo. `.gitignore` also excludes databases, the vendor cache and raw command captures in case that
folder ever points inside the repo.

## Development

```sh
uvx --python /usr/bin/python3 pytest      # or: /usr/bin/python3 -m pytest
```

Tests parse saved `route`, `ifconfig` and `arp` output in `tests/fixtures/`, so they never touch a real
network. Fixtures only use fake MACs (the IANA documentation range `00:00:5e:00:53:xx` and made-up private
addresses) and the example subnet `192.168.50.0/24`.

## License

MIT
