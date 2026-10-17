#!/bin/sh
# Installs the netwatch command for the current user and, with --agent, a launchd agent that runs the
# dashboard + background scans at login. Safe to re-run.
#
#   ./install.sh                      # just the command (~/.local/bin/netwatch)
#   ./install.sh --agent              # + start `netwatch serve` at login (127.0.0.1 only, every 5 min)
#   ./install.sh --agent --interval 10
set -eu

REPO="$(cd "$(dirname "$0")" && pwd)"
SUPPORT="${NETWATCH_HOME:-$HOME/Library/Application Support/net-watch}"
AGENTS="$HOME/Library/LaunchAgents"
LABEL="com.netwatch.serve"
PLIST="$AGENTS/$LABEL.plist"
CLI="$REPO/bin/netwatch"
UID_="$(id -u)"

say() { printf '\033[1m==> %s\033[0m\n' "$*"; }

AGENT=0
INTERVAL=5
while [ $# -gt 0 ]; do
  case "$1" in
    --agent) AGENT=1 ;;
    --interval) shift; INTERVAL="${1:?--interval needs minutes}" ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
  shift
done
case "$INTERVAL" in ''|*[!0-9]*) echo "--interval must be a whole number of minutes"; exit 1 ;; esac

[ -x /usr/bin/python3 ] && /usr/bin/python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))' \
  || { echo "Python 3.9+ not found. Install the Command Line Tools: xcode-select --install"; exit 1; }

mkdir -p "$HOME/.local/bin" "$SUPPORT/logs"
say "Linking netwatch into ~/.local/bin"
ln -sf "$CLI" "$HOME/.local/bin/netwatch"
case ":$PATH:" in *":$HOME/.local/bin:"*) ;; *) echo "  Add ~/.local/bin to your PATH to run plain \`netwatch\`." ;; esac

if ! command -v terminal-notifier >/dev/null 2>&1; then
  echo "  Tip: \`brew install terminal-notifier\` makes alerts clickable (opens the dashboard)."
fi

[ "$AGENT" = 1 ] || { echo "Done. Next: \`netwatch home\` at home, then \`netwatch serve\`."; exit 0; }

if ! /usr/bin/python3 -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1])).get("home") else 1)' \
     "$SUPPORT/config.json" 2>/dev/null; then
  echo "  No home network saved yet: the agent will serve the dashboard but won't scan until you run"
  echo "  \`netwatch home\` on your home Wi-Fi."
fi

say "Writing $LABEL (dashboard on 127.0.0.1:8765, scan every $INTERVAL min)"
mkdir -p "$AGENTS"
cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key><array>
    <string>$CLI</string><string>serve</string><string>--interval</string><string>$INTERVAL</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>ThrottleInterval</key><integer>60</integer>
  <key>ProcessType</key><string>Background</string>
  <key>Nice</key><integer>5</integer>
  <key>EnvironmentVariables</key><dict>
    <key>PATH</key><string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    <key>NETWATCH_HOME</key><string>$SUPPORT</string>
  </dict>
  <key>StandardOutPath</key><string>$SUPPORT/logs/serve.log</string>
  <key>StandardErrorPath</key><string>$SUPPORT/logs/serve.log</string>
</dict></plist>
PLIST
plutil -lint "$PLIST" >/dev/null

if [ "${NETWATCH_NO_LAUNCHCTL:-0}" = 1 ]; then
  echo "  (NETWATCH_NO_LAUNCHCTL=1: not loading it)"
  exit 0
fi
# bootout returns before the old job has fully stopped; wait, then retry bootstrap.
launchctl bootout "gui/$UID_/$LABEL" 2>/dev/null || true
for _ in 1 2 3 4 5; do
  launchctl bootstrap "gui/$UID_" "$PLIST" 2>/dev/null && break
  sleep 1
done
launchctl print "gui/$UID_/$LABEL" >/dev/null 2>&1 || { echo "  Couldn't load the agent. Try: launchctl bootstrap gui/$UID_ \"$PLIST\""; exit 1; }
echo "Done. Dashboard: http://127.0.0.1:8765/   Log: $SUPPORT/logs/serve.log"
echo "If the log says macOS blocked the pings, allow python3 in System Settings → Privacy & Security → Local Network."
