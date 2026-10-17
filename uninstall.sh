#!/bin/sh
# Removes the launchd agent and the command. Keeps your data unless you pass --purge.
set -u
UID_="$(id -u)"
SUPPORT="${NETWATCH_HOME:-$HOME/Library/Application Support/net-watch}"
LABEL="com.netwatch.serve"
[ "${NETWATCH_NO_LAUNCHCTL:-0}" = 1 ] || launchctl bootout "gui/$UID_/$LABEL" 2>/dev/null
rm -f "$HOME/Library/LaunchAgents/$LABEL.plist" "$HOME/.local/bin/netwatch"
if [ "${1:-}" = "--purge" ]; then
  rm -rf "$SUPPORT"
  echo "Removed everything, including the device database and your home network setting."
else
  echo "Uninstalled. Your data is still in: $SUPPORT  (run with --purge to delete it)"
fi
