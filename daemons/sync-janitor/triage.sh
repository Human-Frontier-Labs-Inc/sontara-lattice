#!/bin/bash
# Sync Janitor: skip if quarantined, otherwise check for conflicts.
BROKER_URL="${CLAUDE_PEERS_BROKER_URL:-http://127.0.0.1:7899}"
MACHINE_NAME="${CLAUDE_PEERS_MACHINE:-$(hostname)}"
health=$(curl -sf -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt 2>/dev/null)" "$BROKER_URL/machine-health" 2>/dev/null)
our_status=$(echo "$health" | python3 -c "import sys,json; d=json.load(sys.stdin); h=d.get('$MACHINE_NAME',{}); print(h.get('status','healthy'))" 2>/dev/null)
if [ "$our_status" = "quarantined" ]; then
    echo "SKIP: quarantined"
    exit 1
fi
# Check for Syncthing conflict files in configured directories.
# Set SYNC_WATCH_DIRS env var (colon-separated) with directories to scan.
SYNC_DIRS="${SYNC_WATCH_DIRS:-$HOME/projects}"
IFS=':' read -ra DIR_LIST <<< "$SYNC_DIRS"
count=0
for dir in "${DIR_LIST[@]}"; do
    [ -d "$dir" ] && count=$((count + $(find "$dir" -name "*.sync-conflict-*" 2>/dev/null | wc -l)))
done
[ "$count" -gt 0 ] && echo "$count conflicts" && exit 0
exit 1
