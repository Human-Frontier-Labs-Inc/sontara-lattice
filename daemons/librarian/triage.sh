#!/bin/bash
# Librarian: always run (read-only). Note security status.
BROKER_URL="${CLAUDE_PEERS_BROKER_URL:-http://127.0.0.1:7899}"
health=$(curl -sf -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt 2>/dev/null)" "$BROKER_URL/machine-health" 2>/dev/null)
degraded=$(echo "$health" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(sum(1 for v in d.values() if v["status"]!="healthy"))' 2>/dev/null)
if [ "${degraded:-0}" -gt 0 ]; then
    echo "SECURITY: $degraded machines unhealthy -- audit more carefully"
else
    echo "scheduled audit"
fi
exit 0
