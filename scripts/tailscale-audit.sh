#!/bin/bash
# Tailscale device audit -- runs via systemd timer, alerts on unknown devices
# Configure KNOWN_PATTERNS with your fleet device names (pipe-separated regex).
KNOWN_PATTERNS="${TAILSCALE_KNOWN_PATTERNS:-localhost}"
NATS_URL="${NATS_URL:-nats://127.0.0.1:4222}"
NATS_TOKEN="${NATS_TOKEN:-}"

NATS_ARGS="--server=$NATS_URL"
[ -n "$NATS_TOKEN" ] && NATS_ARGS="$NATS_ARGS --token=$NATS_TOKEN"

tailscale status --json 2>/dev/null | python3 -c "
import sys,json
d=json.load(sys.stdin)
for peer in d.get('Peer',{}).values():
    print(peer.get('HostName',''))
for self in [d.get('Self',{})]:
    print(self.get('HostName',''))
" 2>/dev/null | sort -u | while IFS= read -r device; do
    [ -z "$device" ] && continue
    if ! echo "$device" | grep -qiE "$KNOWN_PATTERNS"; then
        echo "ALERT: Unknown Tailscale device: $device"
        nats pub fleet.security.alert \
            "{\"type\":\"network\",\"severity\":\"critical\",\"level\":12,\"machine\":\"$(hostname)\",\"agent_id\":\"tailscale-audit\",\"rule_id\":\"ts-unknown\",\"description\":\"Unknown Tailscale device detected: $device\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" \
            $NATS_ARGS 2>/dev/null
    fi
done
