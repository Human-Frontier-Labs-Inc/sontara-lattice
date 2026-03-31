#!/bin/bash
# health-check triage: check broker, NATS HTTP monitor, and Wazuh API reachability.
# Exits 0 to run the agent, 1 to skip this cycle.

BROKER_URL="${CLAUDE_PEERS_BROKER_URL:-http://127.0.0.1:7899}"
NATS_MONITOR="${NATS_MONITOR_URL:-http://127.0.0.1:8222}"
WAZUH_API="${WAZUH_API_URL:-http://127.0.0.1:55000}"

broker_ok=0
nats_ok=0
wazuh_ok=0

curl -sf --max-time 3 "${BROKER_URL}/health" >/dev/null 2>&1 && broker_ok=1
curl -sf --max-time 3 "${NATS_MONITOR}/healthz" >/dev/null 2>&1 && nats_ok=1
curl -sf --max-time 3 "${WAZUH_API}/" >/dev/null 2>&1 && wazuh_ok=1

if [ $broker_ok -eq 0 ] || [ $nats_ok -eq 0 ] || [ $wazuh_ok -eq 0 ]; then
    echo "DEGRADED: broker=${broker_ok} nats=${nats_ok} wazuh=${wazuh_ok} -- run agent"
    exit 0
fi

echo "all services healthy -- skipping"
exit 1
