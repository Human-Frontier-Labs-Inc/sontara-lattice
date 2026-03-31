#!/bin/bash
# log-monitor triage: check if any ERROR or WARN lines appeared in the last 10 minutes.
# Exits 0 to run the agent, 1 to skip this cycle.

LOG_DIR="${LOG_DIR:-/var/log}"
LOOKBACK_MINS=10

recent_errors=$(find "${LOG_DIR}" -name "*.log" -newer /tmp/.log-monitor-last-run 2>/dev/null \
    -exec grep -lE "ERROR|WARN" {} \; 2>/dev/null | wc -l)

# Update timestamp marker
touch /tmp/.log-monitor-last-run

if [ "${recent_errors:-0}" -gt 0 ]; then
    echo "FOUND: ${recent_errors} log file(s) with recent errors -- run agent"
    exit 0
fi

echo "no recent errors in ${LOG_DIR} -- skipping"
exit 1
