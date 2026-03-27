#!/bin/bash
# Fleet Memory triage: only run if there are recent events worth consolidating.
count=$(curl -sf http://localhost:8888/api/ticker 2>/dev/null | python3 -c '
import sys, json
events = json.load(sys.stdin)
print(len(events))
' 2>/dev/null)
[ "${count:-0}" -gt 0 ] && echo "$count events to consolidate" && exit 0
exit 1
