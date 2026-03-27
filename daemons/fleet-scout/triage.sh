#!/bin/bash
# Fleet Scout triage: only run if gridwatch reports errors or warnings.
curl -sf http://localhost:8888/api/ticker 2>/dev/null | python3 -c '
import sys, json
events = json.load(sys.stdin)
problems = [e for e in events if e["level"] in ("error", "critical")]
if problems:
    print(problems[0]["title"])
    sys.exit(0)
sys.exit(1)
' 2>/dev/null
