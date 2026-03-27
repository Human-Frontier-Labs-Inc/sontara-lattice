#!/bin/bash
# LLM Watchdog triage: only run if LiteLLM health check fails.
status=$(curl -sf -H "Authorization: Bearer ${OPENAI_API_KEY}" http://100.109.211.128:4000/health/liveliness 2>/dev/null)
[ -z "$status" ] && echo "LiteLLM unreachable" && exit 0
# Check if any unhealthy endpoints
unhealthy=$(curl -sf -m 5 -H "Authorization: Bearer ${OPENAI_API_KEY}" http://100.109.211.128:4000/health/readiness 2>/dev/null)
echo "$unhealthy" | grep -q '"unhealthy"' && echo "unhealthy endpoints" && exit 0
exit 1
