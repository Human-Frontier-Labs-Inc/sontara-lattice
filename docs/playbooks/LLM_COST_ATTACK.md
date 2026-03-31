# Playbook: LLM Cost Attack (API Budget Burn)

The Sontara Lattice runs 7 AI daemons through LiteLLM (<broker-ip>:4000) routing to Vertex AI Claude Sonnet and Haiku. With no budget caps, no per-invocation cost tracking, and no daemon timeout enforcement, an attacker (or bug) can burn through the API budget rapidly. The fleet-memory $164 overnight incident already demonstrated this failure mode in production.

## Architecture (What Makes This Dangerous)

```
Cost chain:
  Supervisor -> vinay-agent binary -> LiteLLM (:4000) -> Vertex AI / Anthropic APIs

7 daemons, normal daily cost ~$30-50:
  fleet-scout      10m   sonnet  max_tokens=16384  ~$0.20-0.50/run
  fleet-memory     10m   sonnet  max_tokens=16384  ~$0.20-0.50/run
  llm-watchdog     10m   haiku   max_tokens=4096   ~$0.01-0.03/run
  pr-helper        15m   sonnet  max_tokens=16384  ~$0.20-0.50/run
  sync-janitor     15m   sonnet  max_tokens=16384  ~$0.10-0.30/run
  librarian         3h   sonnet  max_tokens=16384  ~$0.50-1.00/run
  fleet-digest     60m   haiku   max_tokens=4096   ~$0.01-0.05/run

  4 sonnet daemons x 10-15 min intervals = ~24-40 invocations/hour
  3 other daemons = ~5-10 invocations/hour
  Total: ~30-50 invocations/hour, $1-3/hour normal

LiteLLM config:
  - Routes claude-sonnet -> vertex_ai/claude-sonnet-4-6
  - Routes claude-haiku -> vertex_ai/claude-haiku (or similar)
  - API key in systemd service env var
  - Budget limits: NONE
  - Rate limits: NONE
  - Spend tracking: available but not monitored

Agent binary (vinay-agent):
  - Reads OPENAI_API_KEY env var
  - Uses max_tokens from agent.toml
  - No per-call cost awareness
  - No total spend tracking
```

### Known Incident: fleet-memory $164 Overnight

Documented in project memory. Fleet-memory daemon consumed $164 in API costs during a single overnight period. Root cause: aggressive invocation pattern with large context windows.

## Attack Vectors

### Vector A: Triage Gate Manipulation

Daemons have triage.sh scripts that decide whether to run. These scripts check conditions like broker health, active peers, etc. If an attacker can manipulate the conditions that triage checks (e.g., by injecting fake healthy status), daemons run more often than intended.

Example: fleet-memory's triage checks for active peers. If an attacker registers fake peers via the broker API, triage passes every time instead of skipping when no peers are active.

### Vector B: Daemon Interval Modification

The `daemon.json` file in each daemon directory sets the schedule. If an attacker has write access to broker-server (or the synced `~/projects/claude-peers/daemons/` directory), they can change `"schedule": "interval:10m"` to `"schedule": "interval:1m"`, increasing invocation rate 10x.

```json
// Before: 6 runs/hour * $0.30/run = $1.80/hour
{"schedule": "interval:10m"}

// After: 60 runs/hour * $0.30/run = $18.00/hour = $432/day
{"schedule": "interval:1m"}
```

### Vector C: max_tokens Manipulation

The `agent.toml` file sets `max_tokens` for LLM responses. Increasing this increases cost per invocation:

```toml
# Before (normal)
max_tokens = 16384

# After (manipulated)
max_tokens = 200000  # Claude 3.5 Sonnet supports up to 8192 output, but the
                     # request still reserves the budget at the API level
```

### Vector D: Daemon Feedback Loop

A daemon's output published to NATS triggers another daemon, whose output triggers the first daemon again. The supervisor prevents the same daemon from running concurrently (`s.running[d.Name]`), but does not prevent cross-daemon trigger cycles.

Example loop:
1. fleet-scout publishes `fleet.daemon.fleet-scout` (complete)
2. A daemon subscribed to `event:fleet.daemon.>` triggers
3. That daemon publishes its result to `fleet.daemon.<name>`
4. fleet-scout's event trigger fires again
5. Each cycle costs 2 LLM invocations

### Vector E: Direct LiteLLM Abuse

LiteLLM on port 4000 is accessible from the entire tailnet. Any machine with the API key (stored in env vars) can make direct LLM calls:

```bash
curl http://<broker-ip>:4000/v1/chat/completions \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "claude-sonnet",
    "messages": [{"role": "user", "content": "Write a 50,000 word essay..."}],
    "max_tokens": 8192
  }'
```

Repeated calls from any fleet machine burn the API budget with no throttling.

## Detection

### Check Supervisor Daemon Run Frequency

```bash
# How many daemon invocations in the last hour?
ssh broker-server "journalctl --user -u claude-peers-supervisor --since '1 hour ago' --no-pager | grep 'invoking' | wc -l"

# Which daemons are running most often?
ssh broker-server "journalctl --user -u claude-peers-supervisor --since '1 hour ago' --no-pager | grep 'invoking' | awk '{print \$NF}' | sort | uniq -c | sort -rn"

# Are any daemons completing in <1 minute and re-triggering?
ssh broker-server "journalctl --user -u claude-peers-supervisor --since '1 hour ago' --no-pager | grep -E 'complete|invoking' | tail -30"
```

### Check LiteLLM Spend

```bash
# LiteLLM spend endpoint
curl -s http://<broker-ip>:4000/spend/logs 2>/dev/null | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    if isinstance(data, list):
        total = sum(entry.get('spend', 0) for entry in data)
        print(f'Total tracked spend: \${total:.2f}')
        print(f'Recent calls:')
        for entry in data[-10:]:
            model = entry.get('model', 'unknown')
            spend = entry.get('spend', 0)
            tokens = entry.get('total_tokens', 0)
            ts = entry.get('startTime', '')
            print(f'  {ts:25s} {model:30s} \${spend:.4f} tokens={tokens:,}')
except:
    print('Could not parse LiteLLM spend data')
" || echo "LiteLLM spend endpoint unavailable"
```

### Check Cloud Provider Billing

```bash
# Vertex AI billing (GCP)
echo "Check: https://console.cloud.google.com/billing"

# Anthropic usage
echo "Check: https://console.anthropic.com/settings/usage"
```

### Check Daemon Intervals (Were They Modified?)

```bash
ssh broker-server "for d in ~/claude-peers-daemons/*/daemon.json; do
  name=\$(basename \$(dirname \$d))
  schedule=\$(python3 -c \"import json; print(json.load(open('\$d')).get('schedule','no schedule'))\" 2>/dev/null)
  echo \"  \$name: \$schedule\"
done"
```

### Check max_tokens Settings

```bash
ssh broker-server "for t in ~/claude-peers-daemons/*/agent.toml; do
  name=\$(basename \$(dirname \$t))
  tokens=\$(grep max_tokens \$t 2>/dev/null | head -1)
  echo \"  \$name: \$tokens\"
done"
```

### GAP: No Cost Tracking or Budget Limits

There is **no automated alerting** when API spend exceeds a threshold. LiteLLM supports budget limits but none are configured. The supervisor does not track cumulative cost across daemon invocations.

**STATUS: NOT IMPLEMENTED**

## Immediate Triage

### Step 1: Stop all daemon invocations

```bash
# Stop the supervisor to prevent new daemon launches
ssh broker-server "systemctl --user stop claude-peers-supervisor"

# Kill any currently running agent processes
ssh broker-server "pkill -f 'agent run' 2>/dev/null; echo 'Killed running agents'"
```

### Step 2: Assess the damage

```bash
# Check LiteLLM logs for request volume in the last hour
ssh broker-server "docker logs litellm --since 1h 2>&1 | grep -c 'model='"
ssh broker-server "docker logs litellm --since 1h 2>&1 | grep 'model=' | tail -20"

# Check Vertex AI / Anthropic billing dashboards
echo "GCP: https://console.cloud.google.com/billing"
echo "Anthropic: https://console.anthropic.com/settings/usage"
```

### Step 3: Identify the root cause

```bash
# Was it a single daemon running too often?
ssh broker-server "journalctl --user -u claude-peers-supervisor --since '4 hours ago' --no-pager | grep 'invoking' | awk '{print \$NF}' | sort | uniq -c | sort -rn | head -10"

# Was a daemon running for too long (large context)?
ssh broker-server "journalctl --user -u claude-peers-supervisor --since '4 hours ago' --no-pager | grep 'complete\|failed' | tail -20"

# Were daemon configs modified?
cd ~/projects/claude-peers && git diff -- daemons/
ssh broker-server "ls -lt ~/claude-peers-daemons/*/daemon.json ~/claude-peers-daemons/*/agent.toml 2>/dev/null"
```

### Step 4: Check for direct LiteLLM abuse

```bash
# Check LiteLLM access logs for non-supervisor clients
ssh broker-server "docker logs litellm --since 2h 2>&1 | grep -v '127.0.0.1' | grep -v '<broker-ip>' | head -20"
```

### Step 5: Restart supervisor with fixes applied

```bash
# Only after confirming daemon configs are correct
ssh broker-server "systemctl --user start claude-peers-supervisor"

# Monitor for normal behavior
ssh broker-server "journalctl --user -u claude-peers-supervisor -f"
```

## Decision Tree

```
Suspected LLM cost attack
|
+-- Is the supervisor running daemons too frequently?
|   +-- YES: Check daemon.json intervals
|   |   +-- Intervals modified? -> Restore from git, restart supervisor
|   |   +-- Intervals normal? -> Check triage gates (passing when they shouldn't)
|   |   +-- Feedback loop? -> Check supervisor logs for rapid A->B->A pattern
|   |
|   +-- NO: Normal invocation rate
|       +-- Check per-call cost (max_tokens modified?)
|       +-- Check if direct LiteLLM calls from other machines
|
+-- Is a single daemon burning most of the budget?
|   +-- YES: Which daemon?
|   |   +-- fleet-memory: Known expensive, check context size
|   |   +-- fleet-scout: SSH + API calls can generate huge context
|   |   +-- librarian: Can clone repos, generate large diffs
|   |   +-- Other: Check agent.toml max_tokens
|   |
|   +-- NO: Spread across daemons
|       +-- All intervals shortened? -> Config tampering
|       +-- Triage gates all passing? -> Check broker health reporting
|
+-- Are there direct LiteLLM calls from non-supervisor sources?
    +-- YES: Unauthorized LLM access
    |   +-- Identify source IP from LiteLLM logs
    |   +-- Block IP from :4000 (iptables)
    |   +-- Rotate LiteLLM API key
    |
    +-- NO: All calls coming from supervisor
        +-- Root cause is in daemon config or behavior
        +-- Fix configs, restart supervisor
```

## Prevention

### Configure LiteLLM Budget Limits

```yaml
# litellm_config.yaml
litellm_settings:
  max_budget: 100.0         # $100/day hard limit
  budget_duration: "1d"

  # Per-model limits
  model_list:
    - model_name: claude-sonnet
      litellm_params:
        model: vertex_ai/claude-sonnet-4-6
      model_info:
        max_budget: 75.0    # $75/day for sonnet
    - model_name: claude-haiku
      litellm_params:
        model: vertex_ai/claude-haiku
      model_info:
        max_budget: 25.0    # $25/day for haiku
```

### Add Daemon Execution Timeout

See RESOURCE_EXHAUSTION playbook. In supervisor.go, add `context.WithTimeout()` to cap daemon execution at 15 minutes.

### Add Daily Spend Monitoring

```bash
# Simple cron job for daily spend check
# Add to broker-server crontab
# 0 */4 * * * ~/.local/bin/check-llm-spend.sh

#!/bin/bash
SPEND=$(curl -s http://<broker-ip>:4000/spend/logs 2>/dev/null | python3 -c "
import json, sys
data = json.load(sys.stdin)
if isinstance(data, list):
    total = sum(e.get('spend', 0) for e in data)
    print(f'{total:.2f}')
else:
    print('0')
" 2>/dev/null)

if [ -n "$SPEND" ] && [ "$(echo "$SPEND > 50" | bc)" -eq 1 ]; then
  resend-email -m "LLM spend alert: \$$SPEND today" your-email@example.com "[fleet-alert] LLM spend \$$SPEND"
fi
```

## Monitoring Gaps Summary

| Gap | Severity | Status | Remediation |
|-----|----------|--------|-------------|
| No LLM budget cap | **CRITICAL** | NOT IMPLEMENTED | Configure LiteLLM budget_duration and max_budget |
| No daemon execution timeout | **CRITICAL** | NOT IMPLEMENTED | Add context.WithTimeout in supervisor.go (see RESOURCE_EXHAUSTION) |
| No per-daemon cost tracking | **HIGH** | NOT IMPLEMENTED | Track cumulative spend per daemon per day |
| No cost alerting | **HIGH** | NOT IMPLEMENTED | Alert when daily spend exceeds threshold ($50) |
| LiteLLM accessible from entire tailnet | **HIGH** | KNOWN | Any machine with API key can make direct calls |
| No daemon invocation rate cap | **HIGH** | NOT IMPLEMENTED | Supervisor should refuse >6 invocations/hour per daemon |
| No feedback loop detection | **MEDIUM** | NOT IMPLEMENTED | Track cross-daemon trigger chains, break cycles |
| Daemon config files syncable via Syncthing | **MEDIUM** | BY DESIGN | Modifying daemon.json on workstation propagates to broker-server via Syncthing |

## Hardening Recommendations (Priority Order)

1. **Configure LiteLLM budget limits immediately.** This is the single most impactful fix. A $100/day cap prevents catastrophic overnight burns while allowing normal operations ($30-50/day).

2. **Add daemon execution timeout.** 15 minutes for interval daemons, 30 minutes for event daemons. Kills the agent process if it exceeds the limit.

3. **Add daily spend monitoring and alerting.** A simple script that checks LiteLLM spend every 4 hours and emails if it exceeds $50.

4. **Restrict LiteLLM network access.** Use iptables on broker-server to limit :4000 access to localhost only (since all daemon invocations originate from broker-server).

5. **Add daemon invocation rate limiting.** The supervisor should track invocations per daemon per hour and refuse to invoke if the rate exceeds a threshold.

6. **Pin daemon config files.** Use file integrity monitoring (Wazuh FIM) on daemon.json and agent.toml files to detect unauthorized modifications.
