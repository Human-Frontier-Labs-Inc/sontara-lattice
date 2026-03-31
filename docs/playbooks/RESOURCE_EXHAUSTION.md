# Playbook: Resource Exhaustion (CPU, RAM, API Budget)

The fleet runs 7 AI daemons on broker-server via the supervisor, each invoking the vinay-agent binary with LLM calls through LiteLLM (<broker-ip>:4000) routing to Vertex AI Claude Sonnet/Haiku. A runaway daemon, infinite loop, or resource-hungry process can exhaust CPU, RAM, or LLM API budget across the fleet.

## Architecture (What Makes This Dangerous)

```
Supervisor (broker-server)
  7 daemons, each running vinay-agent binary:
    fleet-scout      interval:10m  (sonnet)  -- SSH to all machines, check APIs
    fleet-memory     interval:10m  (sonnet)  -- fetch peers/events, build briefing
    llm-watchdog     interval:10m  (haiku)   -- check LiteLLM health
    pr-helper        interval:15m  (sonnet)  -- fix open PRs
    sync-janitor     interval:15m  (sonnet)  -- find Syncthing conflicts
    librarian        interval:3h   (sonnet)  -- run tests, fix docs via PR
    fleet-digest     interval:60m  (haiku)   -- compile hourly fleet status

  Each daemon:
    - Gets a workspace at /tmp/daemon-<name>
    - Runs as an OS process with NO timeout enforcement
    - Has full tool access (SSH, git, curl, filesystem)
    - Consumes LLM tokens per invocation (max_tokens=16384 for sonnet daemons)

LiteLLM (broker-server:4000)
  Routes: claude-sonnet -> Vertex AI, claude-haiku -> Vertex AI
  Auth: API key in systemd env var
  Budget limits: NONE CONFIGURED

broker-server resource budget:
  32 GB RAM shared with: Docker (Wazuh manager, LiteLLM, Convex),
  NATS server, 6 systemd services, Syncthing, Cloudflare tunnel
```

### Known Incidents

- **iot-device AIDE scan**: AIDE filesystem integrity check pegged CPU at 100% for 52 minutes on a Pi Zero 2W with 512MB RAM. Already fixed by removing AIDE and switching to Go-based awareness sensor.
- **fleet-memory $164 overnight**: Fleet-memory daemon consumed $164 in API costs in a single overnight period due to aggressive runs. Root cause was documented in project memory.

## Attack Vectors

### Vector A: Runaway Daemon (Infinite Loop)

A daemon's output triggers itself via NATS. Example: fleet-memory publishes to `fleet.daemon.fleet-memory`, which could trigger another daemon subscribed to `fleet.daemon.>`, whose output triggers fleet-memory again.

The supervisor has a single guard: `s.running[d.Name]` prevents the same daemon from running concurrently. But it does NOT prevent daemon A from triggering daemon B from triggering daemon A in a cycle.

### Vector B: LLM Token Burn

Each sonnet daemon invocation costs roughly $0.10-$0.50 depending on context size and max_tokens (16384). With 4 sonnet daemons running every 10-15 minutes, normal daily cost is ~$30-50. But:
- If triage gates pass when they shouldn't, every invocation runs
- If a daemon generates enormous context (e.g., fleet-scout dumps full process lists from all 7 machines), token usage spikes
- If max_tokens is misconfigured to a higher value, each call costs more
- An attacker modifying daemon.json to `interval:1m` would 15x the invocation rate

### Vector C: Docker OOM on broker-server

Docker containers compete for RAM with the 6 systemd services:
- Wazuh Manager: 2-4 GB typical
- LiteLLM: 500 MB-1 GB
- Convex: variable
- NATS Server: scales with message volume
- Plus 6 claude-peers services and 7 daemon processes

A daemon that spawns subprocesses (agent binary can shell out) could fork-bomb or allocate unbounded memory.

### Vector D: Disk Exhaustion via Daemon Workspaces

Each daemon gets `/tmp/daemon-<name>` as workspace. The agent binary can write files to this directory. If a daemon clones repos, downloads files, or generates large outputs, /tmp fills up. On broker-server, /tmp is usually on the root partition.

## Detection

### Gridwatch Fleet Dashboard

The gridwatch dashboard at http://<broker-ip>:8888 shows per-machine:
- CPU percentage
- RAM used/total and percentage
- Disk used/total and percentage
- Top processes by memory

**Look for:** CPU >90% sustained, RAM >85%, Disk >85%, or a single daemon process consuming >4GB RAM.

### Check Daemon Run History

```bash
# Supervisor exposes daemon history via the broker API
TOKEN=$(cat ~/.config/claude-peers/token.jwt)
curl -s -H "Authorization: Bearer $TOKEN" http://<broker-ip>:7899/supervisor/status | python3 -c "
import json, sys
data = json.load(sys.stdin)
for run in data.get('history', [])[-20:]:
    daemon = run.get('daemon', 'unknown')
    status = run.get('status', 'unknown')
    duration = run.get('duration', 'unknown')
    trigger = run.get('trigger', 'unknown')
    print(f'  {daemon:20s} {status:10s} {duration:>10s} trigger={trigger}')
    if status == 'running':
        print(f'    *** STILL RUNNING ***')
"
```

### Check Process List on broker-server

```bash
ssh broker-server "ps aux --sort=-pcpu | head -20"
ssh broker-server "ps aux --sort=-rss | head -20"

# Specifically check for agent processes (daemon invocations)
ssh broker-server "ps aux | grep agent | grep -v grep"

# Check if any daemon has been running longer than 15 minutes
ssh broker-server "ps -eo pid,etimes,cmd | grep 'agent.*daemon' | awk '\$2 > 900 {print \"LONG-RUNNING:\", \$0}'"
```

### Check Docker Resource Usage

```bash
ssh broker-server "docker stats --no-stream --format 'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}'"
```

### Check LLM API Usage

```bash
# LiteLLM has a spend tracking endpoint
curl -s http://<broker-ip>:4000/spend/logs | python3 -c "
import json, sys
data = json.load(sys.stdin)
if isinstance(data, list):
    total = sum(entry.get('spend', 0) for entry in data)
    print(f'Total spend in recent logs: \${total:.2f}')
    for entry in data[-10:]:
        model = entry.get('model', 'unknown')
        spend = entry.get('spend', 0)
        tokens = entry.get('total_tokens', 0)
        print(f'  {model:30s} \${spend:.4f} tokens={tokens:,}')
else:
    print('Unexpected response format')
    print(json.dumps(data, indent=2)[:500])
" 2>/dev/null || echo "LiteLLM spend endpoint not available"
```

### Check Supervisor Logs

```bash
ssh broker-server "journalctl --user -u claude-peers-supervisor --since '1 hour ago' --no-pager | tail -50"

# Look for:
# - Daemon invocations happening too frequently
# - "already running" messages (daemon overlap)
# - Failed runs accumulating
# - Unusually long durations
```

### GAP: No Daemon Timeout Enforcement

The supervisor in supervisor.go calls `cmd.CombinedOutput()` which blocks indefinitely. There is **no context timeout, no process kill after N minutes**. A daemon can run forever.

**STATUS: NOT IMPLEMENTED**

### GAP: No LLM Cost Tracking or Budget Limits

LiteLLM supports budget limits per API key, but none are configured. There is no alerting when daily spend exceeds a threshold.

**STATUS: NOT IMPLEMENTED**

## Immediate Triage

### Step 1: Identify the runaway process

```bash
# Check what's consuming resources right now
ssh broker-server "top -bn1 | head -20"

# Find long-running agent processes
ssh broker-server "ps -eo pid,etimes,pcpu,rss,cmd --sort=-etimes | grep agent | head -10"
```

### Step 2: Kill the runaway daemon

```bash
# Kill a specific agent process by PID
ssh broker-server "kill <PID>"

# Kill all agent processes (nuclear option -- stops all daemons mid-run)
ssh broker-server "pkill -f 'agent run'"

# Kill a specific daemon's agent process
ssh broker-server "pkill -f 'daemon-fleet-memory'"
```

### Step 3: Stop the supervisor (prevents new daemon invocations)

```bash
ssh broker-server "systemctl --user stop claude-peers-supervisor"
```

### Step 4: Clean up daemon workspaces if disk is full

```bash
ssh broker-server "du -sh /tmp/daemon-* 2>/dev/null"
ssh broker-server "rm -rf /tmp/daemon-*"
```

### Step 5: Restart with resource controls

```bash
# Restart the supervisor
ssh broker-server "systemctl --user start claude-peers-supervisor"

# Monitor for 15 minutes to ensure stability
ssh broker-server "journalctl --user -u claude-peers-supervisor -f"
```

## Investigation

### Determine if API budget was burned

```bash
# Check Anthropic usage dashboard
echo "https://console.anthropic.com/settings/usage"

# Check Vertex AI billing
echo "https://console.cloud.google.com/billing"

# Check LiteLLM logs for request volume
ssh broker-server "docker logs litellm --since 2h 2>&1 | grep 'model=' | wc -l"
ssh broker-server "docker logs litellm --since 2h 2>&1 | grep 'model=' | tail -20"
```

### Determine if a daemon was modified

```bash
# Check if daemon configs were changed
ssh broker-server "ls -la ~/claude-peers-daemons/*/daemon.json"
ssh broker-server "for d in ~/claude-peers-daemons/*/daemon.json; do echo '=== \$d ==='; cat \$d; done"

# Check git log for recent daemon changes
cd ~/projects/claude-peers && git log --oneline --since='24 hours ago' -- daemons/
```

### Check for daemon feedback loops

```bash
# Look for rapid daemon invocations in supervisor logs
ssh broker-server "journalctl --user -u claude-peers-supervisor --since '2 hours ago' --no-pager | grep 'invoking' | awk '{print \$1, \$2, \$3, \$NF}' | uniq -c | sort -rn | head -20"

# If the same daemon is invoked every few seconds, there's a feedback loop
```

## Decision Tree

```
Resource exhaustion detected
|
+-- Is it CPU?
|   +-- Single process at 100%?
|   |   +-- Is it an agent/daemon process?
|   |   |   +-- YES: Kill it, check which daemon, check duration
|   |   |   +-- NO: Identify the process, may be Docker or system
|   |   +-- Multiple processes?
|   |       +-- Fork bomb or daemon spawning children
|   |       +-- Kill process tree: kill -9 -$(pgrep -o agent)
|   |
|   +-- Sustained high CPU across Docker?
|       +-- Check docker stats, may be Wazuh indexing or LiteLLM
|       +-- docker restart <container> if needed
|
+-- Is it RAM?
|   +-- Which process is the top consumer?
|   |   +-- Docker container: docker restart <container>
|   |   +-- Agent process: kill it, add memory limit
|   |   +-- NATS: stream may be large, check NATS_FLOOD playbook
|   +-- Is OOM killer active?
|       +-- Check: dmesg | grep -i "out of memory"
|       +-- If OOM killed critical services, restart them in order
|       +-- See SERVICE_CASCADE playbook for restart order
|
+-- Is it API cost?
|   +-- Check LiteLLM spend logs
|   +-- Stop the supervisor immediately
|   +-- Identify which daemon(s) are burning tokens
|   +-- Check daemon intervals (were they modified?)
|   +-- Restart supervisor after investigation
|
+-- Is it disk?
    +-- Check /tmp/daemon-* workspace sizes
    +-- Check NATS stream size (NATS_FLOOD playbook)
    +-- Check Docker volumes (DISK_FILL playbook)
    +-- Clean up and add limits
```

## Monitoring Gaps Summary

| Gap | Severity | Status | Remediation |
|-----|----------|--------|-------------|
| No daemon execution timeout | **CRITICAL** | NOT IMPLEMENTED | Add `context.WithTimeout()` in supervisor.go invoke(), kill process after 15 min for interval daemons, 30 min for event daemons |
| No LLM cost tracking/budget | **CRITICAL** | NOT IMPLEMENTED | Configure LiteLLM budget limits per key, add daily spend alerting |
| No daemon workspace size limit | **HIGH** | NOT IMPLEMENTED | Set ulimit or tmpfs size for /tmp/daemon-* |
| No per-daemon memory limit | **HIGH** | NOT IMPLEMENTED | Use cgroups or systemd MemoryMax= on supervisor service |
| No daemon invocation rate limiting | **HIGH** | NOT IMPLEMENTED | Supervisor should refuse to invoke a daemon more than N times per hour |
| No feedback loop detection | **MEDIUM** | NOT IMPLEMENTED | Track invocation timestamps per daemon, alert if >5 invocations in 30 min |
| Supervisor 5-minute cooldown only on failure | **MEDIUM** | PARTIAL | Cooldown exists for failed daemons but not for rapid successful invocations |

## Hardening Recommendations

1. **Add execution timeout to supervisor.** In supervisor.go `invoke()`, wrap the command execution with a context timeout:
   ```go
   ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
   defer cancel()
   cmd := exec.CommandContext(ctx, s.agentBin, args...)
   ```
   This kills the agent process if it exceeds 15 minutes.

2. **Configure LiteLLM budget limits.** LiteLLM supports per-key budget limits in its config:
   ```yaml
   budget_limits:
     - api_key: "sk-..."
       max_budget: 50.0    # $50/day
       budget_duration: "1d"
   ```

3. **Set systemd resource limits.** Edit the supervisor service unit:
   ```ini
   [Service]
   MemoryMax=8G
   CPUQuota=200%
   TasksMax=50
   ```

4. **Add daemon invocation rate limiting.** Track invocations per daemon per hour in the supervisor and refuse to invoke if the rate exceeds a threshold (e.g., 6 per hour for a 10-minute interval daemon).

5. **Add workspace cleanup.** After each daemon completes, check `/tmp/daemon-<name>` size and delete if >100 MB. Or use a tmpfs mount with a size limit.

6. **Add cost alerting.** A simple daemon or cron job that queries LiteLLM's spend endpoint and sends an email alert if daily spend exceeds $50.
