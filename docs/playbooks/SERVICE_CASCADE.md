# Playbook: Service Cascade Failure on broker-server

broker-server runs all fleet infrastructure: 6 systemd user services, Docker containers (Wazuh, LiteLLM, Convex), NATS server, and Cloudflare tunnel. When one service fails, it can cascade: broker down means peers are orphaned, NATS down means events are blind, Wazuh down means no security alerts. Recovery order matters -- restoring services in the wrong order causes secondary failures.

## Architecture (What Makes This Dangerous)

```
broker-server (<broker-ip>, Ubuntu 24.04, 32 GB RAM)

systemd user services (all prefixed claude-peers-):
  1. broker        -- HTTP API on :7899, SQLite DB, UCAN auth, health scores
  2. dream         -- Fleet digest, event consumer
  3. supervisor    -- 7 daemon orchestrator, spawns agent processes
  4. wazuh-bridge  -- Tails alerts.json, publishes to NATS
  5. security-watch -- Correlates security events, escalates, emails
  6. response-daemon -- Automated incident response (forensics, IP blocks)

Docker containers:
  - wazuh.manager  -- Wazuh OSSEC manager, receives agent checkins
  - litellm        -- LLM proxy on :4000, routes to Vertex AI/Anthropic
  - convex          -- (if running) application backend

System services:
  - nats-server    -- NATS JetStream on :4222, monitoring on :8222
  - cloudflared    -- Cloudflare tunnel for your-domain.example.com
  - syncthing      -- File sync with workstation
  - sshd           -- SSH access

Dependency chain:
  NATS <- broker (publishes events)
  NATS <- wazuh-bridge (publishes security events)
  NATS <- security-watch (subscribes + publishes escalations)
  NATS <- response-daemon (subscribes to fleet.>)
  NATS <- supervisor (event-triggered daemons + result publishing)
  NATS <- dream (subscribes to fleet.>)

  broker <- all peers (registration, heartbeat, messages)
  broker <- gridwatch (API queries for peers, health)
  broker <- daemons via triage (health check)

  Wazuh Manager <- wazuh-bridge (alerts.json)
  Wazuh Manager <- 5 agents (workstation, edge-node, workstation-2, broker-server, laptop-1)

  LiteLLM <- supervisor/daemons (LLM API calls)
  LiteLLM <- Vertex AI / Anthropic (upstream providers)
```

## Failure Scenarios

### Scenario A: Broker Down

The broker (`claude-peers-broker`) crashes or becomes unresponsive.

**Immediate effects:**
- All peers lose heartbeat -- after 300s (StaleTimeout), peers are marked stale
- No peer registration, no message sending/receiving
- Gridwatch cannot fetch peer list or machine health
- Fleet memory reads/writes fail
- Daemons whose triage checks the broker's `/machine-health` endpoint fail triage

**What keeps working:**
- NATS events continue flowing (NATS is independent)
- Wazuh continues monitoring and wazuh-bridge publishes events
- Security-watch continues correlating
- Daemon invocations continue if triage passes (some don't check broker)
- SSH access is unaffected

### Scenario B: NATS Down

The NATS server (`nats-server.service`) crashes or stops.

**Immediate effects:**
- ALL event flow stops: security events, peer events, daemon results
- Broker cannot dual-write events to NATS (falls back to SQLite-only, events invisible to subscribers)
- Wazuh-bridge cannot publish security events -- security pipeline is blind
- Security-watch loses event feed -- no correlation, no escalation, no email alerts
- Response-daemon loses event feed -- no automated incident response
- Supervisor event-triggered daemons stop firing
- Dream/fleet-digest lose event feed
- Gridwatch NATS panel shows disconnected

**What keeps working:**
- Broker HTTP API continues (SQLite-backed)
- Peer communication works (broker stores in SQLite)
- Wazuh Manager continues monitoring (alerts.json still written)
- LiteLLM continues working
- Interval-based daemons continue on schedule

### Scenario C: Wazuh Manager Down

The Wazuh Manager Docker container stops.

**Immediate effects:**
- No new alerts written to alerts.json
- Wazuh-bridge has nothing to tail -- goes silent
- Security pipeline receives no new events from EDR
- Wazuh agents on fleet machines buffer alerts locally (up to agent buffer limit)
- FIM monitoring stops

**What keeps working:**
- Everything else -- broker, NATS, daemons, peer communication
- The fleet is just blind to security events

### Scenario D: Docker Daemon Crash

Docker itself crashes on broker-server.

**Immediate effects:**
- ALL containers go down: Wazuh Manager, LiteLLM, Convex
- Wazuh pipeline: no alerts, bridge goes silent, security blind
- LiteLLM: all daemon LLM calls fail, supervisor daemons fail
- Convex: application backend down

**What keeps working:**
- NATS (system service, not Docker)
- Broker and all claude-peers services (systemd user services, not Docker)
- Peer communication, event flow (minus security events and LLM)

### Scenario E: Full broker-server Crash

Machine crash, power loss, or kernel panic.

**Impact:** Everything stops. The entire fleet loses:
- Broker (peer communication)
- NATS (event flow)
- Wazuh Manager (security monitoring)
- LiteLLM (daemon LLM access)
- All 6 systemd services
- All Docker containers

Peer machines continue running their local claude-peers clients but cannot reach the broker. Wazuh agents buffer alerts locally. Daemons on any other machine that depends on broker-server services will fail.

### Scenario F: LiteLLM Down

LiteLLM container stops or upstream providers (Vertex AI/Anthropic) are unavailable.

**Immediate effects:**
- All 7 daemons fail when they try to make LLM calls
- Supervisor logs repeated failures, triggers 5-minute cooldown per daemon
- After 3 consecutive failures, email alert sent
- Fleet operations that depend on daemon output (fleet-memory, fleet-scout, pr-helper) go stale

**What keeps working:**
- Everything else -- broker, NATS, Wazuh, peer communication, security pipeline

## Detection

### Gridwatch Dashboard

The gridwatch service monitor checks all services every 30 seconds and pushes status changes to the ticker:

```
Service down -> ticker event "error" level
Docker container stopped -> ticker event "error" level
Failed systemd units -> ticker event showing count
```

The lattice units panel shows the status of all 6 claude-peers services.

### Check Service Status Manually

```bash
# All claude-peers services
ssh broker-server "for svc in claude-peers-broker claude-peers-dream claude-peers-supervisor claude-peers-wazuh-bridge claude-peers-security-watch claude-peers-response-daemon; do
  status=\$(systemctl --user is-active \$svc.service 2>/dev/null)
  echo \"  \$svc: \$status\"
done"

# NATS server
ssh broker-server "systemctl is-active nats-server.service"

# Docker containers
ssh broker-server "docker ps --format 'table {{.Names}}\t{{.Status}}'"

# All failed units
ssh broker-server "systemctl --user list-units --state=failed --no-legend"
```

### Check Logs for Crash Reason

```bash
# Broker logs
ssh broker-server "journalctl --user -u claude-peers-broker --since '30 min ago' --no-pager | tail -30"

# NATS logs
ssh broker-server "journalctl -u nats-server --since '30 min ago' --no-pager | tail -30"

# Docker/container logs
ssh broker-server "docker logs wazuh.manager --tail 30 2>&1"
ssh broker-server "docker logs litellm --tail 30 2>&1"

# System dmesg for OOM kills
ssh broker-server "dmesg | grep -i 'out of memory\|oom\|killed process' | tail -10"
```

## Recovery Procedure

### Recovery Order (CRITICAL)

Services must be restarted in dependency order. Starting downstream services before their dependencies causes reconnection storms and error floods.

```
Phase 1: Infrastructure
  1. Docker daemon (if down)
  2. NATS server

Phase 2: Data sources
  3. Wazuh Manager (Docker container)
  4. LiteLLM (Docker container)

Phase 3: Core fleet
  5. claude-peers-broker

Phase 4: Event processors
  6. claude-peers-wazuh-bridge
  7. claude-peers-security-watch
  8. claude-peers-response-daemon

Phase 5: Operations
  9. claude-peers-supervisor
  10. claude-peers-dream
```

### GAP: No Dependency-Ordered Restart Script

There is currently **no single script** that restarts all services in the correct order. Each service must be restarted individually, and the operator must know the order.

**STATUS: NOT IMPLEMENTED**

### Recovery Script

```bash
#!/bin/bash
# Sontara Lattice service recovery script
# Run on broker-server or via SSH from any fleet machine
# Usage: ssh broker-server "bash -s" < this_script.sh

set -e

HOST="broker-server"

echo "=== Phase 1: Infrastructure ==="

# Docker daemon
if ! ssh $HOST "systemctl is-active docker" >/dev/null 2>&1; then
  echo "Starting Docker..."
  ssh $HOST "sudo systemctl start docker"
  sleep 5
fi

# NATS server
if ! ssh $HOST "systemctl is-active nats-server" >/dev/null 2>&1; then
  echo "Starting NATS..."
  ssh $HOST "sudo systemctl start nats-server"
  sleep 3
fi

echo "=== Phase 2: Data Sources ==="

# Wazuh Manager
if ! ssh $HOST "docker ps --format '{{.Names}}' | grep -q wazuh.manager"; then
  echo "Starting Wazuh Manager..."
  ssh $HOST "docker start wazuh.manager" 2>/dev/null || \
    ssh $HOST "docker compose -f /opt/wazuh-docker/docker-compose.yml up -d wazuh.manager" 2>/dev/null || \
    echo "  WARNING: Could not start Wazuh Manager -- check docker compose location"
  sleep 5
fi

# LiteLLM
if ! ssh $HOST "docker ps --format '{{.Names}}' | grep -q litellm"; then
  echo "Starting LiteLLM..."
  ssh $HOST "docker start litellm" 2>/dev/null || \
    echo "  WARNING: Could not start LiteLLM -- may need manual docker run"
  sleep 3
fi

echo "=== Phase 3: Core Fleet ==="

echo "Starting broker..."
ssh $HOST "systemctl --user start claude-peers-broker"
sleep 3

# Verify broker is responding
if ssh $HOST "curl -sf http://127.0.0.1:7899/health >/dev/null 2>&1"; then
  echo "  Broker is healthy"
else
  echo "  WARNING: Broker not responding on /health"
fi

echo "=== Phase 4: Event Processors ==="

echo "Starting wazuh-bridge..."
ssh $HOST "systemctl --user start claude-peers-wazuh-bridge"
sleep 2

echo "Starting security-watch..."
ssh $HOST "systemctl --user start claude-peers-security-watch"
sleep 2

echo "Starting response-daemon..."
ssh $HOST "systemctl --user start claude-peers-response-daemon"
sleep 2

echo "=== Phase 5: Operations ==="

echo "Starting supervisor..."
ssh $HOST "systemctl --user start claude-peers-supervisor"
sleep 2

echo "Starting dream..."
ssh $HOST "systemctl --user start claude-peers-dream"
sleep 2

echo "=== Verification ==="

ssh $HOST "echo '--- Service Status ---'
for svc in claude-peers-broker claude-peers-dream claude-peers-supervisor claude-peers-wazuh-bridge claude-peers-security-watch claude-peers-response-daemon; do
  status=\$(systemctl --user is-active \$svc.service 2>/dev/null)
  echo \"  \$svc: \$status\"
done
echo '--- Docker ---'
docker ps --format 'table {{.Names}}\t{{.Status}}'
echo '--- NATS ---'
systemctl is-active nats-server
"

echo ""
echo "Recovery complete. Check gridwatch at http://<broker-ip>:8888"
```

### Quick Recovery (Restart All)

For cases where you just need everything back up and don't care about investigating the crash:

```bash
# Restart everything in order on broker-server
ssh broker-server "
sudo systemctl restart nats-server && sleep 3 && \
docker restart wazuh.manager litellm 2>/dev/null; sleep 5 && \
systemctl --user restart claude-peers-broker && sleep 3 && \
systemctl --user restart claude-peers-wazuh-bridge claude-peers-security-watch claude-peers-response-daemon && sleep 2 && \
systemctl --user restart claude-peers-supervisor claude-peers-dream && \
echo 'All services restarted'
"
```

## Decision Tree

```
Service(s) down on broker-server
|
+-- Is the machine itself reachable?
|   +-- NO: Full machine outage
|   |   +-- Check physical power, check Tailscale status
|   |   +-- If machine comes back, run full recovery script
|   |   +-- All fleet machines buffer locally until recovery
|   |
|   +-- YES: Selective service failure
|       +-- Which services are down?
|
+-- NATS down?
|   +-- Check: systemctl is-active nats-server
|   +-- Restart NATS first (everything depends on it)
|   +-- Then restart claude-peers services that lost connections
|
+-- Docker down?
|   +-- Check: systemctl is-active docker
|   +-- Restart Docker, wait for containers to come up
|   +-- Check: docker ps (all containers should auto-restart)
|   +-- If containers don't auto-restart, start them manually
|
+-- Broker down?
|   +-- Check: systemctl --user is-active claude-peers-broker
|   +-- Check logs: journalctl --user -u claude-peers-broker --since '10 min ago'
|   +-- Common causes: SQLite lock, OOM kill, panic
|   +-- Restart broker, verify with curl http://127.0.0.1:7899/health
|
+-- Security pipeline down (wazuh-bridge, security-watch, response-daemon)?
|   +-- Restart in order: bridge -> watch -> response-daemon
|   +-- Check Wazuh container is running first
|   +-- Check NATS is running first
|
+-- Supervisor down?
|   +-- Check logs for crash reason
|   +-- May be OOM from too many daemon processes
|   +-- Restart supervisor, monitor for daemon launches
|
+-- Multiple services down simultaneously?
    +-- Likely root cause: OOM, disk full, or machine restart
    +-- Check dmesg for OOM kills
    +-- Check disk space (DISK_FILL playbook)
    +-- Run full recovery script in dependency order
```

## Post-Recovery Verification

After recovery, verify the full pipeline is working:

```bash
# 1. Check all services are active
ssh broker-server "systemctl --user list-units 'claude-peers-*' --no-legend"

# 2. Check NATS connectivity
nats stream info FLEET

# 3. Check broker health
TOKEN=$(cat ~/.config/claude-peers/token.jwt)
curl -s -H "Authorization: Bearer $TOKEN" http://<broker-ip>:7899/machine-health | python3 -c "
import json, sys
health = json.load(sys.stdin)
for machine, h in sorted(health.items()):
    print(f'  {machine:20s} score={h.get(\"score\",0):3d} status={h.get(\"status\",\"unknown\")}')
"

# 4. Check peers are registering
curl -s -H "Authorization: Bearer $TOKEN" http://<broker-ip>:7899/peers | python3 -c "
import json, sys
peers = json.load(sys.stdin)
print(f'{len(peers)} peers registered')
for p in peers:
    print(f'  {p.get(\"machine\",\"?\")} ({p.get(\"id\",\"?\")[:8]})')
"

# 5. Check Wazuh bridge is tailing
ssh broker-server "journalctl --user -u claude-peers-wazuh-bridge --since '2 min ago' --no-pager | tail -5"

# 6. Check supervisor is running daemons
ssh broker-server "journalctl --user -u claude-peers-supervisor --since '2 min ago' --no-pager | tail -10"

# 7. Check gridwatch dashboard
echo "http://<broker-ip>:8888"
```

## Monitoring Gaps Summary

| Gap | Severity | Status | Remediation |
|-----|----------|--------|-------------|
| No dependency-ordered restart script | **HIGH** | NOT IMPLEMENTED | Create a recovery script (template above) and deploy to broker-server |
| No automatic service recovery | **HIGH** | PARTIAL | Systemd Restart=on-failure exists but doesn't handle dependency ordering |
| No cross-service health check | **MEDIUM** | NOT IMPLEMENTED | A watchdog that verifies the full pipeline (NATS -> broker -> wazuh-bridge -> security-watch) is functioning end-to-end |
| No cascade detection | **MEDIUM** | NOT IMPLEMENTED | If 3+ services fail within 1 minute, alert with "cascade failure" classification |
| No pre-recovery disk check | **MEDIUM** | NOT IMPLEMENTED | Recovery script should check disk space before restarting services (restarting into a full disk causes immediate re-crash) |

## Hardening Recommendations

1. **Deploy the recovery script.** Save the recovery script above to `~/.local/bin/lattice-recover` on broker-server and make it executable. Test it by stopping all services and running it.

2. **Add systemd dependencies.** Configure the claude-peers service units with proper `After=` and `Requires=` directives so systemd handles ordering automatically:
   ```ini
   # claude-peers-wazuh-bridge.service
   [Unit]
   After=nats-server.service
   Wants=nats-server.service
   ```

3. **Add a pipeline health check daemon.** A simple script that periodically:
   - Publishes a test event to NATS
   - Checks broker `/health`
   - Checks that security-watch last processed an event within 30 min
   - Alerts if any step fails

4. **Configure systemd Restart policies.** Ensure all services have `Restart=on-failure` with appropriate `RestartSec` delays to prevent restart storms.

5. **Add OOM score adjustments.** Set `OOMScoreAdjust=-500` for the broker service (most critical) so the kernel kills other processes first during memory pressure.
