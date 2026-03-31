# Playbook: Quarantine Denial of Service (Health Scoring Weaponization)

The broker's health scoring system on broker-server can be used as a weapon. Any entity that can publish to `fleet.security.*` via NATS can manipulate machine health scores to quarantine legitimate machines, degrade fleet operations, or quarantine the broker's own host to blind the security pipeline. The system trusts all incoming SecurityEvents without verifying their origin.

## Architecture (What Makes This Dangerous)

```
Health Scoring (security.go):
  warning  -> +1 point (capped at 9 -- warnings alone never quarantine)
  critical -> +10 points (immediate quarantine at score >= 10)
  quarantine -> immediate quarantine (bypasses score)

  Score thresholds:
    0-4:   healthy
    5-9:   degraded (visible on gridwatch, daemons may skip via triage)
    10+:   quarantined (broker rejects ALL requests from this machine)

  Decay: -2 every 5 minutes (non-quarantined machines only)

  Quarantine effect:
    UCAN middleware returns HTTP 403 "machine quarantined"
    Machine cannot: register peers, send messages, heartbeat, read events
    Machine is effectively cut off from the fleet

Event Flow:
  NATS fleet.security.* -> broker subscribeSecurityEvents() -> updateMachineHealth()

  NO verification of:
    - Who published the event (any NATS client with the shared token)
    - Whether the machine field matches the publisher
    - Whether the event corresponds to a real Wazuh alert
    - Whether the quarantine rate is suspicious
```

### The Core Vulnerability

`updateMachineHealth()` in security.go processes ANY SecurityEvent from NATS without checking its origin. The event's `Machine` field is trusted verbatim. The `Severity` field directly controls score changes. There is no rate limiting, no deduplication, and no correlation with Wazuh.

## Attack Scenarios

### Scenario A: Mass Quarantine via Fake Critical Events

An attacker publishes critical-severity events for every fleet machine:

```bash
# One critical event per machine = score +10 = immediate quarantine
for machine in workstation edge-node workstation-2 laptop-1 iot-device laptop-2; do
  nats pub fleet.security.alert "{
    \"type\": \"alert\",
    \"severity\": \"critical\",
    \"level\": 12,
    \"machine\": \"$machine\",
    \"rule_id\": \"999999\",
    \"description\": \"fake critical event\",
    \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
  }"
done
```

**Impact:** All 6 non-broker machines are quarantined instantly. The broker rejects their requests. Peers cannot communicate. Daemons whose triage checks health scores skip their runs. Gridwatch shows everything red. Fleet is effectively down.

### Scenario B: Direct Quarantine via Quarantine-Severity Events

Even simpler -- the broker handles `quarantine` severity as an immediate status change, bypassing the score system entirely:

```bash
nats pub fleet.security.quarantine "{
  \"type\": \"security.quarantine\",
  \"severity\": \"quarantine\",
  \"machine\": \"workstation\",
  \"description\": \"injected quarantine\",
  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
}"
```

### Scenario C: Degrade All Machines to Score 9

Warnings add +1 but cap at score 9 (degraded, not quarantined). But degraded machines trigger different daemon triage behavior -- fleet-scout reports URGENT, pr-helper and sync-janitor refuse to run.

```bash
# 9 warning events per machine = score 9 = degraded
for machine in workstation edge-node workstation-2 laptop-1 iot-device laptop-2; do
  for i in $(seq 1 9); do
    nats pub fleet.security.alert "{
      \"type\": \"alert\",
      \"severity\": \"warning\",
      \"level\": 7,
      \"machine\": \"$machine\",
      \"rule_id\": \"$((100000+i))\",
      \"description\": \"injected warning $i\",
      \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
    }"
  done
done
```

**Impact:** All machines show degraded. Daemons that check health refuse to run. Fleet-scout reports everything as URGENT, flooding email alerts. But no machine is quarantined, so the attack is subtler and harder to notice.

### Scenario D: Quarantine broker-server (Blind the Security Pipeline)

The most devastating target is broker-server itself. The broker runs on broker-server. If its health score hits quarantine:

```bash
nats pub fleet.security.alert "{
  \"type\": \"alert\",
  \"severity\": \"critical\",
  \"level\": 12,
  \"machine\": \"broker-server\",
  \"description\": \"injected critical\",
  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
}"
```

**Impact:** The broker does not quarantine itself (the UCAN middleware only checks incoming requests from remote machines), but the health score IS updated. Daemons that check `broker-server` health via the `/machine-health` endpoint see it as quarantined and skip runs. Gridwatch shows it red. The security pipeline continues to operate (wazuh-bridge, security-watch, response-daemon are local services), but fleet operators see a false crisis.

### Scenario E: Quarantine Then Attack

The attacker quarantines all monitoring machines first, then performs the real attack while detection is disabled:

1. Quarantine broker-server to degrade daemon triage
2. Quarantine edge-node to kill gridwatch visibility
3. Quarantine workstation to disconnect the operator's primary machine
4. Now perform the actual attack (data exfiltration, NATS injection, etc.) while alerts are suppressed

## Detection

### Sudden Quarantine Without Wazuh Alerts

The single most reliable indicator: if a machine is quarantined but there are no corresponding Wazuh alerts, the quarantine was injected.

```bash
# Check current health state
TOKEN=$(cat ~/.config/claude-peers/token.jwt)
curl -s -H "Authorization: Bearer $TOKEN" http://<broker-ip>:7899/machine-health | python3 -c "
import json, sys
health = json.load(sys.stdin)
for machine, h in sorted(health.items()):
    status = h.get('status', 'unknown')
    score = h.get('score', 0)
    events = h.get('events', [])
    if status in ('quarantined', 'degraded'):
        print(f'*** {machine}: {status} (score {score})')
        for e in events[-3:]:
            print(f'    {e}')
"
```

```bash
# Cross-reference with Wazuh bridge logs
ssh broker-server "journalctl --user -u claude-peers-wazuh-bridge --since '30 min ago' --no-pager | grep -c 'level='"
# If wazuh-bridge published 0-2 events but machines have high scores, events were injected
```

### Multiple Machines Quarantined Simultaneously

Normal Wazuh alerts are machine-specific and staggered. Multiple machines quarantined within seconds is a clear injection signal.

```bash
TOKEN=$(cat ~/.config/claude-peers/token.jwt)
curl -s -H "Authorization: Bearer $TOKEN" http://<broker-ip>:7899/machine-health | python3 -c "
import json, sys
from datetime import datetime
health = json.load(sys.stdin)
quarantined = []
for machine, h in health.items():
    if h.get('status') == 'quarantined' and h.get('demoted_at'):
        quarantined.append((h['demoted_at'], machine))
quarantined.sort()
if len(quarantined) >= 2:
    print(f'{len(quarantined)} machines quarantined:')
    for ts, m in quarantined:
        print(f'  {ts}  {m}')
    # Check time spread
    first = datetime.fromisoformat(quarantined[0][0].replace('Z', '+00:00'))
    last = datetime.fromisoformat(quarantined[-1][0].replace('Z', '+00:00'))
    spread = (last - first).total_seconds()
    if spread < 60:
        print(f'*** SUSPICIOUS: {len(quarantined)} machines quarantined within {spread:.0f} seconds')
else:
    print(f'{len(quarantined)} machines quarantined (normal if 0-1)')
"
```

### Check Security-Watch Correlation Logs

Security-watch logs every event it processes. If it did not escalate, but machines are quarantined, the events were injected directly to the broker's security monitor (which has its own NATS subscription).

```bash
ssh broker-server "journalctl --user -u claude-peers-security-watch --since '30 min ago' --no-pager | grep -E 'CORRELATION|quarantine'"
```

### GAP: No Quarantine Event Verification

The broker's `subscribeSecurityEvents()` handler in security.go processes all events without verifying:
- That the event came from the wazuh-bridge (only legitimate publisher of security events)
- That the machine field matches the NATS connection IP
- That the event rate is normal

**STATUS: NOT IMPLEMENTED**

## Immediate Triage

### Step 1: Unquarantine all falsely quarantined machines

```bash
TOKEN=$(cat ~/.config/claude-peers/token.jwt)

# Unquarantine all machines at once
for machine in workstation edge-node workstation-2 laptop-1 iot-device laptop-2 broker-server; do
  curl -s -X POST http://<broker-ip>:7899/unquarantine \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"machine\": \"$machine\"}"
  echo " -> unquarantined $machine"
done
```

### Step 2: Identify the injecting source

```bash
# Check NATS connections sorted by published message count
curl -s http://<broker-ip>:8222/connz?sort=msgs_to | python3 -c "
import json, sys
data = json.load(sys.stdin)
known_ips = {
    '<workstation-ip>': 'workstation',
    '<broker-ip>': 'broker-server',
    '127.0.0.1': 'broker-server-local',
    '<workstation-2-ip>': 'workstation-2',
    '<laptop-1-ip>': 'laptop-1',
    '<iot-device-ip>': 'iot-device',
    '<laptop-2-ip>': 'laptop-2',
}
print('Top publishers:')
for conn in data.get('connections', [])[:10]:
    ip = conn.get('ip', 'unknown')
    name = conn.get('name', 'unnamed')
    in_msgs = conn.get('in_msgs', 0)
    known = known_ips.get(ip, 'UNKNOWN')
    flag = ' *** SUSPICIOUS' if known == 'UNKNOWN' else ''
    if in_msgs > 0:
        print(f'  {ip:20s} {known:20s} {name:40s} published={in_msgs:,}{flag}')
"
```

### Step 3: Block the attacker from NATS

```bash
ATTACKER_IP="100.x.x.x"  # Replace with identified IP
ssh broker-server "sudo iptables -A INPUT -s $ATTACKER_IP -p tcp --dport 4222 -j DROP"
```

### Step 4: Verify fleet is restored

```bash
TOKEN=$(cat ~/.config/claude-peers/token.jwt)
curl -s -H "Authorization: Bearer $TOKEN" http://<broker-ip>:7899/machine-health | python3 -c "
import json, sys
health = json.load(sys.stdin)
for machine, h in sorted(health.items()):
    print(f'  {machine:20s} score={h.get(\"score\",0):3d} status={h.get(\"status\",\"unknown\")}')
"
```

## Investigation

### Replay injected events from NATS stream

```bash
nats stream view FLEET --last 200 --raw 2>/dev/null | python3 -c "
import json, sys
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        event = json.loads(line)
        if 'severity' in event or 'security' in event.get('type', ''):
            machine = event.get('machine', 'unknown')
            severity = event.get('severity', 'unknown')
            desc = event.get('description', event.get('summary', ''))
            ts = event.get('timestamp', '')
            rule = event.get('rule_id', '')
            print(f'[{ts}] severity={severity:12s} machine={machine:20s} rule={rule:8s} {desc}')
    except json.JSONDecodeError:
        pass
"
```

### Check if the attack was a precursor to something else

The quarantine DoS is most dangerous as a distraction. After restoring fleet health, check:

```bash
# Was fleet memory modified during the quarantine?
TOKEN=$(cat ~/.config/claude-peers/token.jwt)
curl -s -H "Authorization: Bearer $TOKEN" http://<broker-ip>:7899/fleet-memory | head -20

# Were any broker endpoints called during the quarantine window?
ssh broker-server "journalctl --user -u claude-peers-broker --since '1 hour ago' --no-pager | grep -E 'POST|PUT|DELETE' | tail -20"

# Were any SSH connections made to fleet machines during the quarantine?
for machine in workstation edge-node workstation-2 laptop-1 iot-device; do
  echo "=== $machine ==="
  ssh -o ConnectTimeout=5 $machine "last -5" 2>/dev/null
done
```

## Decision Tree

```
Unexpected quarantine(s) detected
|
+-- How many machines quarantined?
|   +-- Single machine
|   |   +-- Check Wazuh bridge logs for matching alerts
|   |   |   +-- YES: Legitimate quarantine, investigate the actual alert
|   |   |   +-- NO: Injected event, unquarantine and investigate source
|   |
|   +-- Multiple machines (2+)
|       +-- Within seconds of each other?
|       |   +-- YES: Almost certainly injected (mass quarantine attack)
|       |   |   +-- Unquarantine all immediately
|       |   |   +-- Identify injecting NATS connection
|       |   |   +-- Block source
|       |   |   +-- Check for concurrent secondary attack
|       |   |
|       |   +-- NO: May be a real distributed attack or cascading incident
|       |       +-- Check Wazuh bridge logs
|       |       +-- Check security-watch correlation logs
|       |       +-- If no matching real events: injected
|
+-- Is broker-server itself showing degraded/quarantined?
|   +-- YES: Check if daemons are skipping runs
|   |   +-- Reset broker-server health score
|   |   +-- Daemons will resume on next interval
|   |
|   +-- NO: Attack targeted only client machines
|
+-- Is the quarantine recurring (coming back after unquarantine)?
    +-- YES: Attacker is still actively injecting
    |   +-- Must block the NATS source first, THEN unquarantine
    |   +-- Consider NATS token rotation if source can't be identified
    |
    +-- NO: One-time injection, recovery is sufficient
```

## Monitoring Gaps Summary

| Gap | Severity | Status | Remediation |
|-----|----------|--------|-------------|
| No origin verification on security events | **CRITICAL** | NOT IMPLEMENTED | Broker should verify that security events come from wazuh-bridge (127.0.0.1 or broker-server IP) |
| No quarantine rate limiting | **CRITICAL** | NOT IMPLEMENTED | If >2 machines quarantined within 5 min, flag as potential injection and require human approval |
| No Wazuh correlation before quarantine | **HIGH** | NOT IMPLEMENTED | Before quarantining, broker should check if a matching Wazuh alert exists (or at least that wazuh-bridge recently published) |
| No quarantine audit log | **HIGH** | NOT IMPLEMENTED | All quarantine/unquarantine events should be logged to SQLite with source IP and timestamp |
| Health score manipulation has no rollback | **MEDIUM** | NOT IMPLEMENTED | No way to undo injected score changes short of full unquarantine (resets to 0) |
| Degraded status affects daemon triage | **MEDIUM** | BY DESIGN | Triage gates check health, so injected warnings degrade daemon operations |

## Hardening Recommendations

1. **Verify security event origin.** The broker's `subscribeSecurityEvents()` should only process events from NATS connections originating from `127.0.0.1` or `<broker-ip>` (broker-server). This requires either NATS connection metadata or message signing with the machine's Ed25519 key.

2. **Add quarantine rate limiting.** If the broker receives quarantine events for more than 2 distinct machines within 5 minutes, it should:
   - NOT auto-quarantine
   - Publish a `fleet.security.suspicious` event
   - Send an email alert
   - Require manual quarantine confirmation

3. **Require human approval for mass quarantine.** Any event that would quarantine more than 1 machine in a 10-minute window should be held in `approval_pending` status until the operator confirms.

4. **Log all health score changes.** Write every health score update to SQLite with the source event, timestamp, and NATS connection info. This creates an audit trail for investigation.

5. **Add quarantine re-injection protection.** After an unquarantine, add a 10-minute cooldown where new quarantine events for that machine require elevated verification (e.g., must match a real Wazuh rule ID from the last hour's bridge logs).
