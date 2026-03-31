# Clock Skew / Time Attack Incident Response Playbook

**System:** Sontara Lattice (claude-peers) fleet
**Last updated:** 2026-03-28
**Audience:** the operator (fleet operator)
**Severity tier:** Tier 2 (Contain) -- can enable token replay or cause denial of service

---

## Table of Contents

1. [Attack Model](#attack-model)
2. [Impact on Fleet Components](#impact-on-fleet-components)
3. [Detection](#detection)
4. [Immediate Triage (0-5 minutes)](#immediate-triage)
5. [Containment and Response](#containment-and-response)
6. [Investigation](#investigation)
7. [Recovery](#recovery)
8. [Post-Incident Hardening](#post-incident-hardening)
9. [Monitoring Gaps](#monitoring-gaps)

---

## Attack Model

### How time affects the fleet

The Sontara Lattice fleet relies on accurate time for:

1. **UCAN token validation** -- tokens have `iat` (issued-at) and `exp` (expiry) timestamps. The broker's `TokenValidator` uses `jwt.WithLeeway(30*time.Second)` for clock skew tolerance.
2. **Wazuh event correlation** -- the security-watch correlator uses timestamps to detect patterns (e.g., "5+ auth failures within 10 minutes"). Skewed timestamps break these windows.
3. **NATS JetStream** -- message deduplication uses a 5-minute window (`Duplicates: 5 * time.Minute`). Skewed clocks could cause duplicate processing or missed deduplication.
4. **Forensic timeline** -- incidents are reconstructed from timestamps across machines. Clock skew makes cross-machine correlation unreliable.
5. **Health score decay** -- the broker decays health scores every 5 minutes based on `time.Now()`. A skewed broker clock changes decay timing.
6. **Stale peer cleanup** -- peers are removed after `StaleTimeout` (300 seconds) based on `last_seen` timestamps. Clock skew can cause premature or delayed cleanup.

### Attack scenarios

**Scenario 1: Clock set backwards on a fleet machine (expired token replay)**

An attacker with root access sets the system clock backwards on a machine. If the machine's clock is set to before the token's `iat`:
- The machine sends requests with timestamps in the "past"
- The broker (with correct time) sees a token that was "just issued" -- no issue
- But if the BROKER's clock is set backwards, expired tokens become valid again

If the BROKER's clock is set backwards by more than 30 seconds past a token's `exp`:
- `jwt.WithLeeway(30*time.Second)` adds 30 seconds to the expiry check
- A token that expired at T will still be accepted until T+30s (broker time)
- Setting the broker clock back by 1 hour makes tokens that expired 1 hour ago valid

**Scenario 2: Clock set forward on a fleet machine (denial of service)**

An attacker sets the system clock forward on a machine:
- The machine's heartbeats have future timestamps
- When the clock is corrected, the machine appears "stale" immediately (last_seen is in the far past relative to the corrected time)
- Peers from that machine are cleaned up as stale

If the BROKER's clock is set forward:
- All current tokens appear expired (current time > exp)
- Every authenticated request gets 401 TOKEN_EXPIRED
- The entire fleet is denied service

**Scenario 3: Clock skew disrupts Wazuh correlation**

The security-watch correlator uses time windows:
- `checkDistributedAttack`: Same rule ID on 3+ machines within 5 minutes
- `checkBruteForce`: 5+ auth failures within 10 minutes
- `checkCredentialTheft`: FIM event + peer registration within 5 minutes
- `pruneOldEvents`: Events older than 30 minutes are discarded

If clocks are skewed between machines:
- Events from a fast-clock machine appear "in the future" and are never pruned
- Events from a slow-clock machine appear "in the past" and are immediately pruned
- Correlation windows break -- attacks spanning multiple machines are not detected because the timestamps don't fall within the same window

**Scenario 4: Subtle clock drift (not malicious but damaging)**

NTP failure or VM clock drift causes gradual desynchronization:
- Tokens expire slightly early or late across machines
- Wazuh timestamps drift, making forensic timeline reconstruction difficult
- NATS deduplication windows become unreliable

### The 30-second leeway

The `TokenValidator` in `ucan.go` line 130:
```go
parser := jwt.NewParser(
    jwt.WithValidMethods([]string{"EdDSA"}),
    jwt.WithLeeway(30*time.Second),
)
```

This means:
- A token that expired up to 30 seconds ago is still accepted
- A token with an `iat` up to 30 seconds in the future is still accepted
- This is intentional to handle normal clock skew between machines
- An attacker who can shift time by more than 30 seconds can exploit the boundary

---

## Impact on Fleet Components

| Component | Time-Dependent Behavior | Impact of Skew |
|-----------|------------------------|----------------|
| **Broker TokenValidator** | `exp` check with 30s leeway | >30s skew: tokens incorrectly accepted/rejected |
| **Broker stale cleanup** | `last_seen < cutoff` (300s timeout) | Peers incorrectly cleaned up or kept alive |
| **Broker health decay** | Runs every 5 minutes via `time.Ticker` | Decay timing changes, scores decay too fast/slow |
| **security-watch** | 5-min, 10-min, 30-min correlation windows | Cross-machine correlations break |
| **wazuh-bridge** | Uses Wazuh alert timestamps (from agent clocks) | Agent clock skew = timestamps from wrong epoch |
| **NATS JetStream** | 5-min deduplication, 24h max age | Messages expire too early or too late |
| **Fleet digest** | Report timestamp | Cosmetic, but confusing |
| **Forensic snapshots** | `CapturedAt: time.Now()` | Timeline reconstruction breaks |
| **response-daemon email throttle** | 15-min throttle via `time.Since()` | Emails throttled incorrectly |

---

## Detection

### What We CAN Detect Today

| Signal | How | Automated? |
|--------|-----|------------|
| Token rejection with `TOKEN_EXPIRED` errors | Broker logs 401 responses | Partial -- logs exist, no alerting |
| Events with impossible timestamps | Manual review of NATS events or Wazuh alerts | No |
| Peers going stale unexpectedly | Gridwatch shows machines disappearing | Partial -- visual monitoring |
| NTP sync failure on systemd machines | `timedatectl` shows sync status | No -- not monitored |

### What We CANNOT Detect Today

| Gap | Risk | Priority |
|-----|------|----------|
| **No NTP sync monitoring** | Clock drift or NTP failure goes unnoticed until something breaks | **P1** |
| **No cross-machine timestamp comparison** | Cannot detect that one machine's clock is off relative to others | **P1** |
| **No alerting on TOKEN_EXPIRED spikes** | Sudden increase in expired token errors (indicating clock skew) not surfaced | **P2** |
| **No `iat` future-time rejection** | Token with `iat` in the future (beyond leeway) is still processed | **P2** |
| **No Wazuh timestamp sanity check** | Alert with a timestamp hours off from the manager's clock is processed normally | **P2** |

---

## Immediate Triage (0-5 minutes)

### Step 1: Check time on all fleet machines

```bash
# Quick time comparison across the fleet
echo "=== Local time ==="
date -u +"%Y-%m-%dT%H:%M:%SZ"

echo "=== broker-server (BROKER) ==="
ssh broker-server "date -u +'%Y-%m-%dT%H:%M:%SZ'"

echo "=== workstation ==="
ssh <workstation-ip> "date -u +'%Y-%m-%dT%H:%M:%SZ'"

echo "=== edge-node ==="
ssh edge-node "date -u +'%Y-%m-%dT%H:%M:%SZ'"

echo "=== workstation-2 ==="
ssh <workstation-2-ip> "date -u +'%Y-%m-%dT%H:%M:%SZ'"

echo "=== laptop-1 ==="
ssh <user>@<laptop-1-ip><laptop-1-ip> "date -u +'%Y-%m-%dT%H:%M:%SZ'"

echo "=== iot-device ==="
ssh <iot-device-ip> "date -u +'%Y-%m-%dT%H:%M:%SZ'"

# All timestamps should be within 1-2 seconds of each other
# >5 seconds difference = investigate
# >30 seconds difference = token validation is affected
# >5 minutes difference = Wazuh correlation is broken
```

### Step 2: Check NTP sync status on each machine

```bash
# Linux machines (systemd-timesyncd or chrony)
for host in broker-server <workstation-ip> edge-node <workstation-2-ip> <iot-device-ip>; do
  echo "=== $host ==="
  ssh $host "timedatectl status 2>/dev/null | grep -E 'synchronized|NTP|System clock'"
done

# macOS
ssh <user>@<laptop-1-ip><laptop-1-ip> "sntp -d time.apple.com 2>&1 | head -5"

# What to look for:
# "System clock synchronized: yes" = good
# "System clock synchronized: no" = NTP is failing
# "NTP service: inactive" = NTP is not running at all
```

### Step 3: Check broker for token expiry errors

```bash
# Check broker logs for TOKEN_EXPIRED errors (indicates someone's clock is off)
ssh broker-server "journalctl --user -u claude-peers-broker --since '1 hour ago' --no-pager | grep -i 'expired\|TOKEN_EXPIRED'"

# Count recent auth errors
ssh broker-server "journalctl --user -u claude-peers-broker --since '1 hour ago' --no-pager | grep -c '401'"
# A sudden spike = possible clock issue
```

### Step 4: Check for deliberate time manipulation

```bash
# Check if someone manually set the time (Linux)
for host in broker-server <workstation-ip> edge-node <workstation-2-ip> <iot-device-ip>; do
  echo "=== $host ==="
  ssh $host "journalctl --since '24 hours ago' --no-pager 2>/dev/null | grep -iE 'time.*set|clock.*change|date.*set|timedatectl' | tail -5"
done

# Check if NTP was disabled
for host in broker-server <workstation-ip> edge-node <workstation-2-ip> <iot-device-ip>; do
  echo "=== $host ==="
  ssh $host "systemctl status systemd-timesyncd 2>/dev/null | head -5"
done
```

---

## Containment and Response

### If the BROKER's clock is wrong

This is the most critical scenario. The broker's clock determines token validity for the entire fleet.

```bash
# Force NTP sync on broker-server
ssh broker-server "sudo systemctl restart systemd-timesyncd"
ssh broker-server "sudo timedatectl set-ntp true"

# If systemd-timesyncd is not working, use ntpdate as a fallback
ssh broker-server "sudo ntpdate -u pool.ntp.org 2>/dev/null || sudo chronyc -a makestep 2>/dev/null"

# Verify the clock is now correct
ssh broker-server "date -u +'%Y-%m-%dT%H:%M:%SZ'"

# Restart the broker to clear any cached time-dependent state
ssh broker-server "systemctl --user restart claude-peers-broker"
```

### If a fleet machine's clock is wrong

```bash
MACHINE_HOST="edge-node"  # Replace with affected machine

# Force NTP sync
ssh $MACHINE_HOST "sudo systemctl restart systemd-timesyncd"
ssh $MACHINE_HOST "sudo timedatectl set-ntp true"

# If NTP is broken, set time manually (last resort)
ssh $MACHINE_HOST "sudo timedatectl set-time '$(date -u +%Y-%m-%dT%H:%M:%S)'"

# Verify
ssh $MACHINE_HOST "date -u +'%Y-%m-%dT%H:%M:%SZ'"

# The machine's existing token may now be expired (if clock jumped forward then back)
# Re-issue if needed:
# ssh broker-server "claude-peers issue-token /tmp/<machine>.pub peer-session"
```

### If clock skew caused false quarantines

If Wazuh event timestamps were corrupted by clock skew, the security-watch correlator may have triggered false quarantines:

```bash
# Check which machines are quarantined
curl -s http://<broker-ip>:7899/machine-health \
  -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt)" | jq 'to_entries[] | select(.value.status == "quarantined")'

# Unquarantine machines that were falsely quarantined
for machine in workstation edge-node workstation-2 laptop-1 iot-device; do
  curl -X POST http://<broker-ip>:7899/unquarantine \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt)" \
    -d "{\"machine\": \"$machine\"}"
done
```

### If clock skew enabled a token replay attack

If an attacker exploited clock skew to replay an expired token:

1. Fix the clock first (above)
2. Rotate the token for the affected machine (see TOKEN_REPLAY.md)
3. Check broker logs for what the replayed token was used for
4. Restart the broker to clear the `knownTokens` cache

---

## Investigation

### Was the clock change deliberate?

```bash
# Check for manual time changes in system logs
ssh $MACHINE_HOST "journalctl --since '48 hours ago' --no-pager | grep -iE 'time.*change|clock|ntp|timedatectl|date.*set' | tail -20"

# Check if NTP was intentionally disabled
ssh $MACHINE_HOST "systemctl is-enabled systemd-timesyncd"
# Should be "enabled"

# Check if the NTP config was modified
ssh $MACHINE_HOST "cat /etc/systemd/timesyncd.conf"
# Look for modified NTP servers pointing to attacker-controlled servers

# Check if timedatectl was used to disable NTP
ssh $MACHINE_HOST "journalctl -u systemd-timesyncd --since '48 hours ago' --no-pager"
```

### Was clock skew used to exploit tokens?

```bash
# Check broker logs for accepted tokens that should have been expired
# Look for registrations or API calls from a machine whose clock was wrong
ssh broker-server "journalctl --user -u claude-peers-broker --since '24 hours ago' --no-pager | grep '$MACHINE'"

# Check events timeline for impossible sequences
curl -s http://<broker-ip>:7899/events?limit=200 \
  -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt)" | \
  jq '[.[] | {type, created_at, machine}] | sort_by(.created_at) | .[] | select(.created_at < "2026-03-27T" or .created_at > "2026-03-29T")'
# Events with dates far from today = clock skew artifacts
```

### Was clock skew used to disrupt Wazuh correlation?

```bash
# Check Wazuh alerts for timestamp anomalies
ssh broker-server "tail -200 ~/docker/wazuh/logs/alerts/alerts.json | jq -r '.timestamp' | sort | head -20"
# Look for timestamps that are hours off from the current time

# Check the security-watch for correlation failures
ssh broker-server "journalctl --user -u claude-peers-security-watch --since '24 hours ago' --no-pager | grep -i 'correlat'"
```

---

## Recovery

### Step 1: Synchronize all clocks

```bash
# Ensure NTP is running and synced on every machine
declare -A FLEET=(
  [broker-server]="broker-server"
  [workstation]="<workstation-ip>"
  [edge-node]="edge-node"
  [workstation-2]="<workstation-2-ip>"
  [laptop-1]="<user>@<laptop-1-ip><laptop-1-ip>"
  [iot-device]="<iot-device-ip>"
)

for machine in "${!FLEET[@]}"; do
  HOST="${FLEET[$machine]}"
  echo "=== $machine ==="
  if [ "$machine" = "laptop-1" ]; then
    ssh $HOST "sudo sntp -sS time.apple.com 2>&1 | tail -1"
  else
    ssh $HOST "sudo systemctl restart systemd-timesyncd && sleep 2 && timedatectl status | grep -E 'synchronized|System clock'"
  fi
done
```

### Step 2: Clear stale state

```bash
# Restart the broker (clears knownTokens, resets timers)
ssh broker-server "systemctl --user restart claude-peers-broker"

# Restart security-watch (clears alertWindows with potentially bad timestamps)
ssh broker-server "systemctl --user restart claude-peers-security-watch"

# Wait for fleet to re-register
sleep 30

# Verify all machines are connected
curl -s http://<broker-ip>:7899/list-peers \
  -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt)" \
  -H "Content-Type: application/json" \
  -d '{"scope":"all","cwd":"/"}' | jq '.[].machine'
```

### Step 3: Re-issue tokens if any expired during the incident

```bash
# Check which machines have expired tokens
for machine in workstation edge-node workstation-2 laptop-1 iot-device; do
  case $machine in
    workstation)   HOST="<workstation-ip>" ;;
    edge-node)  HOST="edge-node" ;;
    workstation-2) HOST="<workstation-2-ip>" ;;
    laptop-1)  HOST="<user>@<laptop-1-ip><laptop-1-ip>" ;;
    iot-device)   HOST="<iot-device-ip>" ;;
  esac

  # Decode token expiry
  EXP=$(ssh $HOST "cat ~/.config/claude-peers/token.jwt" | cut -d. -f2 | base64 -d 2>/dev/null | jq -r '.exp')
  NOW=$(date +%s)
  if [ "$EXP" -lt "$NOW" ]; then
    echo "$machine: TOKEN EXPIRED (exp=$EXP, now=$NOW) -- needs re-issue"
  else
    REMAINING=$(( EXP - NOW ))
    echo "$machine: token valid for $(( REMAINING / 3600 )) more hours"
  fi
done
```

---

## Post-Incident Hardening

### Monitor NTP sync status fleet-wide

Add NTP monitoring to the fleet health pipeline. This could be a lightweight check that publishes to NATS:

```bash
# Simple cron-based NTP check on each machine (add to crontab)
# */5 * * * * timedatectl status | grep -q "synchronized: yes" || \
#   logger -t claude-peers "NTP DESYNC: clock not synchronized"

# On each Linux machine:
for host in broker-server <workstation-ip> edge-node <workstation-2-ip> <iot-device-ip>; do
  ssh $host "(crontab -l 2>/dev/null; echo '*/5 * * * * timedatectl status | grep -q \"synchronized: yes\" || logger -t claude-peers \"NTP DESYNC: clock not synchronized\"') | crontab -"
done
```

Wazuh can then pick up the `logger` messages and publish them through the security pipeline.

### Reject tokens with future `iat` claims

The current TokenValidator does not check whether `iat` is in the future. A token issued with a future `iat` would be accepted. Add a check:

```go
// In ucan.go Validate(), after parsing:
// if claims.IssuedAt != nil {
//     iat := claims.IssuedAt.Time
//     if iat.After(time.Now().Add(30 * time.Second)) {
//         return nil, fmt.Errorf("token issued in the future: %v", iat)
//     }
// }
```

### Add timestamp sanity checks in security-watch

The security-watch correlator should reject events with timestamps that are too far from the current time:

```go
// In security_watch.go processEvent(), before adding to alertWindows:
// eventTime, err := time.Parse(time.RFC3339, secEvent.Timestamp)
// if err == nil {
//     drift := time.Since(eventTime).Abs()
//     if drift > 10*time.Minute {
//         log.Printf("[security-watch] WARNING: event timestamp %s is %s from now, possible clock skew", secEvent.Timestamp, drift)
//         // Optionally: publish a clock_skew event to NATS
//     }
// }
```

### Add cross-machine time comparison to fleet digest

The fleet digest runs periodically and contacts all machines. Add a time check:

```go
// In fleet_digest.go, for each machine, compare reported time against local time
// If drift > 5 seconds, flag it in the digest email
```

### Hardware clock considerations

| Machine | Clock Source | NTP Risk |
|---------|------------|----------|
| broker-server | Hardware RTC + NTP | Low -- server-grade hardware, stable |
| workstation | Hardware RTC + NTP | Low -- desktop, always powered |
| workstation-2 | Hardware RTC + NTP | Medium -- laptop, may sleep/hibernate |
| edge-node | **No hardware RTC** (Pi 5) | **High** -- depends entirely on NTP at boot |
| iot-device | **No hardware RTC** (Pi Zero 2W) | **High** -- depends entirely on NTP at boot, may have network issues |
| laptop-1 | Hardware RTC + NTP | Low -- Apple silicon, excellent time management |

Raspberry Pi devices (edge-node, iot-device) have no battery-backed RTC. On boot, they start with the time from the last shutdown and must sync via NTP. If NTP fails at boot:
- edge-node and iot-device could boot with clocks hours or days behind
- All tokens would appear to be from the "future" relative to the Pi's clock
- Wazuh agents on these machines would report events with wrong timestamps

**Fix for Pi devices:**

```bash
# Install a software RTC that saves time to disk (already in systemd, but verify)
ssh edge-node "sudo systemctl enable systemd-timesyncd"
ssh <iot-device-ip> "sudo systemctl enable systemd-timesyncd"

# Consider adding a hardware RTC module to edge-node (DS3231 RTC, ~$5)
# iot-device has limited GPIO available due to the Whisplay HAT
```

---

## Monitoring Gaps

| Gap | Impact | Current State | Fix Priority |
|-----|--------|--------------|-------------|
| **No NTP sync monitoring on any machine** | Clock drift or NTP failure goes unnoticed | timedatectl exists but is not monitored | **P1** |
| **No cross-machine time comparison** | One machine silently drifts, breaking correlation | No automated comparison | **P1** |
| **No `iat` future-time rejection** | Token with `iat` in the future is accepted | TokenValidator does not check `iat` against current time | **P2** |
| **No event timestamp sanity check in security-watch** | Events with wrong timestamps corrupt correlation windows | No validation of event timestamps | **P2** |
| **No alerting on TOKEN_EXPIRED spikes** | Mass token expiry (broker clock jump) not detected | Broker logs errors but no alerting | **P2** |
| **Raspberry Pi devices have no hardware RTC** | Boot with wrong time if NTP fails | Known hardware limitation | **P2** (hardware RTC for edge-node) |
| **No NATS message timestamp validation** | Messages with skewed timestamps processed normally | No validation | **P3** |
| **macOS NTP status not monitored** | laptop-1 clock drift not detected | No monitoring | **P3** |

---

## Quick Reference Card

```
CLOCK SKEW SUSPECTED
    |
    +-- Check all clocks immediately
    |     ssh <machine> "date -u +'%Y-%m-%dT%H:%M:%SZ'"
    |     All machines should be within 1-2 seconds
    |
    +-- Is the BROKER's clock wrong?
    |     YES: CRITICAL -- all token validation is affected
    |          Fix broker clock first: sudo systemctl restart systemd-timesyncd
    |          Restart broker: systemctl --user restart claude-peers-broker
    |     NO:  Lower severity -- only the affected machine is impacted
    |
    +-- How big is the skew?
    |     <30 seconds: Within leeway. Tokens still validate. Fix NTP anyway.
    |     30s - 5min: Token validation affected. Wazuh correlation starting to break.
    |     >5 minutes: Wazuh correlation fully broken. Correlation windows missed.
    |     >24 hours: All tokens appear expired. Fleet is fully denied service.
    |
    +-- Fix the clock
    |     sudo systemctl restart systemd-timesyncd
    |     sudo timedatectl set-ntp true
    |     Verify: timedatectl status | grep synchronized
    |
    +-- Was it deliberate?
    |     Check: journalctl | grep -i 'time.*change\|date.*set\|timedatectl'
    |     Check: systemctl is-enabled systemd-timesyncd
    |     Check: cat /etc/systemd/timesyncd.conf (modified NTP servers?)
    |
    +-- Clean up aftermath
    |     Restart broker (clear cached state)
    |     Restart security-watch (clear alertWindows)
    |     Unquarantine any falsely quarantined machines
    |     Re-issue expired tokens
    |
    +-- Harden
          Add NTP monitoring cron on all machines
          Reject tokens with future iat
          Add timestamp sanity checks in security-watch
          Consider hardware RTC for edge-node
```
