# Log Tampering and Evidence Destruction Incident Response Playbook

**System:** Sontara Lattice (claude-peers) fleet
**Last updated:** 2026-03-28
**Audience:** the operator (fleet operator)
**Severity tier:** Tier 3 (Approval Required) -- log tampering indicates an active attacker covering tracks

---

## Table of Contents

1. [Attack Model](#attack-model)
2. [Detection](#detection)
3. [Immediate Triage (0-5 minutes)](#immediate-triage)
4. [Containment](#containment)
5. [Investigation](#investigation)
6. [Recovery](#recovery)
7. [Post-Incident Hardening](#post-incident-hardening)
8. [Monitoring Gaps](#monitoring-gaps)

---

## Attack Model

### Fleet log sources

| Log Source | Location | Machine | Protected? |
|-----------|----------|---------|-----------|
| journald (systemd) | `/var/log/journal/` | All Linux machines | Persistent if configured; volatile by default on some distros |
| Wazuh ossec.log | Docker volume on broker-server | broker-server | Only as secure as the container/host |
| Wazuh alerts.json | `~/docker/wazuh/logs/alerts/alerts.json` on broker-server | broker-server | Host-mounted -- modifiable by any process as user |
| Broker events | NATS JetStream (`fleet-events` stream) | broker-server | NATS token auth, but stream can be purged |
| NATS server log | journald or file on broker-server | broker-server | Same as journald |
| claude-peers logs | journald per machine | All machines | Same as journald |
| pacman.log | `/var/log/pacman.log` | Arch machines | Root-writable |
| dpkg.log | `/var/log/dpkg.log` | Ubuntu/Debian machines | Root-writable |
| auth.log / secure | journald or `/var/log/auth.log` | All Linux machines | Root-writable |
| Docker logs | Docker log driver on broker-server | broker-server | Accessible via `docker logs` |

### Attack scenarios

**Scenario A: Attacker clears journald logs**

```
1. Attacker gains root on a fleet machine
2. Runs: journalctl --vacuum-time=1s  (deletes all journal entries)
3. Or: rm -rf /var/log/journal/*  (destroys journal files)
4. All system logs on that machine are gone
5. The attacker's initial access method, actions, and persistence are now invisible
```

**Scenario B: Attacker modifies Wazuh alerts**

```
1. Attacker gains access to broker-server as user user
2. Modifies ~/docker/wazuh/logs/alerts/alerts.json to:
   - Remove alerts about their activity
   - Inject false alerts to mislead investigation
3. The wazuh-bridge (if running) may have already forwarded some alerts to NATS
4. But the primary alert file is now corrupted or incomplete
```

**Scenario C: NATS stream purge**

```
1. Attacker with NATS token runs: nats stream purge fleet-events -f
2. All fleet event history is destroyed
3. Daemon messages, security events, peer communications -- all gone
4. No way to reconstruct what happened before the purge
```

**Scenario D: Selective log editing**

```
1. Attacker modifies specific log entries rather than deleting entire logs
2. Removes only the lines showing their SSH login, their commands, their process activity
3. Logs appear intact but are missing critical entries
4. Hardest to detect -- log appears continuous but has gaps
```

**Scenario E: Log file truncation**

```
1. Attacker truncates log files: > /var/log/auth.log
2. File exists but is empty or very small
3. Sudden drop in log file size is detectable but easily overlooked
```

---

## Detection

### Detect log gaps and truncation

```bash
echo "=== Fleet Log Integrity Check ==="

for machine in "localhost" "broker-server" "edge-node" "<workstation-2-ip>" "<iot-device-ip>"; do
    if [ "$machine" = "localhost" ]; then
        NAME="workstation"
    else
        NAME="$machine"
    fi

    echo "--- $NAME ---"
    if [ "$machine" = "localhost" ]; then
        # Check journal continuity
        echo "Journal time range:"
        journalctl --no-pager -o short-iso | head -1
        journalctl --no-pager -o short-iso | tail -1

        # Check for journal vacuum events
        journalctl --no-pager | grep -i 'vacuum' | tail -5

        # Check log file sizes
        echo "Log file sizes:"
        ls -lh /var/log/pacman.log 2>/dev/null
    else
        ssh -o ConnectTimeout=5 $machine "
            echo 'Journal time range:'
            journalctl --no-pager -o short-iso 2>/dev/null | head -1
            journalctl --no-pager -o short-iso 2>/dev/null | tail -1
            echo 'Vacuum events:'
            journalctl --no-pager 2>/dev/null | grep -i 'vacuum' | tail -5
        " 2>/dev/null || echo "  UNREACHABLE"
    fi
done
```

### Detect time gaps in logs

```bash
# Look for suspicious gaps in journal entries (periods with no log entries)
for machine in "broker-server" "edge-node" "<workstation-2-ip>" "<iot-device-ip>"; do
    echo "=== $machine: Log gap analysis ==="
    ssh -o ConnectTimeout=5 $machine "
        journalctl --since '24 hours ago' --no-pager -o short-iso 2>/dev/null | \
        awk -F'T| ' '{print \$1\"T\"\$2}' | cut -c1-16 | uniq -c | sort -n | head -5
        echo '(Lowest counts may indicate gaps)'
        echo ''
        # Look for hour-long gaps
        journalctl --since '24 hours ago' --no-pager -o short-iso 2>/dev/null | \
        awk -F'T| ' '{print \$1\"T\"substr(\$2,1,2)}' | uniq -c | \
        awk '\$1 < 10 {print \"SPARSE: \"\$2\" only \"\$1\" entries\"}'
    " 2>/dev/null || echo "  UNREACHABLE"
done
```

### Detect Wazuh alert tampering

```bash
ssh broker-server "
echo '=== Wazuh Alert File Integrity ==='
# Check file size and modification time
ls -la ~/docker/wazuh/logs/alerts/alerts.json 2>/dev/null

# Check if the file has been truncated (unusually small)
SIZE=\$(stat -c%s ~/docker/wazuh/logs/alerts/alerts.json 2>/dev/null)
echo \"File size: \$SIZE bytes\"
if [ \"\$SIZE\" -lt 1000 ]; then
    echo 'WARNING: Alert file is unusually small -- possible truncation'
fi

# Check for time continuity in alerts
echo 'Alert time range:'
head -1 ~/docker/wazuh/logs/alerts/alerts.json 2>/dev/null | python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get(\"timestamp\",\"unknown\"))' 2>/dev/null
tail -1 ~/docker/wazuh/logs/alerts/alerts.json 2>/dev/null | python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get(\"timestamp\",\"unknown\"))' 2>/dev/null

# Check for malformed JSON lines (sign of manual editing)
echo 'Malformed lines:'
python3 -c '
import json, sys
bad = 0
total = 0
with open(sys.argv[1]) as f:
    for i, line in enumerate(f):
        total += 1
        try:
            json.loads(line.strip())
        except:
            bad += 1
            if bad <= 5:
                print(f\"  Line {i+1}: malformed\")
print(f\"Total: {total} lines, {bad} malformed\")
' ~/docker/wazuh/logs/alerts/alerts.json 2>/dev/null
"
```

### Detect NATS stream tampering

```bash
# Check NATS stream state
curl -sf http://<broker-ip>:8222/jsz | python3 -c "
import json, sys
data = json.load(sys.stdin)
for stream in data.get('account_details', [{}])[0].get('stream_detail', []):
    config = stream.get('config', {})
    state = stream.get('state', {})
    name = config.get('name', 'unknown')
    msgs = state.get('messages', 0)
    first_seq = state.get('first_seq', 0)
    last_seq = state.get('last_seq', 0)
    print(f'Stream: {name}')
    print(f'  Messages: {msgs}')
    print(f'  Sequence: {first_seq} -> {last_seq}')
    print(f'  Gap: {last_seq - first_seq - msgs + 1} missing sequences')
    if first_seq > 1:
        print(f'  WARNING: First sequence is {first_seq} -- earlier messages were purged')
" 2>/dev/null || echo "NATS monitoring unreachable"
```

### Cross-reference timestamps across log sources

```bash
# If an attacker tampers with one log source, others may still have evidence
# Compare timestamps across: journald, Wazuh alerts, NATS events, Docker logs
ssh broker-server "
echo '=== Cross-reference: Last entries from each log source ==='

echo '--- journald ---'
journalctl --since '1 hour ago' --no-pager -o short-iso 2>/dev/null | tail -3

echo '--- Wazuh alerts ---'
tail -3 ~/docker/wazuh/logs/alerts/alerts.json 2>/dev/null | python3 -c '
import json, sys
for line in sys.stdin:
    try:
        a = json.loads(line.strip())
        print(f\"  {a.get(\"timestamp\",\"?\")} - {a.get(\"rule\",{}).get(\"description\",\"?\")}\")
    except:
        pass
'

echo '--- Docker logs (wazuh-manager) ---'
docker logs wazuh-manager --since 1h 2>&1 | tail -3

echo '--- NATS (last 3 fleet events) ---'
nats stream view fleet-events --last 3 2>/dev/null | head -20
"
```

---

## Immediate Triage (0-5 minutes)

### Step 1: Capture current log state before more tampering occurs

```bash
SUSPECT="broker-server"

# Snapshot all available logs NOW
mkdir -p /tmp/log-snapshot-$(date +%Y%m%d%H%M%S)
SNAPSHOT_DIR="/tmp/log-snapshot-$(date +%Y%m%d%H%M%S)"

ssh $SUSPECT "
journalctl --no-pager --since '7 days ago' 2>/dev/null
" > "$SNAPSHOT_DIR/journald-full.txt" 2>/dev/null

ssh $SUSPECT "cat ~/docker/wazuh/logs/alerts/alerts.json" > "$SNAPSHOT_DIR/wazuh-alerts.json" 2>/dev/null

ssh $SUSPECT "docker logs wazuh-manager 2>&1" > "$SNAPSHOT_DIR/wazuh-manager-docker.log" 2>/dev/null

ssh $SUSPECT "docker logs litellm 2>&1" > "$SNAPSHOT_DIR/litellm-docker.log" 2>/dev/null

# NATS stream snapshot
curl -sf http://<broker-ip>:8222/jsz > "$SNAPSHOT_DIR/nats-streams.json" 2>/dev/null

echo "Log snapshot saved to $SNAPSHOT_DIR"
ls -lh "$SNAPSHOT_DIR"
```

### Step 2: Check if log tampering is still in progress

```bash
ssh $SUSPECT "
# Watch for active log deletion/modification
echo '=== Active file access on log paths ==='
sudo lsof /var/log/journal/* 2>/dev/null | grep -v 'systemd-journal' | head -10
sudo lsof ~/docker/wazuh/logs/alerts/alerts.json 2>/dev/null | head -10

# Check for running cleanup commands
ps aux | grep -iE 'vacuum|truncat|shred|wipe|rm.*log' | grep -v grep
"
```

---

## Containment

### Protect remaining logs

```bash
ssh broker-server "
# Make Wazuh alert file append-only (requires root, prevents truncation)
sudo chattr +a ~/docker/wazuh/logs/alerts/alerts.json 2>/dev/null && \
    echo 'alerts.json set to append-only' || \
    echo 'chattr not available -- cannot protect file'

# Protect journal from vacuum
sudo mkdir -p /var/log/journal
sudo systemd-tmpfiles --create --prefix /var/log/journal
"
```

### Snapshot NATS streams before purge

```bash
# Export NATS stream data to file
ssh broker-server "
nats stream backup fleet-events /tmp/nats-backup-fleet-events-\$(date +%Y%m%d%H%M%S) 2>/dev/null && \
    echo 'NATS stream backed up' || \
    echo 'NATS stream backup failed'
"
```

---

## Investigation

### Determine what was tampered with

```bash
# Compare log snapshot against live logs
# If live logs are shorter/different, tampering occurred between snapshot and now

ssh broker-server "
echo '=== Journal integrity ==='
# Check journal file consistency
journalctl --verify 2>&1 | tail -20

echo '=== Recent journal vacuum operations ==='
journalctl --no-pager | grep -i 'vacuum\|rotate\|flush' | tail -10

echo '=== File modification times on log files ==='
stat ~/docker/wazuh/logs/alerts/alerts.json 2>/dev/null
stat /var/log/journal 2>/dev/null
"
```

### Reconstruct timeline from surviving logs

```bash
# Use the log source that was NOT tampered with to fill gaps
# Cross-reference: if journald was wiped, check Wazuh alerts and NATS events
# If Wazuh was modified, check journald and NATS
# If NATS was purged, check journald and Wazuh

ssh broker-server "
echo '=== Reconstructing timeline ==='
echo 'Sources available:'
echo -n '  journald entries (last 24h): '
journalctl --since '24 hours ago' --no-pager 2>/dev/null | wc -l
echo -n '  Wazuh alerts: '
wc -l ~/docker/wazuh/logs/alerts/alerts.json 2>/dev/null
echo -n '  NATS fleet-events messages: '
curl -sf http://<broker-ip>:8222/jsz 2>/dev/null | python3 -c 'import json,sys; data=json.load(sys.stdin); print(sum(s.get(\"state\",{}).get(\"messages\",0) for s in data.get(\"account_details\",[{}])[0].get(\"stream_detail\",[])))'
"
```

### Identify the attacker's actions from remaining evidence

```bash
# Even if the attacker cleared logs, some evidence persists:
ssh broker-server "
echo '=== Persistent evidence sources ==='

echo '--- bash history (may be cleared too) ---'
cat ~/.bash_history 2>/dev/null | tail -20

echo '--- wtmp (login records, harder to tamper) ---'
last -20

echo '--- utmp (current logins) ---'
who

echo '--- lastlog ---'
lastlog 2>/dev/null | grep -v 'Never' | head -10

echo '--- /proc (running processes show current state) ---'
ps auxf | head -30

echo '--- network connections ---'
ss -tlnp

echo '--- file timestamps (attackers often forget these) ---'
# Recently modified files in home directory
find /home/user -maxdepth 2 -mmin -60 -type f 2>/dev/null | head -20
"
```

---

## Recovery

### Step 1: Restore logs from backups (if available)

```bash
# If fleet-backup strategy is implemented (see BACKUP_ATTACK playbook):
# Restore from the most recent backup that predates the tampering
```

### Step 2: Rebuild log continuity

```bash
# After addressing the root cause (evicting the attacker), restart logging
ssh broker-server "
# Restart journald to ensure clean state
sudo systemctl restart systemd-journald

# Restart Wazuh to regenerate alerts
docker restart wazuh-manager

# Verify logs are being written again
sleep 5
journalctl --since '1 minute ago' --no-pager | tail -5
"
```

### Step 3: Re-establish NATS stream if purged

```bash
# Restore from backup if available
ssh broker-server "
nats stream restore fleet-events /tmp/nats-backup-fleet-events-* 2>/dev/null || \
    echo 'No NATS backup available -- stream data is lost'
"
```

---

## Post-Incident Hardening

### 1. Remote log shipping

Ship logs to a separate machine so the attacker cannot destroy evidence by compromising only one machine.

```bash
# Option A: Forward journald to a remote syslog server
# On broker-server, configure systemd-journal-remote
ssh broker-server "
# Forward to workstation (or another machine) as a backup log destination
# In /etc/systemd/journal-upload.conf:
# [Upload]
# URL=http://<workstation-ip>:19532
echo 'TODO: Configure remote journal forwarding'
"

# Option B: Ship Wazuh alerts to NATS as they arrive (already partially done via wazuh-bridge)
# Ensure wazuh-bridge is running and forwarding all alerts in real-time
```

### 2. Append-only log storage

```bash
# Set critical log files to append-only
ssh broker-server "
# Wazuh alerts
sudo chattr +a ~/docker/wazuh/logs/alerts/alerts.json 2>/dev/null

# Note: This prevents log rotation too, so manage size carefully
# Alternative: use a separate append-only filesystem or volume
"
```

### 3. NATS stream protection

```bash
# Configure NATS stream to prevent purge
# Set deny_purge in stream config (NATS 2.10+)
ssh broker-server "
nats stream edit fleet-events --deny-purge 2>/dev/null || \
    echo 'NATS deny-purge not supported -- upgrade NATS or use ACLs'
"
```

### 4. Log integrity monitoring

```bash
# Add Wazuh FIM rules to monitor log files for unexpected modifications
# Monitor:
# - /var/log/journal/ (directory contents)
# - ~/docker/wazuh/logs/alerts/alerts.json (file integrity)
# - /var/log/pacman.log
# - /var/log/dpkg.log
# Alert on: file size decrease, unexpected modification, deletion
```

### 5. Multi-source log correlation

Ensure every significant event is logged to at least two independent sources:

| Event | Source 1 | Source 2 |
|-------|----------|----------|
| Security alert | Wazuh alerts.json | NATS fleet.security.* |
| Service state change | journald | NATS fleet.health.* |
| Peer message | NATS fleet.peers.* | Broker log |
| Package install | pacman.log / dpkg.log | Wazuh package audit |

If an attacker wipes one source, the other still has the evidence.

---

## Monitoring Gaps

| Gap | Severity | Status | Remediation |
|-----|----------|--------|-------------|
| No remote log shipping | **CRITICAL** | NOT IMPLEMENTED | All logs are local -- attacker with root can destroy all evidence on that machine |
| No append-only log protection | **HIGH** | NOT IMPLEMENTED | Critical logs should be append-only or on immutable storage |
| NATS streams can be purged by anyone with a token | **HIGH** | NOT IMPLEMENTED | Enable deny_purge on fleet-events stream or restrict purge via ACLs |
| No log gap detection | **HIGH** | NOT IMPLEMENTED | Automated detection of unusual gaps in log entry timestamps |
| Wazuh alerts.json on host-mounted volume | **HIGH** | BY DESIGN | Any process running as user can modify the alert file |
| No log backup | **HIGH** | NOT IMPLEMENTED | Logs should be included in fleet backup strategy |
| journald may not be persistent on all machines | **MEDIUM** | NOT CONFIRMED | Verify `Storage=persistent` in /etc/systemd/journald.conf on all Linux machines |
| bash_history easily cleared | **LOW** | INHERENT | Consider `PROMPT_COMMAND` approach to ship history to syslog |
| Docker log retention policy unknown | **MEDIUM** | NOT CONFIRMED | Docker may rotate logs aggressively, losing old container output |
| No central log aggregation | **CRITICAL** | NOT IMPLEMENTED | Fleet has no single pane of glass for logs across all machines |
