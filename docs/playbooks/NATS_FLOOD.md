# Playbook: NATS JetStream Flood (Storage Exhaustion)

The NATS JetStream FLEET stream on broker-server (<broker-ip>:4222) uses file-based storage with `LimitsPolicy` retention and a 24-hour `MaxAge`. There is **no MaxBytes or MaxMsgs limit** configured in the stream. An attacker with the shared NATS token can flood the stream with messages until the underlying disk partition is full, causing NATS to reject new publishes and disrupting all fleet event flow.

## Architecture (What Makes This Dangerous)

```
NATS JetStream (broker-server:4222)
  Stream: FLEET
  Subjects: fleet.>
  Retention: LimitsPolicy
  MaxAge: 24 hours
  MaxBytes: UNLIMITED (not set)
  MaxMsgs: UNLIMITED (not set)
  Storage: FileStorage (/var/lib/nats/ or default JetStream dir)
  Auth: Single shared nats_token

Stream config in nats.go:
  &nats.StreamConfig{
    Name:       "FLEET",
    Subjects:   []string{"fleet.>"},
    Retention:  nats.LimitsPolicy,
    MaxAge:     24 * time.Hour,
    Storage:    nats.FileStorage,
    Duplicates: 5 * time.Minute,
  }
  // NO MaxBytes, NO MaxMsgs -- stream grows unbounded within 24h window
```

### Why 24h Retention is the Problem

Messages are retained for 24 hours. If an attacker publishes 1 MB/sec of garbage to `fleet.garbage`, that accumulates to 86 GB in 24 hours before the oldest messages age out. broker-server has limited disk space shared with Docker, Wazuh, Syncthing, and system operations.

### What Gets Affected

- **NATS server**: Runs out of disk, begins rejecting publishes from all clients
- **Broker**: Cannot dual-write events to NATS (SQLite-only fallback, but events are invisible to subscribers)
- **Wazuh Bridge**: Cannot publish security events, security pipeline goes blind
- **Security Watch**: Cannot receive events, no correlation or escalation
- **Response Daemon**: Cannot receive events, automated response disabled
- **Gridwatch**: Event ticker goes stale, no new fleet events displayed
- **Supervisor**: Event-triggered daemons stop firing
- **Dream/Fleet Digest**: Cannot consume events for summaries
- **Consumers**: Fall behind processing the flood, legitimate events buried in noise

## Detection

### Real-Time: Gridwatch NATS Panel

The gridwatch dashboard at http://<broker-ip>:8888 shows NATS stream stats (messages, bytes, consumers) via the nats_monitor.go collector. Look for:
- Stream bytes increasing rapidly (>10 MB/min is suspicious for this fleet)
- Message count spiking (normal fleet traffic is ~100-500 msgs/hour)
- Consumer lag increasing (pending messages growing)

### Check NATS Stream Stats

```bash
# On broker-server (or any machine with nats CLI + token)
nats stream info FLEET

# Key fields to watch:
#   Messages: total message count
#   Bytes: total storage used
#   Consumer Count: number of active consumers
#   First Sequence / Last Sequence: delta shows accumulation rate
```

### Check via NATS Monitoring HTTP API

```bash
# NATS monitoring endpoint (no auth required on tailnet)
curl -s http://<broker-ip>:8222/jsz | python3 -c "
import json, sys
data = json.load(sys.stdin)
for stream in data.get('account_details', [{}])[0].get('stream_detail', []):
    state = stream.get('state', {})
    name = stream.get('name', 'unknown')
    msgs = state.get('messages', 0)
    bytes_used = state.get('bytes', 0)
    consumers = state.get('consumer_count', 0)
    mb = bytes_used / 1024 / 1024
    print(f'Stream: {name}')
    print(f'  Messages: {msgs:,}')
    print(f'  Storage: {mb:.1f} MB')
    print(f'  Consumers: {consumers}')
    if mb > 100:
        print(f'  WARNING: Stream exceeds 100 MB')
    if msgs > 10000:
        print(f'  WARNING: Message count exceeds 10,000')
"
```

### Check Disk Usage on broker-server

```bash
ssh broker-server "df -h / && echo '---' && du -sh /var/lib/nats/ 2>/dev/null || du -sh ~/nats-data/ 2>/dev/null || echo 'NATS data dir not found at expected locations'"
```

### Check Consumer Lag

```bash
# List all consumers and their pending message counts
nats consumer ls FLEET
nats consumer info FLEET security-monitor
nats consumer info FLEET security-watch
nats consumer info FLEET supervisor-fleet-scout

# High "Num Pending" means consumer is falling behind
```

### GAP: No NATS Storage Alerting

There is currently **no automated alerting** when NATS stream storage crosses a threshold. The gridwatch dashboard shows the numbers, but nobody gets notified. The fleet-scout daemon checks services but does not check NATS stream byte usage.

**STATUS: NOT IMPLEMENTED**

## Immediate Triage

### Step 1: Confirm the flood

```bash
# Check current stream state
nats stream info FLEET

# Watch message rate in real time (5 second samples)
for i in 1 2 3 4 5; do
  MSGS=$(nats stream info FLEET -j | python3 -c "import json,sys; print(json.load(sys.stdin)['state']['messages'])")
  echo "$(date +%H:%M:%S) messages=$MSGS"
  sleep 5
done
# If messages are increasing by hundreds/thousands per 5 seconds, this is a flood
```

### Step 2: Identify the flooding source

```bash
# Check which NATS connections are publishing the most messages
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
print('Top publishers (by messages sent to NATS):')
for conn in data.get('connections', [])[:10]:
    ip = conn.get('ip', 'unknown')
    name = conn.get('name', 'unnamed')
    in_msgs = conn.get('in_msgs', 0)  # in_msgs = published by this client
    known = known_ips.get(ip, 'UNKNOWN')
    print(f'  {ip:20s} {known:20s} {name:40s} published={in_msgs:,}')
"
```

### Step 3: Purge the stream

```bash
# Purge ALL messages from the FLEET stream
# This is safe -- events are transient and consumers will just see nothing pending
nats stream purge FLEET --force

# Verify
nats stream info FLEET
# Messages should be 0, Bytes should be 0
```

### Step 4: Block the flooding source

```bash
# If the flood comes from a specific machine's IP:
FLOOD_IP="100.x.x.x"  # Replace with actual IP from step 2

# Block from reaching NATS port
ssh broker-server "sudo iptables -A INPUT -s $FLOOD_IP -p tcp --dport 4222 -j DROP"
echo "Blocked $FLOOD_IP from NATS"
```

### Step 5: Add stream limits (immediate mitigation)

```bash
# Update the FLEET stream to add byte and message limits
# 256 MB is generous for normal fleet traffic (usually <10 MB)
nats stream edit FLEET \
  --max-bytes=268435456 \
  --max-msgs=50000 \
  --discard=old

# Verify the limits are in place
nats stream info FLEET
```

**Note:** This CLI change will be overwritten the next time the broker restarts, because `newNATSPublisher()` in nats.go calls `js.AddStream()` with no MaxBytes/MaxMsgs. The code fix must also be applied -- see Hardening Recommendations below.

## Investigation

### Reconstruct what was published

```bash
# View the last 50 messages in the stream (subjects reveal the flood pattern)
nats stream view FLEET --last 50

# Count messages per subject
nats stream view FLEET --last 1000 --raw 2>/dev/null | python3 -c "
import json, sys
from collections import Counter
subjects = Counter()
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        event = json.loads(line)
        subjects[event.get('type', 'unknown')] += 1
    except:
        subjects['unparseable'] += 1
for subj, count in subjects.most_common(20):
    print(f'  {count:6d}  {subj}')
"
```

### Check if legitimate events were dropped

```bash
# Compare broker SQLite event count with NATS
# The broker dual-writes to SQLite and NATS, so SQLite should have all legitimate events
ssh broker-server "sqlite3 ~/.claude-peers.db 'SELECT COUNT(*) FROM events WHERE created_at > datetime(\"now\", \"-1 hour\")'"

# Check if security events were being published during the flood
ssh broker-server "journalctl --user -u claude-peers-wazuh-bridge --since '1 hour ago' --no-pager | grep 'publish.*failed' | tail -10"
```

### Check consumer health after the flood

```bash
# Consumers that fell behind may have stale state
for consumer in security-monitor security-watch supervisor-fleet-scout; do
  echo "=== $consumer ==="
  nats consumer info FLEET $consumer 2>/dev/null | grep -E "Num Pending|Last Delivered|Num Ack Pending"
done

# If consumers are massively behind, delete and let them re-create on next subscription
nats consumer rm FLEET security-monitor --force
nats consumer rm FLEET security-watch --force
# The broker and security-watch will recreate their consumers on next startup
```

## Decision Tree

```
NATS stream storage growing abnormally
|
+-- Is message count increasing rapidly (>100/sec)?
|   +-- YES: Active flood in progress
|   |   +-- Identify source IP from NATS connz
|   |   +-- Block source IP from port 4222
|   |   +-- Purge the stream
|   |   +-- Add stream limits (max-bytes, max-msgs)
|   |   +-- Investigate the source machine
|   |
|   +-- NO: Gradual accumulation
|       +-- Check if consumers are keeping up (Num Pending)
|       +-- Check if legitimate events are larger than expected
|       +-- May be a slow leak rather than an attack
|
+-- Is disk usage on broker-server above 85%?
|   +-- YES: Immediate purge required regardless of cause
|   |   +-- Purge NATS stream
|   |   +-- Clean Docker (see DISK_FILL playbook)
|   |   +-- Add stream limits
|   |
|   +-- NO: Stream is growing but disk has headroom
|       +-- Add limits proactively
|       +-- Monitor for 30 min
|       +-- If still growing abnormally, identify and block source
|
+-- Are consumers falling behind with high pending counts?
    +-- YES: Consumers are overwhelmed
    |   +-- Delete stale consumers: nats consumer rm FLEET <name>
    |   +-- Restart affected services to recreate consumers
    |
    +-- NO: Stream is large but consumers are keeping up
        +-- Less urgent, but still add byte limits
```

## Monitoring Gaps Summary

| Gap | Severity | Status | Remediation |
|-----|----------|--------|-------------|
| No MaxBytes on FLEET stream | **CRITICAL** | NOT IMPLEMENTED | Add `MaxBytes: 256 * 1024 * 1024` to StreamConfig in nats.go |
| No MaxMsgs on FLEET stream | **HIGH** | NOT IMPLEMENTED | Add `MaxMsgs: 50000` to StreamConfig in nats.go |
| No NATS storage alerting | **HIGH** | NOT IMPLEMENTED | fleet-scout or a dedicated daemon should check stream bytes and alert at 80% of MaxBytes |
| No per-client publish rate limiting | **HIGH** | NOT IMPLEMENTED | NATS server config can set per-connection publish rate limits |
| No consumer lag alerting | **MEDIUM** | NOT IMPLEMENTED | Alert when any consumer's Num Pending exceeds 1000 |
| Stream limits reset on broker restart | **MEDIUM** | BUG | nats.go AddStream call overwrites CLI-set limits because no MaxBytes/MaxMsgs in code |

## Hardening Recommendations

1. **Add stream limits in code.** Update nats.go `newNATSPublisher()` to include MaxBytes and MaxMsgs:
   ```go
   _, err = js.AddStream(&nats.StreamConfig{
       Name:       streamName,
       Subjects:   fleetSubjects,
       Retention:  nats.LimitsPolicy,
       MaxAge:     24 * time.Hour,
       MaxBytes:   256 * 1024 * 1024, // 256 MB
       MaxMsgs:    50000,
       Discard:    nats.DiscardOld,
       Storage:    nats.FileStorage,
       Duplicates: 5 * time.Minute,
   })
   ```

2. **Add NATS storage monitoring.** Either in fleet-scout's triage.sh or as a new check in the service monitor, query the NATS monitoring API for stream bytes and publish an alert when storage exceeds a threshold.

3. **Configure NATS server-level rate limits.** In the NATS server config (`/etc/nats/nats-server.conf`), add per-client message rate limits to prevent any single connection from flooding:
   ```
   authorization {
     token: "..."
     max_payload: 65536
   }
   limits {
     max_connections: 20
     max_payload: 65536
   }
   ```

4. **Implement per-machine NATS NKey auth.** This allows setting per-machine publish rate limits and subject restrictions in the NATS authorization config. See NATS_INJECTION playbook for details.

5. **Add a stream bytes check to gridwatch ticker.** When stream bytes exceed 80% of MaxBytes, push a ticker event with level "warn".
