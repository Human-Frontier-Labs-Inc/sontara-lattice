# Playbook: Disk Fill (Storage Exhaustion on Fleet Machines)

Multiple subsystems on the fleet can fill disk, especially on broker-server where all infrastructure services are co-located. When the root partition fills, NATS stops accepting messages, Docker containers crash, SQLite writes fail, and the broker becomes unresponsive. Recovery is blocked if there is no space for even basic operations.

## Architecture (What Makes This Dangerous)

```
broker-server disk consumers (all on root partition):

  Docker volumes:
    - Wazuh Manager: /opt/wazuh-data/ (alerts.json, logs, DB)
    - LiteLLM: container logs, SQLite DB
    - Convex: container data
    - Other containers
    Total Docker: /var/lib/docker/

  NATS JetStream:
    - FLEET stream storage: 24h retention, NO MaxBytes limit
    - Default location: /var/lib/nats/ or ~/nats-data/

  SQLite:
    - Broker DB: ~/.claude-peers.db (events, fleet memory, peers)

  Daemon workspaces:
    - /tmp/daemon-<name> (7 daemons, agent can write files)

  Wazuh alerts.json:
    - /opt/wazuh-data/logs/alerts/alerts.json
    - Wazuh writes continuously, wazuh-bridge tails it
    - Log rotation may or may not be configured

  Syncthing:
    - ~/projects/ and ~/hfl-projects/ synced from workstation
    - Large file additions on workstation propagate to broker-server
    - ~/ricing-resources/ also synced

  System logs:
    - journalctl logs for 6 systemd user services
    - System journal

Other machines at risk:

  workstation (16 GB disk? -- N100 system):
    - Syncthing sync target
    - /tmp from local operations
    - journalctl logs

  iot-device (Pi Zero 2W, likely small SD card):
    - Minimal storage, easily filled
    - Agent runs write to /tmp
    - sontara-lite logs

  edge-node (Pi 5, SD card):
    - Gridwatch runs locally
    - journalctl logs
```

### What Happens When Disk is Full

1. **NATS**: Rejects all publishes with "insufficient storage" error. All event flow stops.
2. **Docker**: Containers crash or enter unhealthy state. Wazuh Manager stops processing.
3. **Broker SQLite**: Write transactions fail. New events lost. Fleet memory updates rejected.
4. **Wazuh Bridge**: Cannot process alerts (NATS publish fails), falls behind.
5. **Daemons**: Agent binary crashes if it cannot write to workspace.
6. **SSH**: May fail if system cannot write to wtmp/lastlog.

## Detection

### Gridwatch Fleet Dashboard

Gridwatch shows disk percentage per machine on the fleet overview page. The service monitor `collectServices()` runs `df` via SSH and reports `DiskPct`.

**Alert threshold**: Gridwatch ticker pushes a "warn" event when disk exceeds 85% (already implemented in gridwatch).

### Check Disk Usage Manually

```bash
# All fleet machines at once
for machine in broker-server workstation edge-node workstation-2 laptop-1 iot-device; do
  echo "=== $machine ==="
  ssh -o ConnectTimeout=5 $machine "df -h / 2>/dev/null" 2>/dev/null || echo "  unreachable"
done
```

### Identify Largest Consumers on broker-server

```bash
ssh broker-server "
echo '=== Top-level directories ==='
du -sh /var/lib/docker/ 2>/dev/null
du -sh /opt/wazuh-data/ 2>/dev/null
du -sh /var/lib/nats/ 2>/dev/null || du -sh ~/nats-data/ 2>/dev/null
du -sh /tmp/daemon-* 2>/dev/null
du -sh ~/projects/ 2>/dev/null
du -sh ~/hfl-projects/ 2>/dev/null
du -sh ~/.claude-peers.db 2>/dev/null
echo '=== System ==='
du -sh /var/log/ 2>/dev/null
journalctl --disk-usage 2>/dev/null
"
```

### Check Wazuh alerts.json Size

```bash
ssh broker-server "ls -lh /opt/wazuh-data/logs/alerts/alerts.json 2>/dev/null"
ssh broker-server "ls -lh /opt/wazuh-data/logs/alerts/ 2>/dev/null"
```

### Check NATS Stream Storage

```bash
# Via NATS monitoring API
curl -s http://<broker-ip>:8222/jsz | python3 -c "
import json, sys
data = json.load(sys.stdin)
for stream in data.get('account_details', [{}])[0].get('stream_detail', []):
    state = stream.get('state', {})
    name = stream.get('name', 'unknown')
    mb = state.get('bytes', 0) / 1024 / 1024
    msgs = state.get('messages', 0)
    print(f'  {name}: {mb:.1f} MB, {msgs:,} messages')
"
```

### Check Docker Disk Usage

```bash
ssh broker-server "docker system df"
ssh broker-server "docker system df -v" # verbose: per-container breakdown
```

## Immediate Triage

### Step 1: Determine what is filling the disk

```bash
ssh broker-server "df -h / && echo '---' && du -sh /var/lib/docker /opt/wazuh-data /var/lib/nats /tmp/daemon-* /var/log 2>/dev/null | sort -rh | head -10"
```

### Step 2: Quick wins (safe to delete immediately)

```bash
# Daemon workspaces (recreated on next run)
ssh broker-server "rm -rf /tmp/daemon-*"

# Docker build cache and dangling images
ssh broker-server "docker system prune -f"

# Old journal logs (keep last 2 days)
ssh broker-server "sudo journalctl --vacuum-time=2d"
```

### Step 3: NATS stream purge (if NATS is the culprit)

```bash
# Purge all messages from the FLEET stream
nats stream purge FLEET --force

# Or if nats CLI is not available:
ssh broker-server "nats stream purge FLEET --force"
```

### Step 4: Wazuh alerts.json rotation

```bash
# Check size
ssh broker-server "ls -lh /opt/wazuh-data/logs/alerts/alerts.json"

# Truncate (wazuh-bridge seeks to end, so it will just start reading new alerts)
ssh broker-server "sudo truncate -s 0 /opt/wazuh-data/logs/alerts/alerts.json"

# Or if you want to preserve data, rotate:
ssh broker-server "
sudo mv /opt/wazuh-data/logs/alerts/alerts.json /opt/wazuh-data/logs/alerts/alerts.json.old
# Wazuh will create a new alerts.json
# The wazuh-bridge detects rotation via inode change and reopens
"
```

### Step 5: Docker volume cleanup (more aggressive)

```bash
# Check which containers are using the most space
ssh broker-server "docker ps -a --format 'table {{.Names}}\t{{.Size}}'"

# Remove stopped containers
ssh broker-server "docker container prune -f"

# Remove unused volumes (CAREFUL: only if you know what's unused)
ssh broker-server "docker volume ls"
ssh broker-server "docker volume prune -f"  # Only removes truly unused volumes
```

### Step 6: Syncthing large file cleanup

```bash
# Check if Syncthing synced something large recently
ssh broker-server "find ~/projects ~/hfl-projects -maxdepth 3 -size +100M -type f 2>/dev/null"

# Check Syncthing conflict files
ssh broker-server "find ~/projects ~/hfl-projects -name '*.sync-conflict-*' 2>/dev/null | head -20"
```

## Investigation

### Determine Root Cause

```bash
# Check what grew recently (files modified in last 24 hours over 50MB)
ssh broker-server "find / -xdev -mtime -1 -size +50M -type f 2>/dev/null | head -20"

# Check Docker container logs (can grow unbounded)
ssh broker-server "for c in \$(docker ps -q); do
  name=\$(docker inspect --format '{{.Name}}' \$c)
  size=\$(docker inspect --format '{{.LogPath}}' \$c | xargs ls -lh 2>/dev/null | awk '{print \$5}')
  echo \"\$name: \$size\"
done"
```

### Check if NATS was flooded (see NATS_FLOOD playbook)

```bash
curl -s http://<broker-ip>:8222/jsz | python3 -c "
import json, sys
data = json.load(sys.stdin)
for stream in data.get('account_details', [{}])[0].get('stream_detail', []):
    state = stream.get('state', {})
    mb = state.get('bytes', 0) / 1024 / 1024
    if mb > 100:
        print(f'NATS stream {stream[\"name\"]} at {mb:.0f} MB -- likely contributor')
"
```

### Check if it was a Syncthing bomb

```bash
# Check Syncthing recent sync activity
ssh broker-server "curl -s -H 'X-API-Key: YOUR_KEY' http://127.0.0.1:8384/rest/events?since=0&limit=20 2>/dev/null | python3 -c '
import json, sys
events = json.load(sys.stdin)
for e in events:
    if e.get(\"type\") in (\"ItemFinished\", \"FolderSummary\"):
        print(e.get(\"type\"), e.get(\"data\", {}).get(\"item\", \"\"), e.get(\"data\", {}).get(\"folder\", \"\"))
' 2>/dev/null" || echo "Syncthing API not accessible"
```

## Decision Tree

```
Disk usage > 85% detected
|
+-- Which machine?
|   +-- broker-server (most critical)
|   |   +-- What is consuming space?
|   |   |   +-- /var/lib/docker/ > 10 GB
|   |   |   |   +-- docker system prune
|   |   |   |   +-- Check container log sizes
|   |   |   |   +-- Consider log rotation config
|   |   |   |
|   |   |   +-- NATS data > 500 MB
|   |   |   |   +-- Purge stream (nats stream purge FLEET)
|   |   |   |   +-- Add MaxBytes limit (see NATS_FLOOD)
|   |   |   |
|   |   |   +-- Wazuh alerts.json > 1 GB
|   |   |   |   +-- Truncate or rotate
|   |   |   |   +-- Configure log rotation
|   |   |   |
|   |   |   +-- /tmp/daemon-* > 500 MB
|   |   |   |   +-- rm -rf /tmp/daemon-*
|   |   |   |   +-- Add workspace cleanup to supervisor
|   |   |   |
|   |   |   +-- Syncthing folders growing
|   |   |       +-- Check for large files synced recently
|   |   |       +-- Check for massive conflict files
|   |   |
|   |   +-- Is disk > 95%?
|   |       +-- YES: Emergency -- services are likely failing
|   |       |   +-- Kill non-essential containers: docker stop litellm convex
|   |       |   +-- Purge NATS stream
|   |       |   +-- Clean /tmp
|   |       |   +-- Then investigate root cause
|   |       +-- NO: Clean up methodically
|   |
|   +-- iot-device (smallest disk, most vulnerable)
|   |   +-- Check /tmp for agent workspace remnants
|   |   +-- Check journalctl --disk-usage
|   |   +-- sudo journalctl --vacuum-size=50M
|   |
|   +-- Other machine
|       +-- Check journalctl and /tmp
|       +-- Less critical, standard cleanup
|
+-- Is it recurring?
    +-- YES: Root cause not addressed
    |   +-- Add monitoring/alerting
    |   +-- Configure log rotation
    |   +-- Add disk limits to services
    |
    +-- NO: One-time incident
        +-- Clean up and document
```

## Prevention and Ongoing Maintenance

### Log Rotation for Wazuh

```bash
# Create logrotate config for Wazuh alerts
ssh broker-server "sudo tee /etc/logrotate.d/wazuh-alerts << 'CONF'
/opt/wazuh-data/logs/alerts/alerts.json {
    daily
    rotate 3
    compress
    delaycompress
    missingok
    notifempty
    size 500M
    copytruncate
}
CONF"
```

### Docker Log Limits

```bash
# Set default log limits for all Docker containers
ssh broker-server "sudo tee /etc/docker/daemon.json << 'CONF'
{
  \"log-driver\": \"json-file\",
  \"log-opts\": {
    \"max-size\": \"50m\",
    \"max-file\": \"3\"
  }
}
CONF
sudo systemctl restart docker"
```

### Journal Size Limits

```bash
# Limit journal to 500MB
ssh broker-server "sudo sed -i 's/#SystemMaxUse=/SystemMaxUse=500M/' /etc/systemd/journald.conf"
ssh broker-server "sudo systemctl restart systemd-journald"
```

## Monitoring Gaps Summary

| Gap | Severity | Status | Remediation |
|-----|----------|--------|-------------|
| No NATS MaxBytes limit | **CRITICAL** | NOT IMPLEMENTED | Add MaxBytes to StreamConfig in nats.go (see NATS_FLOOD playbook) |
| No Wazuh log rotation | **HIGH** | NOT VERIFIED | Check if logrotate is configured for /opt/wazuh-data/logs/ |
| No Docker log size limits | **HIGH** | NOT VERIFIED | Check /etc/docker/daemon.json for log-opts |
| No daemon workspace cleanup | **HIGH** | NOT IMPLEMENTED | Supervisor should rm -rf workspace after each run, or limit workspace size |
| No disk usage alerting beyond gridwatch | **MEDIUM** | PARTIAL | Gridwatch ticker fires at 85%, but no email alert or NATS event |
| Syncthing can sync arbitrarily large files | **MEDIUM** | BY DESIGN | Consider .stignore patterns for large binary files |
| No /tmp size limit | **MEDIUM** | NOT IMPLEMENTED | Consider tmpfs mount with size limit for /tmp on broker-server |

## Hardening Recommendations

1. **Add NATS stream MaxBytes.** See NATS_FLOOD playbook -- add `MaxBytes: 256 * 1024 * 1024` to the stream config.

2. **Configure Docker log rotation.** Set `max-size` and `max-file` in Docker daemon config to prevent container logs from growing unbounded.

3. **Add Wazuh log rotation.** Configure logrotate for alerts.json with a 500 MB size trigger and 3 rotations.

4. **Clean daemon workspaces.** After each daemon completes in supervisor.go, delete the workspace directory. Or better: use a tmpfs mount with a 100 MB size limit.

5. **Add disk-based alerting.** When disk exceeds 85%, publish a `fleet.security.disk` event to NATS so the security pipeline and response daemon can act (e.g., auto-purge NATS stream, auto-clean Docker).

6. **Set journal size limits.** Configure systemd-journald to cap at 500 MB on all fleet machines.
