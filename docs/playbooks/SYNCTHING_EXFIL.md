# Playbook: Syncthing Data Exfiltration

**System:** Sontara Lattice (claude-peers) fleet
**Last updated:** 2026-03-28
**Audience:** the operator (fleet operator)
**Severity tier:** Tier 3 (Approval Required) -- data exfiltration via trusted sync channel

---

## Table of Contents

1. [Attack Model](#attack-model)
2. [What Gets Exfiltrated](#what-gets-exfiltrated)
3. [Detection Signals](#detection-signals)
4. [Immediate Triage (0-5 minutes)](#immediate-triage)
5. [Investigation](#investigation)
6. [Containment](#containment)
7. [Recovery](#recovery)
8. [Decision Tree](#decision-tree)
9. [Monitoring Gaps](#monitoring-gaps)
10. [Hardening Recommendations](#hardening-recommendations)

---

## Attack Model

Syncthing runs between workstation (<workstation-ip>) and broker-server (<broker-ip>) syncing three folder pairs:

| Folder | Content | Sensitivity |
|--------|---------|-------------|
| `~/projects/` | All source code including claude-peers, client projects | **CRITICAL** -- full codebase, Wazuh rules, fleet architecture |
| `~/hfl-projects/` | Human Frontier Labs client projects | **CRITICAL** -- client IP, contracts, business logic |
| `~/ricing-resources/` | Theme assets, wallpapers | LOW |

### Attack Vector 1: Rogue Device Addition

1. Attacker gains write access to Syncthing config on workstation or broker-server
2. Attacker adds their device ID to Syncthing's device list
3. Attacker shares one or more folders with their device
4. Syncthing begins syncing data to the attacker's machine over any network path

Syncthing config lives at:
- workstation: `~/.local/state/syncthing/config.xml` (or `~/.config/syncthing/config.xml`)
- broker-server: `~/.local/state/syncthing/config.xml`

The Syncthing API listens on `http://localhost:8384` by default. If the API has no auth or weak auth, any local process can modify the config.

### Attack Vector 2: Rogue Folder Share

1. Attacker adds a new folder to Syncthing pointing at sensitive directories
2. Shares it with the attacker's device or even with the existing peer (broker-server)
3. Sensitive dirs like `~/.ssh/`, `~/.config/claude-peers/`, `~/.gnupg/` get synced

### Attack Vector 3: Syncthing API Exploitation

1. Syncthing API on port 8384 is accessible from localhost
2. Any compromised process (daemon, Claude session, rogue script) can call:
   ```
   curl -X POST http://localhost:8384/rest/config/devices \
     -H "X-API-Key: <key>" \
     -d '{"deviceID":"ATTACKER-DEVICE-ID","name":"backup"}'
   ```
3. No external network access needed -- just localhost API access

### Detection Timeline

| Event | Time | Detection |
|-------|------|-----------|
| Config modified | T+0 | **NONE** -- Syncthing config is NOT monitored by Wazuh FIM |
| Device added | T+0 | **NONE** -- no Syncthing device list monitoring exists |
| Sync begins | T+seconds | **NONE** -- Syncthing traffic looks like normal sync |
| Data on attacker machine | T+minutes | **NONE** -- no outbound data volume monitoring |

**CRITICAL GAP: There is currently ZERO automated detection for Syncthing config changes.** The Wazuh syscheck configuration does not monitor Syncthing config paths. An attacker could add a device and exfiltrate the entire `~/projects/` tree without triggering a single alert.

---

## What Gets Exfiltrated

If the attacker syncs `~/projects/`:

| Asset | Location | Impact |
|-------|----------|--------|
| Sontara Lattice source | `~/projects/claude-peers/` | Full fleet architecture, all Wazuh rules, all playbooks, all IPs, UCAN auth implementation |
| Wazuh config | `~/projects/claude-peers/wazuh/` | Every monitored path, every rule ID, every detection gap |
| Daemon definitions | `~/projects/claude-peers/daemons/` | All daemon prompts, LLM interactions, security analysis patterns |
| Client projects | `~/hfl-projects/` | Client source code, business logic, credentials in .env files |
| Deploy scripts | `~/projects/claude-peers/deploy.sh` | Deployment procedures, server access patterns |

If the attacker adds `~/.ssh/` as a new folder:

| Asset | Impact |
|-------|--------|
| `~/.ssh/id_*` | Private SSH keys for all fleet machines |
| `~/.ssh/config` | SSH aliases, jump hosts, port forwards |
| `~/.ssh/authorized_keys` | Which keys have access (reconnaissance) |

If the attacker adds `~/.config/claude-peers/`:

| Asset | Impact |
|-------|--------|
| `identity.pem` | Machine's UCAN private key -- can impersonate on broker |
| `token.jwt` | Signed JWT with API capabilities |
| `config.json` | Broker URL, NATS URL, LLM endpoint, NATS token |

---

## Detection Signals

### Primary: Syncthing API Audit (Manual)

```bash
# Check device list on workstation
curl -s -H "X-API-Key: $(grep apikey ~/.local/state/syncthing/config.xml 2>/dev/null | sed 's/.*<apikey>\(.*\)<\/apikey>/\1/')" \
  http://localhost:8384/rest/config/devices 2>/dev/null | python3 -c "
import json, sys
devices = json.load(sys.stdin)
print(f'Total devices: {len(devices)}')
for d in devices:
    print(f'  {d[\"name\"]:20s} ID={d[\"deviceID\"][:16]}...')
"

# Check folder list on workstation
curl -s -H "X-API-Key: $(grep apikey ~/.local/state/syncthing/config.xml 2>/dev/null | sed 's/.*<apikey>\(.*\)<\/apikey>/\1/')" \
  http://localhost:8384/rest/config/folders 2>/dev/null | python3 -c "
import json, sys
folders = json.load(sys.stdin)
print(f'Total folders: {len(folders)}')
for f in folders:
    devices = [d['deviceID'][:16] for d in f.get('devices', [])]
    print(f'  {f[\"label\"]:20s} path={f[\"path\"]}  shared_with={len(devices)} devices')
"
```

### Secondary: Syncthing Logs

```bash
# Check Syncthing logs for device connection events
journalctl --user -u syncthing --since "24 hours ago" --no-pager 2>/dev/null | grep -iE 'device|connect|added|folder' | tail -20

# Or check the log file directly
cat ~/.local/state/syncthing/syncthing.log 2>/dev/null | grep -iE 'device|connect|added' | tail -20
```

### Tertiary: Network Traffic Anomalies

```bash
# Check for Syncthing connections to unexpected IPs
# Syncthing uses TCP port 22000 for data transfer
ss -tnp | grep syncthing | grep -v '100\.' | grep -v '127\.'
# Any connections NOT to Tailscale IPs (100.x.x.x) or localhost are suspicious
```

---

## Immediate Triage (0-5 minutes)

### Step 1: Check current Syncthing device list on both machines

```bash
# On workstation
APIKEY=$(grep apikey ~/.local/state/syncthing/config.xml 2>/dev/null | sed 's/.*<apikey>\(.*\)<\/apikey>/\1/')
echo "=== WORKSTATION DEVICES ==="
curl -s -H "X-API-Key: $APIKEY" http://localhost:8384/rest/config/devices | python3 -c "
import json, sys
for d in json.load(sys.stdin):
    print(f'  {d[\"deviceID\"][:20]}... name={d.get(\"name\",\"\")}')
"

# On broker-server
echo "=== BROKER-SERVER DEVICES ==="
ssh broker-server "
APIKEY=\$(grep apikey ~/.local/state/syncthing/config.xml 2>/dev/null | sed 's/.*<apikey>\(.*\)<\/apikey>/\1/')
curl -s -H \"X-API-Key: \$APIKEY\" http://localhost:8384/rest/config/devices | python3 -c \"
import json, sys
for d in json.load(sys.stdin):
    print(f'  {d[\\\"deviceID\\\"][:20]}... name={d.get(\\\"name\\\",\\\"\\\")}')
\"
"
```

### Step 2: Check folder list for unexpected shares

```bash
# On workstation
APIKEY=$(grep apikey ~/.local/state/syncthing/config.xml 2>/dev/null | sed 's/.*<apikey>\(.*\)<\/apikey>/\1/')
curl -s -H "X-API-Key: $APIKEY" http://localhost:8384/rest/config/folders | python3 -c "
import json, sys
EXPECTED_PATHS = {'projects', 'hfl-projects', 'ricing-resources'}
folders = json.load(sys.stdin)
for f in folders:
    label = f.get('label', '')
    path = f.get('path', '')
    shared = len(f.get('devices', []))
    # Flag anything not in expected list
    is_known = any(e in path or e in label for e in EXPECTED_PATHS)
    prefix = 'OK' if is_known else 'SUSPICIOUS'
    print(f'  [{prefix}] {label}: {path} (shared with {shared} devices)')
"
```

### Step 3: Stop Syncthing immediately if rogue device found

```bash
# On workstation
systemctl --user stop syncthing

# On broker-server
ssh broker-server "systemctl --user stop syncthing"
```

---

## Investigation

### Determine when the rogue device was added

```bash
# Check config.xml modification time
stat ~/.local/state/syncthing/config.xml
ssh broker-server "stat ~/.local/state/syncthing/config.xml"

# Check Syncthing's internal database for connection history
ls -la ~/.local/state/syncthing/index-v0.14.0.db/

# Review Syncthing logs for the first connection from the rogue device
grep "<rogue-device-id-prefix>" ~/.local/state/syncthing/syncthing.log 2>/dev/null
ssh broker-server "grep '<rogue-device-id-prefix>' ~/.local/state/syncthing/syncthing.log 2>/dev/null"
```

### Determine what data was synced

```bash
# Check Syncthing's completion status for the rogue device
APIKEY=$(grep apikey ~/.local/state/syncthing/config.xml 2>/dev/null | sed 's/.*<apikey>\(.*\)<\/apikey>/\1/')
# Replace ROGUE_DEVICE_ID with the actual device ID
curl -s -H "X-API-Key: $APIKEY" \
  "http://localhost:8384/rest/db/completion?device=ROGUE_DEVICE_ID" 2>/dev/null | python3 -m json.tool

# Check which folders were shared with the rogue device
curl -s -H "X-API-Key: $APIKEY" http://localhost:8384/rest/config/folders | python3 -c "
import json, sys
ROGUE_ID = 'ROGUE_DEVICE_ID'  # Replace
for f in json.load(sys.stdin):
    device_ids = [d['deviceID'] for d in f.get('devices', [])]
    if ROGUE_ID in device_ids:
        print(f'  SHARED: {f[\"label\"]} -> {f[\"path\"]}')
"
```

### Check how the device was added (compromise vector)

```bash
# Was the Syncthing API accessed from a non-local process?
# Check for API key leakage
grep -r "X-API-Key\|apikey" ~/.bash_history ~/.zsh_history 2>/dev/null

# Check if Syncthing GUI was exposed beyond localhost
grep -A2 'gui' ~/.local/state/syncthing/config.xml | grep address
# Should be 127.0.0.1:8384 -- if 0.0.0.0:8384, the GUI was exposed to the network

# Check if the API key is in any synced files (circular exposure)
grep -r "$(grep apikey ~/.local/state/syncthing/config.xml 2>/dev/null | sed 's/.*<apikey>\(.*\)<\/apikey>/\1/')" ~/projects/ 2>/dev/null
```

### Full fleet audit -- check all machines that run Syncthing

```bash
for machine in workstation broker-server; do
  echo "=== $machine ==="
  if [ "$machine" = "workstation" ]; then
    APIKEY=$(grep apikey ~/.local/state/syncthing/config.xml 2>/dev/null | sed 's/.*<apikey>\(.*\)<\/apikey>/\1/')
    curl -s -H "X-API-Key: $APIKEY" http://localhost:8384/rest/config/devices 2>/dev/null | python3 -c "import json,sys; [print(f'  {d[\"deviceID\"][:20]}... {d.get(\"name\",\"\")}') for d in json.load(sys.stdin)]"
  else
    ssh $machine "
      APIKEY=\$(grep apikey ~/.local/state/syncthing/config.xml 2>/dev/null | sed 's/.*<apikey>\(.*\)<\/apikey>/\1/')
      curl -s -H \"X-API-Key: \$APIKEY\" http://localhost:8384/rest/config/devices 2>/dev/null | python3 -c \"import json,sys; [print(f'  {d[\\\"deviceID\\\"][:20]}... {d.get(\\\"name\\\",\\\"\\\")}') for d in json.load(sys.stdin)]\"
    " 2>/dev/null
  fi
done
```

---

## Containment

### Step 1: Remove the rogue device from Syncthing config

```bash
# On workstation -- remove device via API
APIKEY=$(grep apikey ~/.local/state/syncthing/config.xml 2>/dev/null | sed 's/.*<apikey>\(.*\)<\/apikey>/\1/')
# First, get current config
curl -s -H "X-API-Key: $APIKEY" http://localhost:8384/rest/config > /tmp/syncthing-config-backup.json

# Remove the rogue device (replace ROGUE_DEVICE_ID)
curl -s -H "X-API-Key: $APIKEY" http://localhost:8384/rest/config | python3 -c "
import json, sys
ROGUE_ID = 'ROGUE_DEVICE_ID'  # Replace
config = json.load(sys.stdin)
config['devices'] = [d for d in config['devices'] if d['deviceID'] != ROGUE_ID]
for folder in config['folders']:
    folder['devices'] = [d for d in folder['devices'] if d['deviceID'] != ROGUE_ID]
json.dump(config, sys.stdout)
" | curl -s -X PUT -H "X-API-Key: $APIKEY" -H "Content-Type: application/json" \
  -d @- http://localhost:8384/rest/config

# Repeat on broker-server
ssh broker-server "
APIKEY=\$(grep apikey ~/.local/state/syncthing/config.xml 2>/dev/null | sed 's/.*<apikey>\(.*\)<\/apikey>/\1/')
curl -s -H \"X-API-Key: \$APIKEY\" http://localhost:8384/rest/config | python3 -c \"
import json, sys
ROGUE_ID = 'ROGUE_DEVICE_ID'
config = json.load(sys.stdin)
config['devices'] = [d for d in config['devices'] if d['deviceID'] != ROGUE_ID]
for folder in config['folders']:
    folder['devices'] = [d for d in folder['devices'] if d['deviceID'] != ROGUE_ID]
json.dump(config, sys.stdout)
\" | curl -s -X PUT -H \"X-API-Key: \$APIKEY\" -H 'Content-Type: application/json' \
  -d @- http://localhost:8384/rest/config
"
```

### Step 2: Remove any rogue folder shares

```bash
# If attacker added a folder share for ~/.ssh/ or ~/.config/claude-peers/:
APIKEY=$(grep apikey ~/.local/state/syncthing/config.xml 2>/dev/null | sed 's/.*<apikey>\(.*\)<\/apikey>/\1/')

# List and remove suspicious folders
curl -s -H "X-API-Key: $APIKEY" http://localhost:8384/rest/config/folders | python3 -c "
import json, sys
SAFE_LABELS = {'projects', 'hfl-projects', 'ricing-resources'}
for f in json.load(sys.stdin):
    if f.get('label', '') not in SAFE_LABELS:
        print(f'REMOVE: {f[\"id\"]} ({f[\"label\"]}: {f[\"path\"]})')
"
# For each suspicious folder ID:
# curl -X DELETE -H "X-API-Key: $APIKEY" "http://localhost:8384/rest/config/folders/<folder-id>"
```

### Step 3: Pause all sync until investigation is complete

```bash
# Pause all folders (non-destructive)
APIKEY=$(grep apikey ~/.local/state/syncthing/config.xml 2>/dev/null | sed 's/.*<apikey>\(.*\)<\/apikey>/\1/')
curl -s -H "X-API-Key: $APIKEY" http://localhost:8384/rest/config/folders | python3 -c "
import json, sys
for f in json.load(sys.stdin):
    f['paused'] = True
    print(json.dumps(f))
" | while read -r folder; do
  FOLDER_ID=$(echo "$folder" | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
  curl -s -X PUT -H "X-API-Key: $APIKEY" -H "Content-Type: application/json" \
    -d "$folder" "http://localhost:8384/rest/config/folders/$FOLDER_ID"
done
```

---

## Recovery

### Step 1: Rotate Syncthing API keys

```bash
# Generate new API key on workstation
APIKEY=$(grep apikey ~/.local/state/syncthing/config.xml 2>/dev/null | sed 's/.*<apikey>\(.*\)<\/apikey>/\1/')
NEW_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
curl -s -H "X-API-Key: $APIKEY" http://localhost:8384/rest/config | python3 -c "
import json, sys
config = json.load(sys.stdin)
config['gui']['apiKey'] = '$NEW_KEY'
json.dump(config, sys.stdout)
" | curl -s -X PUT -H "X-API-Key: $APIKEY" -H "Content-Type: application/json" \
  -d @- http://localhost:8384/rest/config
echo "New API key: $NEW_KEY"

# Repeat on broker-server
```

### Step 2: Assess exposure and rotate secrets

Based on what folders were shared with the rogue device:

| Folder Shared | Secrets to Rotate |
|--------------|-------------------|
| `~/projects/` | GitHub tokens (if in .env files), any API keys in source |
| `~/hfl-projects/` | All client API keys, database credentials, .env contents |
| `~/.ssh/` | **ALL SSH keys on ALL fleet machines** + regenerate authorized_keys |
| `~/.config/claude-peers/` | UCAN keypair + token on affected machine (see CREDENTIAL_THEFT playbook) |
| `~/.gnupg/` | GPG keys -- revoke and regenerate |

### Step 3: Resume sync after cleanup

```bash
# Unpause folders
APIKEY=$(grep apikey ~/.local/state/syncthing/config.xml 2>/dev/null | sed 's/.*<apikey>\(.*\)<\/apikey>/\1/')
curl -s -H "X-API-Key: $APIKEY" http://localhost:8384/rest/config/folders | python3 -c "
import json, sys
for f in json.load(sys.stdin):
    f['paused'] = False
    print(json.dumps(f))
" | while read -r folder; do
  FOLDER_ID=$(echo "$folder" | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
  curl -s -X PUT -H "X-API-Key: $APIKEY" -H "Content-Type: application/json" \
    -d "$folder" "http://localhost:8384/rest/config/folders/$FOLDER_ID"
done
```

---

## Decision Tree

```
Syncthing exfiltration suspected
|
+-- How was it detected?
|   +-- Manual audit found unknown device
|   +-- Unusual network traffic to non-Tailscale IP
|   +-- Compromised machine investigation revealed Syncthing config change
|
+-- Is Syncthing still running?
|   +-- YES: Stop immediately on both workstation and broker-server
|   +-- NO: Proceed to investigation
|
+-- Are there unknown devices in the device list?
|   +-- YES: unknown device present
|   |   +-- Check when device was added (config.xml mtime, logs)
|   |   +-- Check which folders are shared with it
|   |   +-- Check Syncthing completion API for sync progress
|   |   +-- Was sync 100% complete?
|   |   |   +-- YES: attacker has full copy. Treat as full data breach.
|   |   |   +-- NO: partial exfil. Still treat as breach for affected files.
|   |   +-- Remove device, rotate secrets per exposure table above
|   |
|   +-- NO: devices look clean
|       +-- Were there rogue FOLDER shares? (e.g., ~/.ssh/ added as sync folder)
|       +-- Was the config.xml recently modified? (check mtime)
|       +-- Check if attacker removed their device after exfil to cover tracks
|       +-- Review Syncthing logs for historical connections
|
+-- How did the attacker modify Syncthing config?
    +-- Local process compromise (daemon, Claude session with bash access)
    +-- SSH access to the machine
    +-- Syncthing GUI exposed beyond localhost (check gui address in config)
    +-- API key leaked in synced files or shell history
```

---

## Monitoring Gaps

| Gap | Severity | Status | Remediation |
|-----|----------|--------|-------------|
| **Syncthing config NOT monitored by Wazuh FIM** | **CRITICAL** | NOT IMPLEMENTED | Add `~/.local/state/syncthing/config.xml` to syscheck with realtime monitoring |
| **No Syncthing device list change alerts** | **CRITICAL** | NOT IMPLEMENTED | Periodic script to hash device list and alert on changes |
| **No outbound data volume monitoring** | **HIGH** | NOT IMPLEMENTED | Monitor Syncthing transfer stats via API, alert on transfers to unknown devices |
| **Syncthing API key stored in plaintext XML** | **MEDIUM** | ARCHITECTURAL | Syncthing limitation. Ensure config.xml is 0600 and monitored by FIM. |
| **No Syncthing GUI auth enforcement check** | **MEDIUM** | NOT IMPLEMENTED | Periodic check that GUI is bound to 127.0.0.1 and has auth enabled |

---

## Hardening Recommendations

1. **Add Syncthing config to Wazuh FIM.** In `shared_agent.conf`, add:
   ```xml
   <directories check_all="yes" realtime="yes" report_changes="yes">~/.local/state/syncthing/config.xml</directories>
   ```
   And a corresponding Wazuh rule for level 12 (critical) when this file changes.

2. **Periodic Syncthing device audit.** Create a cron job or daemon that:
   - Queries `http://localhost:8384/rest/config/devices` every 5 minutes
   - Compares against a known-good device list
   - Publishes a security alert to NATS if unknown devices appear

3. **Restrict Syncthing GUI to localhost.** Verify the GUI address is `127.0.0.1:8384` and not `0.0.0.0:8384`. Check this in the periodic audit.

4. **File permission hardening.** Ensure Syncthing config is readable only by the owner:
   ```bash
   chmod 600 ~/.local/state/syncthing/config.xml
   ```

5. **Consider Syncthing device allowlisting.** Configure `autoAcceptFolders: false` and manually verify every device addition.
