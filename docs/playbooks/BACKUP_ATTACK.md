# Backup Failure and Ransomware Incident Response Playbook

**System:** Sontara Lattice (claude-peers) fleet
**Last updated:** 2026-03-28
**Audience:** the operator (fleet operator)
**Severity tier:** Tier 3 (Approval Required) -- total fleet state loss scenario

---

## Table of Contents

1. [Attack Model](#attack-model)
2. [Detection](#detection)
3. [Immediate Triage (0-5 minutes)](#immediate-triage)
4. [Containment](#containment)
5. [Investigation](#investigation)
6. [Recovery](#recovery)
7. [Post-Incident Hardening](#post-incident-hardening)
8. [Backup Strategy Design](#backup-strategy-design)
9. [Monitoring Gaps](#monitoring-gaps)

---

## Attack Model

### Current State: No Backup Strategy

The Sontara Lattice fleet has **no documented or automated backup strategy**. All fleet state -- identity keys, broker database, Wazuh rules, daemon definitions, NATS stream data, configuration files -- lives on individual machines with no offsite copy. A single disk failure on broker-server or a ransomware attack would result in permanent data loss for critical infrastructure.

### What lives where

| Machine | Critical Data | Rebuildable? |
|---------|--------------|--------------|
| broker-server (<broker-ip>) | Broker DB (peer registry, fleet state), NATS JetStream data, Wazuh manager config + custom rules (`local_rules.xml`), daemon definitions, LiteLLM config, Docker volumes, root identity keypair | **NO** -- broker DB, Wazuh custom rules, and NATS streams are unique. Root identity.pem is the master trust anchor. |
| workstation (<workstation-ip>) | Source code (`~/projects/`), claude-peers binaries, identity.pem, config files | Partially -- code is in Git, but local uncommitted work and config are not backed up |
| edge-node (Pi 5) | Gridwatch config, kiosk setup, identity.pem | Mostly -- can be re-provisioned, but identity key would need re-issuance |
| workstation-2 (<workstation-2-ip>) | Identity.pem, config | Fully rebuildable |
| laptop-1 (<laptop-1-ip>) | Identity.pem, config, HFL project data | Partially -- Time Machine may exist but is not confirmed |
| iot-device (<iot-device-ip>) | Identity.pem, sontara-lite config, SD card | Rebuildable except identity key |
| laptop-2 (<laptop-2-ip>) | LLM models, config | Not the operator's machine -- no control |

### Attack Scenario A: Ransomware on broker-server

```
1. Attacker gains root on broker-server (via SSH, container escape, or daemon exploit)
2. Encrypts ~/, Docker volumes, /opt/wazuh-data/
3. Broker is gone -- no peer registry, no fleet coordination
4. NATS JetStream data is gone -- all event history lost
5. Wazuh manager is gone -- all custom detection rules, agent enrollment data lost
6. Daemon definitions are gone -- all AI daemon configs lost
7. Root identity.pem is gone -- entire trust chain is broken, no new tokens can be issued
```

### Attack Scenario B: Disk Failure on broker-server

Same outcome as ransomware but without the attacker. SD card failure on Pi devices is even more likely given flash wear.

### Attack Scenario C: Targeted Deletion

Attacker with shell access selectively deletes high-value files to cripple the fleet without triggering obvious ransomware detection:

```
rm -f ~/.config/claude-peers/identity.pem   # Kills trust chain
rm -rf ~/docker/wazuh/                       # Kills security monitoring
nats stream purge -f fleet-events            # Kills event history
```

### What can be rebuilt vs. what is gone forever

| Asset | Without Backup | Recovery Difficulty |
|-------|---------------|-------------------|
| identity.pem (root key) | **GONE FOREVER** -- new root key means all existing UCAN tokens are invalid, entire fleet must be re-credentialed | Critical |
| Broker DB (peer registry) | Lost -- machines must re-register, fleet state history gone | High |
| Wazuh custom rules (local_rules.xml) | Lost -- all Sontara Lattice-specific detection rules must be rewritten from memory or docs | High |
| NATS JetStream data | Lost -- all fleet event history, daemon messages, security events gone | Medium (operational, not security-critical) |
| Daemon definitions | Lost if not in Git -- all daemon prompts, trigger configs, routing rules | Medium-High |
| Docker compose configs | Recoverable if in Git, lost if only on disk | Medium |
| Machine identity keys (per-machine) | Can be regenerated, but need new UCAN tokens from root | Low (if root key exists) |
| Source code | Recoverable from GitHub (if pushed) | Low |
| claude-peers binary | Rebuildable from source | Low |

---

## Detection

### Signs of ransomware

```bash
# On broker-server: check for encrypted files or ransom notes
ssh broker-server "
echo '=== Checking for ransomware indicators ==='
# Common ransomware extensions
find /home/user -name '*.encrypted' -o -name '*.locked' -o -name '*.crypt' -o -name '*.ransom' 2>/dev/null | head -20

# Ransom notes
find /home/user -name 'README*RANSOM*' -o -name '*DECRYPT*' -o -name '*RECOVER*' 2>/dev/null | head -10

# Mass file modification (all files changed within a short window)
echo '=== Files modified in last 10 minutes ==='
find /home/user -maxdepth 3 -mmin -10 -type f 2>/dev/null | wc -l

# Check if critical files are readable
echo '=== Critical file integrity ==='
cat ~/.config/claude-peers/identity.pem > /dev/null 2>&1 && echo 'identity.pem: OK' || echo 'identity.pem: UNREADABLE'
cat ~/.config/claude-peers/config.json > /dev/null 2>&1 && echo 'config.json: OK' || echo 'config.json: UNREADABLE'
docker ps > /dev/null 2>&1 && echo 'Docker: running' || echo 'Docker: DOWN'
"
```

### Signs of disk failure

```bash
# Check disk health on broker-server
ssh broker-server "
echo '=== Disk Health ==='
sudo smartctl -H /dev/sda 2>/dev/null || echo 'smartctl not available'
df -h /home/user
echo '=== dmesg disk errors ==='
dmesg | grep -i 'error\|fail\|i/o' | grep -i 'sd\|nvme\|disk\|ata' | tail -10
echo '=== Filesystem errors ==='
dmesg | grep -i 'ext4\|btrfs\|xfs' | grep -i 'error\|corrupt' | tail -10
"

# Check Pi SD card health
ssh edge-node "dmesg | grep -i 'mmc\|error' | tail -10"
ssh iot-device "dmesg | grep -i 'mmc\|error' | tail -10" 2>/dev/null
```

### Fleet-wide critical file audit

```bash
echo "=== Fleet Critical File Audit ==="
for machine in "<workstation-ip>" "broker-server" "edge-node" "<workstation-2-ip>" "<user>@<laptop-1-ip><laptop-1-ip>" "<iot-device-ip>"; do
    echo "--- $machine ---"
    ssh -o ConnectTimeout=5 $machine "
        ls -la ~/.config/claude-peers/identity.pem 2>/dev/null || echo 'MISSING: identity.pem'
        ls -la ~/.config/claude-peers/token.jwt 2>/dev/null || echo 'MISSING: token.jwt'
        ls -la ~/.config/claude-peers/config.json 2>/dev/null || echo 'MISSING: config.json'
    " 2>/dev/null || echo "UNREACHABLE"
done
```

---

## Immediate Triage (0-5 minutes)

### Step 1: Assess what is still running

```bash
# Check if broker is responding
curl -sf http://<broker-ip>:7899/health && echo "Broker: UP" || echo "Broker: DOWN"

# Check if NATS is responding
curl -sf http://<broker-ip>:8222/varz | head -5 && echo "NATS: UP" || echo "NATS: DOWN"

# Check Wazuh
ssh broker-server "docker ps --filter name=wazuh-manager --format '{{.Status}}'" 2>/dev/null || echo "Wazuh: UNKNOWN"

# Check if workstation (build machine) is intact
ls ~/.config/claude-peers/identity.pem && echo "Local identity: OK" || echo "Local identity: MISSING"
```

### Step 2: If ransomware -- isolate immediately

```bash
# Disconnect broker-server from the network to prevent spread
ssh broker-server "sudo tailscale down" 2>/dev/null
# If SSH is already dead, physically disconnect the machine
echo "If SSH fails: physically pull the network cable from broker-server"
```

### Step 3: Preserve what you can reach

```bash
# Emergency backup of critical files from all reachable machines
EMERGENCY_DIR="/tmp/emergency-backup-$(date +%Y%m%d%H%M%S)"
mkdir -p "$EMERGENCY_DIR"

for machine in "<workstation-ip>" "edge-node" "<workstation-2-ip>" "<user>@<laptop-1-ip><laptop-1-ip>" "<iot-device-ip>"; do
    mkdir -p "$EMERGENCY_DIR/$machine"
    scp -o ConnectTimeout=5 $machine:~/.config/claude-peers/identity.pem "$EMERGENCY_DIR/$machine/" 2>/dev/null
    scp -o ConnectTimeout=5 $machine:~/.config/claude-peers/config.json "$EMERGENCY_DIR/$machine/" 2>/dev/null
    scp -o ConnectTimeout=5 $machine:~/.config/claude-peers/token.jwt "$EMERGENCY_DIR/$machine/" 2>/dev/null
done

echo "Emergency backup saved to $EMERGENCY_DIR"
ls -laR "$EMERGENCY_DIR"
```

---

## Containment

### Ransomware containment

```bash
# 1. Isolate broker-server completely
ssh broker-server "sudo tailscale down; sudo systemctl stop docker" 2>/dev/null

# 2. Stop all fleet services that depend on broker-server
for machine in "<workstation-ip>" "edge-node" "<workstation-2-ip>" "<user>@<laptop-1-ip><laptop-1-ip>" "<iot-device-ip>"; do
    ssh -o ConnectTimeout=5 $machine "pkill -f claude-peers 2>/dev/null; pkill -f sontara 2>/dev/null" &
done
wait

# 3. Check if ransomware has spread via Syncthing
# Syncthing syncs ~/projects/ between workstation and broker-server
# If encrypted files synced to workstation, they could overwrite good copies
ls ~/projects/ | head -20
# Look for encrypted or corrupted files
find ~/projects/ -name '*.encrypted' -o -name '*.locked' 2>/dev/null | head -10
```

### Disk failure containment

```bash
# If disk is failing but partially readable, emergency copy EVERYTHING
ssh broker-server "
# Priority order: most critical first
tar czf /tmp/critical-backup.tar.gz \
    ~/.config/claude-peers/ \
    ~/docker/wazuh/config/ \
    ~/.config/sontara-lattice/ \
    2>/dev/null
echo 'Critical backup size:' && ls -lh /tmp/critical-backup.tar.gz
" 2>/dev/null

# Pull it off the dying disk immediately
scp broker-server:/tmp/critical-backup.tar.gz /tmp/ 2>/dev/null
```

---

## Investigation

### Ransomware forensics

```bash
# If broker-server is still partially accessible
ssh broker-server "
echo '=== Recent logins ==='
last -20

echo '=== Process tree ==='
ps auxf | head -50

echo '=== Network connections ==='
ss -tlnp

echo '=== Recently modified executables ==='
find /usr/bin /usr/sbin ~/.local/bin -mtime -1 2>/dev/null | head -20

echo '=== Crontab ==='
crontab -l 2>/dev/null

echo '=== Systemd user services ==='
systemctl --user list-units --type=service --all 2>/dev/null | head -20

echo '=== Docker container changes ==='
docker diff wazuh-manager 2>/dev/null | head -20
"
```

### Determine attack vector

```bash
# Check how the attacker got in
ssh broker-server "
echo '=== SSH auth log ==='
journalctl -u sshd --since '7 days ago' --no-pager | grep -i 'accepted\|failed' | tail -30

echo '=== Tailscale connections ==='
journalctl -u tailscaled --since '7 days ago' --no-pager | tail -20

echo '=== Docker logs ==='
docker logs wazuh-manager --since 168h 2>&1 | tail -20
"
```

---

## Recovery

### Recovery WITHOUT backups (current state)

This is the hard path. With no backups, recovery requires rebuilding from scratch.

#### Step 1: Rebuild broker-server

```bash
# Reinstall Ubuntu 24.04 on broker-server
# After fresh install:

# 1. Install Tailscale and rejoin the tailnet
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up

# 2. Generate NEW root identity (old trust chain is gone)
# Install claude-peers from source on workstation, scp binary to broker-server
cd ~/projects/claude-peers && go build -o claude-peers . && scp claude-peers broker-server:~/.local/bin/

# 3. Initialize broker with new root key
ssh broker-server "claude-peers init broker"
# This generates a new identity.pem (root key) and config.json

# 4. Reinstall NATS
ssh broker-server "
# Install nats-server (follow official docs for Ubuntu)
# Configure with new token
"

# 5. Reinstall Docker and Wazuh
ssh broker-server "
sudo apt install docker.io docker-compose-v2
# Re-deploy Wazuh stack
# NOTE: All custom rules (local_rules.xml) must be rewritten
"

# 6. Re-deploy LiteLLM
# 7. Re-deploy daemon supervisor
```

#### Step 2: Re-credential all fleet machines

```bash
# Every machine needs a new UCAN token from the new root key
for machine in "<workstation-ip>" "edge-node" "<workstation-2-ip>" "<user>@<laptop-1-ip><laptop-1-ip>" "<iot-device-ip>"; do
    echo "Re-credentialing $machine..."
    ssh -o ConnectTimeout=5 $machine "
        if [ -f ~/.config/claude-peers/identity.pem ]; then
            echo 'Identity exists, extracting public key'
            claude-peers show-pubkey
        else
            echo 'Identity missing, generating new keypair'
            claude-peers init client http://<broker-ip>:7899
        fi
    " 2>/dev/null
done
```

#### Step 3: Rebuild Wazuh rules from documentation

```bash
# The Sontara Lattice custom Wazuh rules were documented in:
# ~/projects/claude-peers/docs/ (if this survived on workstation via Git)
# Check what documentation exists:
ls ~/projects/claude-peers/docs/wazuh* 2>/dev/null
ls ~/projects/claude-peers/config/wazuh* 2>/dev/null
grep -r "local_rules" ~/projects/claude-peers/ 2>/dev/null | head -10
```

### Recovery WITH backups (target state)

```bash
# 1. Restore identity.pem from encrypted offsite backup
# 2. Restore broker DB
# 3. Restore Wazuh rules and agent enrollment
# 4. Restore NATS JetStream snapshots
# 5. Restore daemon definitions
# 6. Restart all services
# 7. Verify fleet health
```

---

## Post-Incident Hardening

### Implement the backup strategy described below

This is the single highest-impact hardening action for the entire fleet.

---

## Backup Strategy Design

### Tier 1: Critical (daily, encrypted, offsite)

These assets are **irreplaceable** if lost:

| Asset | Location | Backup Method | Frequency |
|-------|----------|---------------|-----------|
| Root identity.pem | broker-server:~/.config/claude-peers/identity.pem | Encrypted copy to workstation + USB drive | Daily + after any change |
| Broker DB | broker-server:~/.config/claude-peers/ (broker state) | Encrypted tarball to workstation via scp | Daily |
| Wazuh custom rules | broker-server:/opt/wazuh-data/etc/rules/local_rules.xml | Git-tracked in claude-peers repo + encrypted offsite | After any change |
| Wazuh agent enrollment | broker-server:/opt/wazuh-data/etc/client.keys | Encrypted copy to workstation | Daily |
| Daemon definitions | broker-server:~/.config/sontara-lattice/daemons/ | Git-tracked + encrypted offsite | After any change |

### Tier 2: Important (weekly, encrypted)

| Asset | Location | Backup Method | Frequency |
|-------|----------|---------------|-----------|
| NATS JetStream data | broker-server NATS data dir | NATS stream snapshot + encrypted copy | Weekly |
| Docker compose configs | broker-server:~/docker/ | Git-tracked | After any change |
| LiteLLM config | broker-server LiteLLM config dir | Git-tracked | After any change |
| Per-machine identity.pem | Each fleet machine | Encrypted copy to broker-server | After generation |
| Per-machine config.json | Each fleet machine | Encrypted copy to broker-server | After any change |

### Tier 3: Nice to have (monthly)

| Asset | Location | Backup Method | Frequency |
|-------|----------|---------------|-----------|
| Full Wazuh Docker volumes | broker-server | Docker volume export | Monthly |
| NATS full stream export | broker-server | `nats stream backup` | Monthly |

### Implementation: Automated backup script

```bash
#!/bin/bash
# ~/.local/bin/fleet-backup
# Run daily via cron or systemd timer

set -euo pipefail

BACKUP_DIR="~/fleet-backups/$(date +%Y%m%d)"
ENCRYPTION_KEY="~/.config/fleet-backup/backup.key"
REMOTE="broker-server"

mkdir -p "$BACKUP_DIR"

echo "=== Fleet Backup $(date) ==="

# Tier 1: Critical assets from broker-server
echo "Backing up critical assets..."
ssh $REMOTE "tar czf - \
    ~/.config/claude-peers/identity.pem \
    ~/.config/claude-peers/config.json \
    ~/.config/claude-peers/*.db \
    ~/.config/sontara-lattice/ \
    " 2>/dev/null | \
    openssl enc -aes-256-cbc -salt -pbkdf2 -pass file:"$ENCRYPTION_KEY" \
    -out "$BACKUP_DIR/critical.tar.gz.enc"

# Wazuh rules
ssh $REMOTE "docker exec wazuh-manager cat /var/ossec/etc/rules/local_rules.xml" 2>/dev/null | \
    openssl enc -aes-256-cbc -salt -pbkdf2 -pass file:"$ENCRYPTION_KEY" \
    -out "$BACKUP_DIR/wazuh-rules.xml.enc"

# Per-machine identity keys
for machine in "<workstation-ip>" "edge-node" "<workstation-2-ip>" "<user>@<laptop-1-ip><laptop-1-ip>" "<iot-device-ip>"; do
    MACHINE_NAME=$(echo "$machine" | tr '@:.' '-')
    ssh -o ConnectTimeout=5 $machine "cat ~/.config/claude-peers/identity.pem" 2>/dev/null | \
        openssl enc -aes-256-cbc -salt -pbkdf2 -pass file:"$ENCRYPTION_KEY" \
        -out "$BACKUP_DIR/identity-${MACHINE_NAME}.pem.enc" 2>/dev/null || true
done

# Rotate: keep 30 days of backups
find ~/fleet-backups/ -maxdepth 1 -type d -mtime +30 -exec rm -rf {} \;

echo "Backup complete: $BACKUP_DIR"
ls -lh "$BACKUP_DIR"
```

### Offsite backup (encrypted USB or remote)

```bash
# Monthly: copy to encrypted USB drive
MOUNT="/mnt/backup-usb"
sudo mount /dev/sdX1 "$MOUNT"
rsync -av ~/fleet-backups/ "$MOUNT/fleet-backups/"
sudo umount "$MOUNT"

# Or: push to a separate machine NOT on the Tailscale mesh
# This ensures ransomware on the mesh cannot reach backups
rsync -av -e ssh ~/fleet-backups/ offsite-backup-host:/backups/sontara/
```

### Backup verification

```bash
#!/bin/bash
# ~/.local/bin/fleet-backup-verify
# Run weekly: verify backups are valid and decryptable

LATEST=$(ls -1d ~/fleet-backups/*/ | tail -1)
ENCRYPTION_KEY="~/.config/fleet-backup/backup.key"

echo "Verifying backup: $LATEST"

# Test decryption of critical backup
openssl enc -d -aes-256-cbc -pbkdf2 -pass file:"$ENCRYPTION_KEY" \
    -in "$LATEST/critical.tar.gz.enc" | tar tzf - > /dev/null 2>&1 \
    && echo "critical.tar.gz.enc: VALID" \
    || echo "critical.tar.gz.enc: CORRUPT OR UNREADABLE"

# Test Wazuh rules backup
openssl enc -d -aes-256-cbc -pbkdf2 -pass file:"$ENCRYPTION_KEY" \
    -in "$LATEST/wazuh-rules.xml.enc" > /dev/null 2>&1 \
    && echo "wazuh-rules.xml.enc: VALID" \
    || echo "wazuh-rules.xml.enc: CORRUPT OR UNREADABLE"

echo "Verification complete"
```

---

## Monitoring Gaps

| Gap | Severity | Status | Remediation |
|-----|----------|--------|-------------|
| No backup strategy exists | **CRITICAL** | NOT IMPLEMENTED | Implement the backup strategy above |
| No backup verification | **CRITICAL** | NOT IMPLEMENTED | Weekly automated verification of backup integrity |
| No offsite backup | **CRITICAL** | NOT IMPLEMENTED | Monthly encrypted USB or off-mesh remote copy |
| No disk health monitoring | **HIGH** | NOT IMPLEMENTED | smartd monitoring on broker-server, SD card health on Pi devices |
| No ransomware detection | **HIGH** | PARTIAL | Wazuh FIM catches file changes but no specific ransomware pattern detection |
| No Syncthing ransomware spread prevention | **HIGH** | NOT IMPLEMENTED | Syncthing can propagate encrypted files from broker-server to workstation |
| Root identity.pem has no backup copy | **CRITICAL** | NOT IMPLEMENTED | Losing this key means rebuilding the entire trust chain |
| Wazuh custom rules not in Git | **HIGH** | NOT CONFIRMED | Should be tracked in claude-peers repo |
| No automated backup rotation | **MEDIUM** | NOT IMPLEMENTED | Prevent disk fill from accumulated backups |
