# Post-Incident Recovery Validation Playbook

**System:** Sontara Lattice (claude-peers) fleet
**Last updated:** 2026-03-28
**Audience:** the operator (fleet operator)
**Severity tier:** Applies after ANY incident -- mandatory validation before returning machines to service

---

## Table of Contents

1. [Purpose](#purpose)
2. [Validation Process Overview](#validation-process-overview)
3. [Linux Validation Checklist (Arch, Ubuntu, Debian)](#linux-validation-checklist)
4. [macOS Validation Checklist](#macos-validation-checklist)
5. [Pi Device Validation Checklist (edge-node, iot-device)](#pi-device-validation-checklist)
6. [Fleet-Wide Cross-Validation](#fleet-wide-cross-validation)
7. [Sign-Off Criteria](#sign-off-criteria)
8. [Monitoring Gaps](#monitoring-gaps)

---

## Purpose

After ANY security incident, a machine must be validated as clean before returning to service. This playbook provides a systematic checklist to verify:

1. No attacker persistence remains (backdoors, rootkits, cron jobs, services)
2. All credentials are legitimate and uncompromised
3. All binaries match expected versions
4. All configurations are in their expected state
5. Cross-machine validation confirms fleet consistency

**Rule: Never trust a machine after an incident without running this validation. "It seems fine" is not acceptable.**

---

## Validation Process Overview

```
Incident resolved
       |
       v
+-------------------+
| Process Audit     |  Are there unexpected processes running?
+-------------------+
       |
       v
+-------------------+
| Network Audit     |  Are there unexpected connections or listeners?
+-------------------+
       |
       v
+-------------------+
| Filesystem Audit  |  Have critical files been modified?
+-------------------+
       |
       v
+-------------------+
| Persistence Audit |  Are there backdoors in cron, systemd, shell profiles?
+-------------------+
       |
       v
+-------------------+
| Credential Audit  |  Are all keys, tokens, and certificates legitimate?
+-------------------+
       |
       v
+-------------------+
| FIM Baseline      |  Does Wazuh confirm file integrity?
+-------------------+
       |
       v
+-------------------+
| Cross-Validation  |  Do configs/binaries match across fleet?
+-------------------+
       |
       v
+-------------------+
| Sign-Off          |  All checks pass -> machine cleared for service
+-------------------+
```

---

## Linux Validation Checklist

Run on: workstation (<workstation-ip>), broker-server (<broker-ip>), workstation-2 (<workstation-2-ip>)

### 1. Process Audit

```bash
TARGET="broker-server"  # Replace per machine

ssh $TARGET "
echo '========================================='
echo '  PROCESS AUDIT: \$(hostname)'
echo '========================================='

echo ''
echo '=== All running processes ==='
ps auxf

echo ''
echo '=== Processes running as root (unexpected?) ==='
ps aux | awk '\$1==\"root\"' | grep -v \
    -e 'sshd' -e 'systemd' -e 'journald' -e 'udevd' -e 'dbus' \
    -e 'tailscaled' -e 'dockerd' -e 'containerd' -e 'agetty' \
    -e 'cron' -e 'rsyslogd' -e 'wazuh' -e 'ossec' \
    -e 'kworker' -e 'ksoftirqd' -e 'rcu_' -e 'migration' -e '\\['

echo ''
echo '=== Processes with deleted binaries (SUSPICIOUS) ==='
ls -la /proc/*/exe 2>/dev/null | while read line; do
    readlink \$(echo \$line | awk '{print \$NF}') 2>/dev/null | grep -q '(deleted)' && echo \"DELETED: \$line\"
done

echo ''
echo '=== Processes listening on network ==='
ss -tlnp

echo ''
echo '=== Processes with open network connections ==='
ss -tnp | grep ESTAB
"
```

### 2. Network Audit

```bash
ssh $TARGET "
echo '========================================='
echo '  NETWORK AUDIT: \$(hostname)'
echo '========================================='

echo ''
echo '=== Listening ports ==='
ss -tlnp

echo ''
echo '=== Established connections ==='
ss -tnp | grep ESTAB

echo ''
echo '=== DNS resolution ==='
cat /etc/resolv.conf

echo ''
echo '=== Routing table ==='
ip route

echo ''
echo '=== Tailscale status ==='
tailscale status

echo ''
echo '=== iptables rules (unexpected rules?) ==='
sudo iptables -L -n -v 2>/dev/null | head -30

echo ''
echo '=== Unexpected network interfaces ==='
ip link show | grep -v 'lo:\|tailscale\|eth\|wlan\|docker\|veth\|br-'
"
```

### 3. Filesystem Audit

```bash
ssh $TARGET "
echo '========================================='
echo '  FILESYSTEM AUDIT: \$(hostname)'
echo '========================================='

echo ''
echo '=== Recently modified files in home directory (last 24h) ==='
find /home/user -maxdepth 3 -mtime -1 -type f 2>/dev/null | head -30

echo ''
echo '=== Recently modified files in /etc (last 24h) ==='
find /etc -mtime -1 -type f 2>/dev/null | head -20

echo ''
echo '=== Setuid binaries ==='
find /usr/bin /usr/sbin /usr/local/bin -perm -4000 2>/dev/null

echo ''
echo '=== World-writable files in system dirs ==='
find /usr/bin /usr/sbin /etc -perm -o+w -type f 2>/dev/null | head -10

echo ''
echo '=== /tmp contents (attacker staging area) ==='
ls -la /tmp/ | head -20

echo ''
echo '=== Hidden files in home directory ==='
find /home/user -maxdepth 1 -name '.*' -type f 2>/dev/null

echo ''
echo '=== Modified package files ==='
pacman -Qkk 2>/dev/null | grep -i 'warning' | head -20 || \
dpkg --verify 2>/dev/null | head -20
"
```

### 4. Persistence Audit

```bash
ssh $TARGET "
echo '========================================='
echo '  PERSISTENCE AUDIT: \$(hostname)'
echo '========================================='

echo ''
echo '=== Crontab (user) ==='
crontab -l 2>/dev/null || echo 'No user crontab'

echo ''
echo '=== Crontab (system) ==='
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/ 2>/dev/null

echo ''
echo '=== Systemd user services ==='
systemctl --user list-units --type=service --all 2>/dev/null

echo ''
echo '=== Systemd system services (non-standard) ==='
systemctl list-units --type=service --state=running | grep -v \
    -e 'systemd' -e 'dbus' -e 'ssh' -e 'network' -e 'docker' \
    -e 'tailscale' -e 'wazuh' -e 'cron' -e 'udev' -e 'journal' \
    -e 'resolved' -e 'timesyncd' -e 'login' -e 'user@'

echo ''
echo '=== Shell profile modifications ==='
echo '--- .bashrc (last 10 lines) ---'
tail -10 ~/.bashrc 2>/dev/null
echo '--- .bash_profile (last 10 lines) ---'
tail -10 ~/.bash_profile 2>/dev/null
echo '--- .profile (last 10 lines) ---'
tail -10 ~/.profile 2>/dev/null
echo '--- .zshrc (last 10 lines) ---'
tail -10 ~/.zshrc 2>/dev/null

echo ''
echo '=== SSH authorized_keys ==='
cat ~/.ssh/authorized_keys 2>/dev/null || echo 'No authorized_keys'

echo ''
echo '=== SSH known_hosts entry count ==='
wc -l ~/.ssh/known_hosts 2>/dev/null || echo 'No known_hosts'

echo ''
echo '=== /etc/hosts modifications ==='
cat /etc/hosts

echo ''
echo '=== LD_PRELOAD (library injection) ==='
echo \$LD_PRELOAD
cat /etc/ld.so.preload 2>/dev/null || echo 'No ld.so.preload'

echo ''
echo '=== PAM configuration (authentication hooks) ==='
ls -la /etc/pam.d/ | head -20
"
```

### 5. Credential Audit

```bash
ssh $TARGET "
echo '========================================='
echo '  CREDENTIAL AUDIT: \$(hostname)'
echo '========================================='

echo ''
echo '=== claude-peers identity key ==='
ls -la ~/.config/claude-peers/identity.pem 2>/dev/null
# Show public key fingerprint (not the private key)
openssl pkey -in ~/.config/claude-peers/identity.pem -pubout 2>/dev/null | openssl dgst -sha256 || echo 'Cannot read identity key'

echo ''
echo '=== claude-peers token ==='
ls -la ~/.config/claude-peers/token.jwt 2>/dev/null
# Show token issuer and expiry (not the full token)
cat ~/.config/claude-peers/token.jwt 2>/dev/null | cut -d. -f2 | base64 -d 2>/dev/null | python3 -c '
import json, sys
try:
    data = json.loads(sys.stdin.read())
    print(f\"  Issuer: {data.get(\"iss\", \"unknown\")}\")
    print(f\"  Expiry: {data.get(\"exp\", \"unknown\")}\")
    print(f\"  Capabilities: {data.get(\"att\", \"unknown\")}\")
except:
    print(\"  Cannot parse token\")
'

echo ''
echo '=== claude-peers config (redacted) ==='
cat ~/.config/claude-peers/config.json 2>/dev/null | python3 -c '
import json, sys
try:
    cfg = json.loads(sys.stdin.read())
    for key in cfg:
        if \"token\" in key.lower() or \"key\" in key.lower() or \"secret\" in key.lower():
            print(f\"  {key}: [REDACTED] (length: {len(str(cfg[key]))})\")
        else:
            print(f\"  {key}: {cfg[key]}\")
except:
    print(\"  Cannot parse config\")
'

echo ''
echo '=== SSH keys ==='
ls -la ~/.ssh/ 2>/dev/null
for key in ~/.ssh/id_*; do
    [ -f \"\$key\" ] && echo \"  \$(ssh-keygen -lf \$key 2>/dev/null)\"
done

echo ''
echo '=== root.pub (trust anchor) ==='
ls -la ~/.config/claude-peers/root.pub 2>/dev/null
cat ~/.config/claude-peers/root.pub 2>/dev/null | openssl dgst -sha256 || echo 'Cannot read root.pub'
"
```

### 6. UCAN Token Validation

```bash
ssh $TARGET "
echo '========================================='
echo '  UCAN TOKEN VALIDATION: \$(hostname)'
echo '========================================='

# Verify the token was issued by the expected root key
# The token's issuer should match the broker's root public key
echo 'Token issuer chain:'
cat ~/.config/claude-peers/token.jwt 2>/dev/null | cut -d. -f2 | base64 -d 2>/dev/null | python3 -c '
import json, sys
try:
    data = json.loads(sys.stdin.read())
    print(f\"  iss (issuer): {data.get(\"iss\", \"unknown\")}\")
    print(f\"  aud (audience): {data.get(\"aud\", \"unknown\")}\")
    print(f\"  exp (expiry): {data.get(\"exp\", \"unknown\")}\")
    prf = data.get(\"prf\", [])
    if prf:
        print(f\"  prf (proof chain): {len(prf)} proofs\")
    else:
        print(\"  prf: root token (no proof chain)\")
except:
    print(\"  Cannot parse token payload\")
'

echo ''
echo 'Root public key fingerprint (should match across fleet):'
openssl dgst -sha256 ~/.config/claude-peers/root.pub 2>/dev/null
"
```

---

## macOS Validation Checklist

Run on: laptop-1 (<laptop-1-ip>)

```bash
ssh <user>@<laptop-1-ip><laptop-1-ip> "
echo '========================================='
echo '  macOS VALIDATION: \$(hostname)'
echo '========================================='

echo ''
echo '=== Running processes (unusual) ==='
ps aux | grep -v \
    -e '/usr/libexec' -e '/System/' -e '/usr/sbin' -e 'kernel_task' \
    -e 'WindowServer' -e 'Finder' -e 'Dock' -e 'tailscaled' \
    | head -30

echo ''
echo '=== Launch agents (user) ==='
ls -la ~/Library/LaunchAgents/ 2>/dev/null

echo ''
echo '=== Launch daemons (system) ==='
ls -la /Library/LaunchDaemons/ 2>/dev/null | head -20

echo ''
echo '=== Login items ==='
osascript -e 'tell application \"System Events\" to get the name of every login item' 2>/dev/null

echo ''
echo '=== Network listeners ==='
lsof -i -P -n | grep LISTEN | head -20

echo ''
echo '=== Established connections ==='
lsof -i -P -n | grep ESTABLISHED | head -20

echo ''
echo '=== claude-peers credentials ==='
ls -la ~/.config/claude-peers/ 2>/dev/null

echo ''
echo '=== SSH keys ==='
ls -la ~/.ssh/ 2>/dev/null

echo ''
echo '=== Homebrew integrity ==='
brew doctor 2>/dev/null | head -10

echo ''
echo '=== Recently modified files ==='
find ~/Library -maxdepth 2 -mtime -1 -type f 2>/dev/null | head -20
"
```

---

## Pi Device Validation Checklist

Run on: edge-node (Pi 5), iot-device (<iot-device-ip>)

```bash
PI_TARGET="edge-node"  # or <iot-device-ip>

ssh $PI_TARGET "
echo '========================================='
echo '  Pi VALIDATION: \$(hostname)'
echo '========================================='

echo ''
echo '=== System info ==='
uname -a
cat /etc/os-release | head -3
vcgencmd measure_temp 2>/dev/null

echo ''
echo '=== Running processes ==='
ps auxf

echo ''
echo '=== Network listeners ==='
ss -tlnp

echo ''
echo '=== Established connections ==='
ss -tnp | grep ESTAB

echo ''
echo '=== Crontab ==='
crontab -l 2>/dev/null || echo 'No crontab'

echo ''
echo '=== Systemd services (non-standard) ==='
systemctl list-units --type=service --state=running | grep -v \
    -e 'systemd' -e 'dbus' -e 'ssh' -e 'network' -e 'tailscale' \
    -e 'cron' -e 'udev' -e 'journal' -e 'resolved' -e 'timesyncd' \
    -e 'login' -e 'user@' -e 'bluetooth' -e 'wpa_supplicant'

echo ''
echo '=== SD card health indicators ==='
dmesg | grep -i 'mmc\|error\|read-only' | tail -10
df -h /

echo ''
echo '=== claude-peers credentials ==='
ls -la ~/.config/claude-peers/ 2>/dev/null

echo ''
echo '=== Authorized SSH keys ==='
cat ~/.ssh/authorized_keys 2>/dev/null || echo 'No authorized_keys'

echo ''
echo '=== Shell profiles ==='
tail -5 ~/.bashrc 2>/dev/null
tail -5 ~/.profile 2>/dev/null

echo ''
echo '=== /etc/hosts ==='
cat /etc/hosts

echo ''
echo '=== Package integrity ==='
dpkg --verify 2>/dev/null | head -20
"
```

---

## Fleet-Wide Cross-Validation

After validating individual machines, cross-validate across the fleet to ensure consistency.

### Binary consistency

```bash
echo "=== Fleet Binary Cross-Validation ==="
HASHES=""
for machine in "<workstation-ip>" "broker-server" "edge-node" "<workstation-2-ip>" "<user>@<laptop-1-ip><laptop-1-ip>" "<iot-device-ip>"; do
    HASH=$(ssh -o ConnectTimeout=5 $machine "sha256sum ~/.local/bin/claude-peers 2>/dev/null || sha256sum \$(which claude-peers) 2>/dev/null" 2>/dev/null | awk '{print $1}')
    echo "  $machine: ${HASH:-UNREACHABLE}"
    HASHES="$HASHES $HASH"
done

UNIQUE=$(echo $HASHES | tr ' ' '\n' | sort -u | grep -v '^$' | wc -l)
if [ "$UNIQUE" -eq 1 ]; then
    echo "PASS: All reachable machines have the same binary"
else
    echo "FAIL: Binary mismatch detected across fleet"
fi
```

### Root public key consistency

```bash
echo "=== root.pub Cross-Validation ==="
for machine in "<workstation-ip>" "broker-server" "edge-node" "<workstation-2-ip>" "<user>@<laptop-1-ip><laptop-1-ip>" "<iot-device-ip>"; do
    HASH=$(ssh -o ConnectTimeout=5 $machine "sha256sum ~/.config/claude-peers/root.pub 2>/dev/null" 2>/dev/null | awk '{print $1}')
    echo "  $machine: ${HASH:-UNREACHABLE}"
done
echo "All hashes should be identical"
```

### Config consistency

```bash
echo "=== Config Cross-Validation ==="
for machine in "<workstation-ip>" "broker-server" "edge-node" "<workstation-2-ip>" "<user>@<laptop-1-ip><laptop-1-ip>" "<iot-device-ip>"; do
    ssh -o ConnectTimeout=5 $machine "
        echo 'Broker URL:' \$(cat ~/.config/claude-peers/config.json 2>/dev/null | python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get(\"broker_url\",\"?\"))' 2>/dev/null)
        echo 'NATS URL:' \$(cat ~/.config/claude-peers/config.json 2>/dev/null | python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get(\"nats_url\",\"?\"))' 2>/dev/null)
    " 2>/dev/null || echo "  $machine: UNREACHABLE"
done
echo "All machines should point to the same broker and NATS URLs"
```

### Wazuh FIM re-scan

```bash
# Trigger a Wazuh integrity scan on all agents
ssh broker-server "
echo '=== Triggering Wazuh FIM re-scan ==='
docker exec wazuh-manager /var/ossec/bin/agent_control -r -a 2>/dev/null || \
    echo 'Cannot trigger re-scan -- check Wazuh manager status'

echo ''
echo '=== Wait for scan results (check in 5 minutes) ==='
echo 'Command to check results:'
echo 'docker exec wazuh-manager cat /var/ossec/logs/alerts/alerts.json | grep syscheck | tail -20'
"
```

### SSH key audit across fleet

```bash
echo "=== SSH Authorized Keys Cross-Validation ==="
echo "Verify that ONLY expected keys are present on each machine"
for machine in "<workstation-ip>" "broker-server" "edge-node" "<workstation-2-ip>" "<user>@<laptop-1-ip><laptop-1-ip>" "<iot-device-ip>"; do
    echo "--- $machine ---"
    ssh -o ConnectTimeout=5 $machine "
        echo 'Authorized keys:'
        cat ~/.ssh/authorized_keys 2>/dev/null | while read type key comment; do
            echo \"  \$comment (\$type \$(echo \$key | cut -c1-20)...)\"
        done
        echo 'Key count:' \$(wc -l < ~/.ssh/authorized_keys 2>/dev/null || echo 0)
    " 2>/dev/null || echo "  UNREACHABLE"
done
```

---

## Sign-Off Criteria

A machine is "cleared for return to service" when ALL of the following are true:

### Mandatory (all machines)

- [ ] **Process audit:** No unexpected processes running, no deleted-binary processes
- [ ] **Network audit:** No unexpected listeners, no suspicious outbound connections
- [ ] **Persistence audit:** No unauthorized cron jobs, systemd services, shell profile modifications, or SSH keys
- [ ] **Credential audit:** identity.pem, token.jwt, and config.json are present and parseable
- [ ] **UCAN token valid:** Token issuer chain traces back to expected root key
- [ ] **Binary integrity:** claude-peers binary hash matches expected value
- [ ] **root.pub match:** Root public key matches all other fleet machines
- [ ] **SSH keys verified:** Only expected authorized_keys entries present
- [ ] **No /etc/hosts tampering:** hosts file contains only expected entries
- [ ] **No LD_PRELOAD injection:** LD_PRELOAD is empty, no /etc/ld.so.preload

### Additional (broker-server only)

- [ ] **Docker containers:** Only expected containers running (wazuh-manager, wazuh-indexer, wazuh-dashboard, litellm)
- [ ] **No Docker socket mounts:** No container has /var/run/docker.sock mounted
- [ ] **Broker responding:** curl http://<broker-ip>:7899/health returns OK
- [ ] **NATS healthy:** curl http://<broker-ip>:8222/varz returns valid JSON
- [ ] **Wazuh manager running:** docker ps shows wazuh-manager as healthy
- [ ] **Wazuh agents connected:** All fleet agents reporting to manager

### Additional (Pi devices)

- [ ] **SD card healthy:** No read-only filesystem, no dmesg mmc errors
- [ ] **Package integrity:** dpkg --verify shows no unexpected modifications

### Final sign-off

```
Machine: _______________
Validated by: the operator
Date: _______________
Incident reference: _______________
All mandatory checks: [ ] PASS / [ ] FAIL
Additional checks: [ ] PASS / [ ] FAIL / [ ] N/A
Decision: [ ] CLEARED FOR SERVICE / [ ] REQUIRES RE-IMAGE / [ ] REQUIRES FURTHER INVESTIGATION
Notes: _______________
```

---

## Monitoring Gaps

| Gap | Severity | Status | Remediation |
|-----|----------|--------|-------------|
| No automated post-incident validation | **HIGH** | NOT IMPLEMENTED | Script the full checklist above for one-command execution |
| No baseline for "normal" process list per machine | **HIGH** | NOT IMPLEMENTED | Document expected processes per machine, compare during validation |
| No FIM baseline for credential files | **HIGH** | NOT CONFIRMED | Wazuh should monitor ~/.config/claude-peers/ on all machines |
| No automated binary consistency check | **MEDIUM** | NOT IMPLEMENTED | Periodic fleet-wide hash comparison (see UPGRADE_ATTACK playbook) |
| No UCAN token validation tool | **MEDIUM** | NOT IMPLEMENTED | `claude-peers validate-token` command that verifies issuer chain |
| No post-incident validation history | **MEDIUM** | NOT IMPLEMENTED | Record which machines were validated, when, and what was found |
| macOS validation limited | **MEDIUM** | INHERENT | Less visibility into macOS internals compared to Linux |
| laptop-2 cannot be validated | **HIGH** | BY DESIGN | Not the operator's machine -- cannot run any validation checks |
