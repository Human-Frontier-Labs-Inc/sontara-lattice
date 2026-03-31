# SSH Brute Force Incident Response Playbook

**System:** Sontara Lattice (claude-peers) fleet
**Last updated:** 2026-03-28
**Audience:** the operator (fleet operator)
**Severity tier:** Tier 2 (Contain) -- auto IP block + forensic capture + email

---

## Table of Contents

1. [Attack Model](#attack-model)
2. [Detection Signals](#detection-signals)
3. [Immediate Triage (0-5 minutes)](#immediate-triage)
4. [Containment](#containment)
5. [Investigation](#investigation)
6. [Eradication](#eradication)
7. [Recovery](#recovery)
8. [Post-Incident](#post-incident)
9. [Escalation Criteria](#escalation-criteria)
10. [Machine-Specific Notes](#machine-specific-notes)

---

## Attack Model

### How attackers reach SSH on this fleet

**External brute force (public IP):**
This should not happen. All SSH on this fleet runs behind Tailscale -- no ports are forwarded to the public internet. If you see brute force from a non-100.x.x.x IP, it means one of:
- A machine has SSH bound to a public interface (misconfiguration)
- A cloud provider or ISP has mapped a public IP to the machine
- The attacker is on the local LAN (same WiFi)

**Internal brute force (Tailscale 100.x.x.x source):**
This is the real threat. It means a fleet device is compromised and the attacker is pivoting. Possible entry points:
- Stolen Tailscale auth key (check `tailscale status` for rogue devices)
- Compromised machine with valid Tailscale identity
- MagicDNS poisoning (unlikely but possible if Tailscale control plane is compromised)
- Physical access to a fleet device (especially iot-device or edge-node)

**Credential stuffing vs key-based:**
All fleet machines should have `PasswordAuthentication no` in sshd_config. If password auth failures are appearing, a machine is misconfigured. Key-based brute force (trying many keys) is unusual but possible from a sophisticated attacker.

### Real-world patterns

- Automated scanners hit SSH within minutes of exposure. They try root, admin, ubuntu, pi, user with common passwords.
- On Tailscale, brute force implies an insider threat or compromised device -- this is always high priority.
- Attackers who gain one foothold will immediately scan for other SSH targets on the same subnet. Tailscale's flat 100.x.x.x network makes lateral movement trivial.

---

## Detection Signals

### What fires automatically

| Layer | Signal | Detail |
|-------|--------|--------|
| **Wazuh** | Built-in rules 5710, 5712, 5720 | SSH authentication failures (levels 5-10) |
| **Wazuh** | Rule 100102 (level 10) | SSH authorized_keys modified |
| **wazuh-bridge** | Publishes to `fleet.security.auth` | SecurityEvent with type=auth, source IP extracted from agent |
| **security-watch** | `checkBruteForce()` | Fires when 5+ auth failures on same machine within 10 minutes |
| **security-watch** | `checkDistributedAttack()` | Fires when same rule ID appears on 3+ machines within 5 minutes |
| **response-daemon** | `IncidentBruteForce` (Tier 2) | Captures forensics, blocks source IP via iptables (1 hour TTL), sends email |
| **Broker** | Health score +10 for critical | Machine enters "quarantined" status at score >= 10 |

### What you see

**Email:** Subject line `[fleet-security] CONTAIN on <machine>: brute_force`
- Body includes: incident type, tier, machines affected, all triggering events with source IPs, actions taken (IP block, forensic capture)

**Gridwatch Security Page:** Machine card shows:
- Score jumping (warning +1 each, critical +10)
- Status changing from "healthy" to "degraded" (score >= 5) or "quarantined" (score >= 10)
- Live event feed showing auth failure events
- Perimeter status changes to "ELEVATED THREAT" or "BREACH DETECTED"

**NATS subjects:**
- `fleet.security.auth` -- individual auth failure events
- `fleet.security.quarantine` -- escalation from security-watch when brute force threshold hit

### What the log shows on broker-server

```
[wazuh-bridge] auth level=5 agent=edge-node rule=5710: sshd: Failed password for invalid user
[security-watch] event: type=auth severity=warning machine=edge-node rule=5710: ...
[security-watch] CORRELATION: brute force: 5 auth failures on edge-node in 10 minutes
[security-watch] escalation published: edge-node -> quarantine
[response] incident classified: type=brute_force machine=edge-node rule= severity=
[response] brute_force on edge-node: IP 203.0.113.99 blocked, forensics captured
[response] forensic snapshot saved: ~/.config/claude-peers/forensics/edge-node-20260328-143022.json
[response] email sent: [fleet-security] CONTAIN on edge-node: brute_force
```

---

## Immediate Triage (0-5 minutes)

### Step 1: Determine source -- external or internal?

The email from response-daemon includes the source IP. Check it immediately.

**If source IP is 100.x.x.x (Tailscale):**
```
THIS IS A COMPROMISED FLEET DEVICE. SKIP TO ESCALATION CRITERIA IMMEDIATELY.
```
The response-daemon refuses to block Tailscale IPs (`executeIPBlock` returns error for 100.x.x.x). You must handle this manually. See [Escalation Criteria](#escalation-criteria).

**If source IP is a private LAN IP (192.168.x.x, 10.x.x.x):**
Someone on your local network is attacking. This means physical proximity. Check who is on the WiFi.

**If source IP is a public IP:**
Your SSH is somehow internet-exposed. This is a configuration emergency independent of the brute force.

### Step 2: Check if any login succeeded

On the target machine (replace `edge-node` with actual machine):

```bash
# Linux machines (workstation, broker-server, edge-node, workstation-2, iot-device)
ssh edge-node "last -20"
ssh edge-node "who"
ssh edge-node "w"

# macOS machines (laptop-1, laptop-2)
ssh <user>@<laptop-1-ip><laptop-1-ip> "last -20"
ssh <user>@<laptop-1-ip><laptop-1-ip> "who"
```

Look for:
- Logins from the attacking IP
- Logins at unusual times
- Logins from usernames you don't recognize
- `pts/` entries that don't correspond to your active sessions

### Step 3: Check SSH logs for success after failures

```bash
# Linux (systemd)
ssh edge-node 'journalctl -u sshd --since "1 hour ago" --no-pager | grep -i "accepted"'

# Linux (auth.log)
ssh edge-node 'grep "Accepted" /var/log/auth.log 2>/dev/null | tail -20'

# macOS
ssh <user>@<laptop-1-ip><laptop-1-ip> 'log show --predicate '\''process == "sshd"'\'' --last 1h --style compact 2>/dev/null | grep -i "accepted"'
```

**If you see an accepted login from the attacking IP: treat this as a full compromise.** Jump to [Eradication](#eradication).

### Step 4: Check authorized_keys for injected keys

```bash
ssh edge-node "cat ~/.ssh/authorized_keys"
```

Look for keys you don't recognize. Your legitimate keys should be from: workstation, broker-server, laptop-1. Any key with an unfamiliar comment field (the text after the key material) is suspicious.

For root-level check (if the machine allows root SSH or if the attacker escalated):

```bash
ssh edge-node "sudo cat /root/.ssh/authorized_keys 2>/dev/null"
```

### Step 5: Check for new users

```bash
# Linux
ssh edge-node "cat /etc/passwd | grep -v nologin | grep -v false"
ssh edge-node "grep -v '^#' /etc/shadow 2>/dev/null | cut -d: -f1,2 | grep -v '!' | grep -v '*'"

# macOS
ssh <user>@<laptop-1-ip><laptop-1-ip> "dscl . list /Users | grep -v '^_'"
```

---

## Containment

### Automated containment (already happened)

The response-daemon has already:
1. Captured a forensic snapshot (processes, listeners, logins, SSH logs, temp files, services)
2. Blocked the source IP via `iptables -A INPUT -s <IP> -j DROP` (1 hour TTL)
3. Sent email alert
4. Published quarantine event to NATS
5. Machine health score set to >= 10 (quarantined status)

The quarantined machine can no longer authenticate to the broker (UCAN middleware returns 403 QUARANTINED).

### Manual containment steps

**If the attacker succeeded in logging in:**

```bash
# Kill all sessions from the attacking IP (Linux)
ssh edge-node "sudo ss -tnp | grep <ATTACKER_IP> | awk '{print \$6}' | grep -oP '(?<=pid=)\d+' | xargs -I{} sudo kill -9 {}"

# Block the IP permanently (not just 1 hour)
ssh edge-node "sudo iptables -I INPUT 1 -s <ATTACKER_IP> -j DROP"
ssh edge-node "sudo iptables-save > /etc/iptables/iptables.rules"  # Arch/edge-node
# or
ssh broker-server "sudo netfilter-persistent save"  # Ubuntu
```

**If the source is a Tailscale IP (compromised fleet device):**

```bash
# Identify which device owns the IP
tailscale status | grep <100.x.x.x IP>

# Remove the compromised device from Tailscale (from any fleet machine)
# This requires Tailscale admin console: https://login.tailscale.com/admin/machines
# Or if you have the tailscale CLI with admin access:
sudo tailscale lock remove <node-key>
```

**Network isolation of the target machine:**

```bash
# Drop all inbound connections except your current SSH session
ssh edge-node "sudo iptables -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT && sudo iptables -A INPUT -p tcp --dport 22 -s <workstation-ip> -j ACCEPT && sudo iptables -A INPUT -j DROP"
```

This allows only your existing sessions and new SSH from workstation (<workstation-ip>). Replace with your current machine's Tailscale IP.

---

## Investigation

### Forensic snapshot review

The response-daemon saved a snapshot to `~/.config/claude-peers/forensics/<machine>-<timestamp>.json` on broker-server. Review it:

```bash
ssh broker-server "cat ~/.config/claude-peers/forensics/edge-node-*.json | jq ."
```

The snapshot contains: processes, listeners, recent_logins, current_users, ssh_logs, temp_files, services.

### Full investigation commands

Run these on the affected machine. The commands differ by OS.

#### Process investigation (Linux)

```bash
# Full process tree -- look for unfamiliar processes, especially children of sshd
ssh edge-node "ps auxf"

# Processes running as root that shouldn't be
ssh edge-node "ps aux | grep -E '^root' | grep -v -E '(systemd|kthread|agetty|sshd|dbus|cron|wazuh)'"

# Processes with network connections
ssh edge-node "ss -tlnp"
ssh edge-node "ss -tnp"

# Look for processes connecting outbound to unusual IPs
ssh edge-node "ss -tnp | grep ESTAB | grep -v '100\.\|127\.0\.0\.1'"
```

#### Process investigation (macOS)

```bash
ssh <user>@<laptop-1-ip><laptop-1-ip> "ps aux"
ssh <user>@<laptop-1-ip><laptop-1-ip> "lsof -iTCP -sTCP:LISTEN -n -P"
ssh <user>@<laptop-1-ip><laptop-1-ip> "lsof -iTCP -sTCP:ESTABLISHED -n -P | grep -v '100\.\|127\.0\.0\.1'"
```

#### Persistence mechanisms (Linux)

```bash
# Cron jobs
ssh edge-node "crontab -l 2>/dev/null"
ssh edge-node "sudo crontab -l 2>/dev/null"
ssh edge-node "ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /var/spool/cron/crontabs/ 2>/dev/null"

# Systemd units (user and system) -- look for recently created/modified
ssh edge-node "find /etc/systemd/system ~/.config/systemd/user /usr/lib/systemd/system -name '*.service' -mmin -60 2>/dev/null"
ssh edge-node "systemctl list-units --type=service --state=running --no-pager"
ssh edge-node "systemctl --user list-units --type=service --state=running --no-pager"

# .bashrc / .profile modifications (common persistence)
ssh edge-node "stat -c '%y' ~/.bashrc ~/.bash_profile ~/.profile 2>/dev/null"
ssh edge-node "tail -20 ~/.bashrc"

# At jobs
ssh edge-node "atq 2>/dev/null"

# SSH authorized_keys (already checked but verify again)
ssh edge-node "md5sum ~/.ssh/authorized_keys"
```

#### Persistence mechanisms (macOS)

```bash
ssh <user>@<laptop-1-ip><laptop-1-ip> "launchctl list | head -30"
ssh <user>@<laptop-1-ip><laptop-1-ip> "ls -la ~/Library/LaunchAgents/ /Library/LaunchAgents/ /Library/LaunchDaemons/ 2>/dev/null"
ssh <user>@<laptop-1-ip><laptop-1-ip> "crontab -l 2>/dev/null"
ssh <user>@<laptop-1-ip><laptop-1-ip> "stat -f '%Sm' ~/.zshrc ~/.bash_profile 2>/dev/null"
```

#### Filesystem investigation

```bash
# Recently modified files in /tmp and /var/tmp
ssh edge-node "find /tmp /var/tmp -mmin -60 -type f -ls 2>/dev/null"

# Recently created files anywhere writable
ssh edge-node "find /home /root /tmp /var/tmp -mmin -120 -type f -newer /etc/hostname 2>/dev/null | head -50"

# Check for SUID binaries that shouldn't exist
ssh edge-node "find /usr/bin /usr/sbin /usr/local/bin -perm -4000 -type f 2>/dev/null"

# World-writable directories with executables
ssh edge-node "find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null"

# Check for hidden files in home directory
ssh edge-node "ls -la ~/.[!.]* 2>/dev/null | grep -v -E '(\.bash|\.ssh|\.config|\.local|\.cache|\.gnupg|\.claude)'"
```

#### Network investigation

```bash
# DNS resolution history (if systemd-resolved is running)
ssh edge-node "resolvectl query --cache 2>/dev/null || true"

# iptables rules (check for attacker-installed rules)
ssh edge-node "sudo iptables -L -n -v"

# Check for unusual network namespaces
ssh edge-node "ip netns list 2>/dev/null"

# Check Tailscale status for rogue peers
ssh edge-node "tailscale status"
```

#### iot-device specific (runs as root, AIDE sentinel)

```bash
ssh <iot-device-ip> "aide --check 2>/dev/null | tail -20"
ssh <iot-device-ip> "auditctl -l"
ssh <iot-device-ip> "ausearch -m execve --start recent 2>/dev/null | tail -30"
```

---

## Eradication

### Decision: rebuild vs. clean

**Rebuild the machine if any of these are true:**
- Root access was confirmed (attacker ran commands as root)
- Kernel modules were loaded (`lsmod` shows unknown modules)
- System binaries were modified (check with `rpm -Va` on Arch or `debsums -c` on Debian)
- You cannot fully account for every process and network connection
- The machine is iot-device or edge-node (small enough to re-flash quickly)

**Clean the machine if ALL of these are true:**
- Attacker only achieved user-level access
- No persistence mechanisms found
- No system binary modifications
- You can account for all processes and connections
- The brute force was blocked before any login succeeded

### Cleaning procedure

```bash
# 1. Remove any injected SSH keys
ssh edge-node "cp ~/.ssh/authorized_keys ~/.ssh/authorized_keys.compromised.$(date +%s)"
# Manually edit to remove unknown keys:
ssh edge-node "vim ~/.ssh/authorized_keys"

# 2. Remove any persistence (cron, systemd, bashrc)
# Based on investigation findings -- remove what you found

# 3. Change the user password (even if password auth is disabled)
ssh edge-node "sudo passwd user"

# 4. Kill any suspicious processes
ssh edge-node "kill -9 <PIDs from investigation>"

# 5. Remove any dropped files
ssh edge-node "rm -rf /tmp/<suspicious files>"

# 6. Verify the iptables block is in place
ssh edge-node "sudo iptables -L INPUT -n | grep <ATTACKER_IP>"

# 7. Restart sshd to drop any cached sessions
ssh edge-node "sudo systemctl restart sshd"
```

### Rebuild procedure (Linux)

For edge-node/iot-device (Raspberry Pi):
1. Flash a fresh SD card with the OS image
2. Re-run the bootstrap script (Tailscale, claude-peers, Wazuh agent)
3. Re-issue UCAN tokens (see [Recovery](#recovery))

For workstation/workstation-2 (Arch):
1. Boot from USB installer
2. Reinstall the workstation
3. Restore dotfiles from chezmoi
4. Re-run claude-peers setup

---

## Recovery

### Step 1: Unquarantine the machine

After eradication is complete and you've verified the machine is clean:

```bash
# Via the broker API
curl -X POST http://<broker-ip>:7899/unquarantine \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt)" \
  -d '{"machine": "edge-node"}'

# Or via sim-attack tool (which calls the same endpoint)
claude-peers unquarantine edge-node
```

### Step 2: Rotate UCAN credentials on the affected machine

Even if credentials weren't directly targeted, rotate them after any compromise:

```bash
# On the affected machine, generate new keypair
ssh edge-node "cd ~/.config/claude-peers && claude-peers init client http://<broker-ip>:7899"

# On the broker (broker-server), issue a new token for the machine's new public key
ssh broker-server "claude-peers issue-token /path/to/edge-node-new-identity.pub peer-session"

# On the affected machine, save the new token
ssh edge-node "claude-peers save-token <new-jwt>"
```

### Step 3: Verify fleet integrity

```bash
# Check all machines' health on the broker
curl -s http://<broker-ip>:7899/machine-health \
  -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt)" | jq .

# Check Tailscale for rogue devices
tailscale status

# Run sim-attack dry run to verify detection still works
claude-peers sim-attack brute-force --target=edge-node --dry-run
```

### Step 4: Review forensic snapshot

The forensic data is saved at:
```
~/.config/claude-peers/forensics/<machine>-<timestamp>.json
```

Keep this for your records. It contains the machine state at the time of detection.

---

## Post-Incident

### Immediate hardening

**Disable password authentication (if it wasn't already):**

```bash
# On every fleet machine (Linux)
for host in edge-node workstation-2-workstation <iot-device-ip>; do
  ssh $host "sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && sudo systemctl restart sshd"
done

# macOS
ssh <user>@<laptop-1-ip><laptop-1-ip> "sudo sed -i '' 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist && sudo launchctl load /System/Library/LaunchDaemons/ssh.plist"
```

**Install fail2ban on machines that don't have it:**

```bash
# Debian/Ubuntu
ssh edge-node "sudo apt install -y fail2ban"
ssh broker-server "sudo apt install -y fail2ban"

# Arch
ssh workstation "sudo pacman -S --noconfirm fail2ban"

# Configure for SSH (all Linux machines)
cat << 'JAIL' | ssh edge-node "sudo tee /etc/fail2ban/jail.local"
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600
JAIL
ssh edge-node "sudo systemctl enable --now fail2ban"
```

**Tighten Tailscale ACLs:**

If SSH should only be accessible from specific machines (e.g., only workstation can SSH to edge-node), configure Tailscale ACLs in the admin console:
- https://login.tailscale.com/admin/acls
- Restrict SSH access to specific source machines
- Enable Tailscale SSH (replaces OpenSSH with Tailscale's identity-verified SSH)

**Consider Tailscale SSH:**
Tailscale SSH eliminates the need for SSH keys entirely. Authentication goes through Tailscale identity. This removes the entire SSH brute force attack surface.

```bash
# On each machine
sudo tailscale set --ssh
```

### Detection tuning

If detection was too slow:
- Reduce the Wazuh syscheck frequency (currently 300 seconds = 5 minutes)
- Enable journald monitoring on machines that only have auth.log monitoring
- Lower the security-watch brute force threshold from 5 to 3 failures

If detection was too noisy:
- Add legitimate source IPs to a whitelist in response-daemon
- Increase the security-watch window from 10 minutes to 15

### Documentation

After the incident:
1. Save the forensic snapshot permanently
2. Update this playbook with anything you learned
3. If the attack was from a Tailscale IP, document which device was compromised and how

---

## Escalation Criteria

### This becomes a lateral movement incident when:

- Source IP is a Tailscale 100.x.x.x address (compromised fleet device)
- Brute force appears on 2+ machines within 5 minutes (security-watch's `checkDistributedAttack` fires)
- A successful login from the brute force IP is found on any machine
- The attacker modified authorized_keys (rule 100102 fires alongside auth failures)

### This becomes a credential theft incident when:

- FIM detects changes to `~/.config/claude-peers/identity.pem` or `token.jwt` (rule 100100, level 12)
- The attacker used the SSH access to read or copy UCAN credentials

### This requires immediate the operator intervention when:

- Any machine shows "quarantined" status from a non-simulated event
- Email subject contains "ACTION REQUIRED" (Tier 3 incident)
- broker-server is the target (broker compromise = full fleet compromise)
- laptop-2 shows activity (not the operator's machine -- any alert here is suspicious by definition)

### Response escalation timeline:

| Time | If not resolved | Action |
|------|----------------|--------|
| 5 min | Automated containment should be complete | Check email, verify IP block |
| 15 min | If login succeeded | Begin eradication |
| 30 min | If lateral movement detected | Isolate all affected machines |
| 1 hour | If root compromise suspected | Begin rebuild |
| 4 hours | If broker-server compromised | Full fleet PKI rotation (see CREDENTIAL_THEFT.md) |

---

## Machine-Specific Notes

| Machine | SSH target | OS | Wazuh | Notes |
|---------|-----------|-----|-------|-------|
| workstation | <workstation-ip> | Arch | Agent | Daily driver. Compromise here = access to all projects via Syncthing |
| broker-server | <broker-ip> | Ubuntu 24.04 | Agent | **BROKER.** Runs all 6 services. Compromise = full fleet compromise. Has Wazuh manager. |
| edge-node | edge-node | Debian (Pi 5) | Agent | Kiosk. Physical access risk. Flash SD to rebuild. |
| workstation-2 | workstation-2-workstation | Arch | Agent | Secondary dev. May not always be online. |
| laptop-1 | <user>@<laptop-1-ip><laptop-1-ip> | macOS 15 | Agent | HFL work, banking. High-value target. macOS forensics differ. |
| iot-device | <iot-device-ip> | Debian (Pi Zero 2W) | AIDE sentinel | Runs as root. 512MB RAM. No Wazuh agent. Physical access risk. Rebuild = re-flash SD. |
| laptop-2 | N/A | macOS | None | **Not the operator's machine.** No agent. Any SSH activity from/to this machine is suspicious. |

---

## Quick Reference Card

```
BRUTE FORCE DETECTED
    |
    +-- Check source IP in email
    |
    +-- 100.x.x.x? --> COMPROMISED FLEET DEVICE --> Escalate immediately
    |                    Remove from Tailscale. Isolate. See Escalation Criteria.
    |
    +-- Public IP? --> HOW IS SSH EXPOSED? --> Fix exposure first
    |
    +-- Private IP? --> LAN attacker --> Physical security issue
    |
    +-- Did any login succeed? (check: last, who, w, journalctl)
    |
    +-- YES --> Full compromise. Eradicate. Possibly rebuild.
    |
    +-- NO --> Containment worked. Verify IP block. Harden.
```
