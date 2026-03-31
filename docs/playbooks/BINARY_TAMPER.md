# Binary Tamper Incident Response Playbook

Sontara Lattice fleet -- last updated 2026-03-28.

**Tier:** 2 (Contain) -- auto-quarantine, forensics, email. No human approval required for containment, but investigation and recovery are manual.

**Wazuh Rules:**
- `100101` (L13, quarantine): `claude-peers` binary modified in `/usr/local/bin/` or `/usr/bin/`
- `100099` (L7, warning): `claude-peers` binary deployed to `~/.local/bin/` (expected deploy path)
- `100200` (L15, quarantine): Compound -- credential change + binary change on same host within 5 minutes

**Fleet machines:**
| Machine | IP | OS | Role | SSH Target |
|---------|----|----|------|------------|
| workstation | <workstation-ip> | Arch | Daily driver | `<workstation-ip>` |
| broker-server | <broker-ip> | Ubuntu 24.04 | Broker, NATS, daemons | `<broker-ip>` |
| edge-node | tailscale | Debian Pi 5 | Kiosk dashboard | `edge-node` |
| workstation-2 | <workstation-2-ip> | Arch | Secondary dev | `workstation-2-workstation` |
| laptop-1 | <laptop-1-ip> | macOS | HFL work | `<user>@<laptop-1-ip><laptop-1-ip>` |
| iot-device | <iot-device-ip> | Debian Pi Zero 2W | Cyberdeck | `<iot-device-ip>` |
| laptop-2 | <laptop-2-ip> | macOS | LLM server (not owned) | N/A |

---

## 1. Detection Signals

### Primary: Wazuh FIM Alert

Rule 100101 fires when `syscheck` detects a change to a file matching `claude-peers` in `/usr/local/bin/` or `/usr/bin/`. The alert arrives via:

1. **Wazuh agent** on the affected machine detects the file change (FIM scan every 300s, or realtime for `~/.local/bin`)
2. **Wazuh manager** (Docker on broker-server) receives the alert, matches rule 100101
3. **wazuh-bridge** tails `~/docker/wazuh/logs/alerts/alerts.json`, parses the alert, publishes a `SecurityEvent` to NATS subject `fleet.security.fim`
4. **Broker** receives the event, maps L13 to severity `quarantine`, immediately quarantines the machine (all API requests from it get 403 `QUARANTINED`)
5. **security-watch** correlates: if rule 100101 fires on 3+ machines within 5 minutes, escalates as distributed attack
6. **response-daemon** classifies as `binary_tamper` (Tier 2), captures forensics with file hash, sends email

### What the alert contains

```json
{
  "type": "fim",
  "severity": "quarantine",
  "level": 13,
  "machine": "edge-node",
  "rule_id": "100101",
  "description": "claude-peers binary TAMPERED in system path: /usr/local/bin/claude-peers",
  "file_path": "/usr/local/bin/claude-peers",
  "timestamp": "2026-03-28T03:14:22Z"
}
```

Wazuh FIM also captures: old checksum, new checksum, file size change, ownership change, permission change. These are in the raw Wazuh alert (check `alerts.json` directly if the SecurityEvent struct doesn't include them).

### Secondary signals to watch for

- Rule 100099 (L7) firing when you did NOT deploy: someone put a binary in `~/.local/bin/claude-peers` without a known deploy
- Rule 100200 (L15) compound: credential file change + binary change on same host = active intrusion in progress
- Unexpected NATS messages from the affected machine after quarantine (the binary may have been replaced with a version that uses a hardcoded NATS token to bypass the broker)

### What you receive

- **Email:** `[fleet-security] CONTAIN on <machine>: binary_tamper` to your-email@example.com
- **Gridwatch:** Machine turns red (quarantined) at `http://<broker-ip>:8888`
- **Forensics:** Snapshot saved to `~/.config/claude-peers/forensics/<machine>-<timestamp>.json` on broker-server

---

## 2. Immediate Triage (First 5 Minutes)

### Severity assessment: claude-peers binary vs system binary

**claude-peers binary tampered** (L13 via rule 100101):
- The attacker knows about the fleet and is targeting it specifically
- The replaced binary could exfiltrate UCAN tokens, inject malicious NATS messages, or pivot to other machines
- Severity: HIGH -- the attacker has fleet-specific knowledge

**System binary tampered** (sudo, ssh, sshd, etc.):
- Not caught by rule 100101 (which only matches `claude-peers`). Would only fire if you add FIM rules for `/usr/bin/sudo`, `/usr/bin/ssh`, etc.
- If a system binary is replaced, the machine is rootkitted. Full rebuild required, no questions.
- Severity: CRITICAL -- assume full compromise

### Step 1: Verify the alert is not a false positive

False positives for rule 100101:
- You deployed `claude-peers` to `/usr/local/bin/` instead of `~/.local/bin/` (the expected deploy path). This is a process error, not an attack.
- A package manager update replaced a binary in `/usr/bin/` that happens to contain "claude-peers" in its path (unlikely but possible on Arch with AUR packages).
- You ran `go install` or `go build` and the output went to a system path.

Check if you or anyone on the team deployed recently:

```bash
# Check git log for recent builds
cd ~/projects/claude-peers && git log --oneline -5

# Check if the deploy script ran recently (on broker-server)
ssh broker-server "journalctl --user --since '2 hours ago' | grep -i 'deploy\|claude-peers'"
```

### Step 2: Check the binary hash against known-good

Known-good hash sources, in order of trust:
1. **Build from source on a trusted machine:**
   ```bash
   cd ~/projects/claude-peers && go build -o /tmp/claude-peers-verify . && sha256sum /tmp/claude-peers-verify
   ```
2. **The forensic snapshot** (captured by response-daemon, includes `md5sum` of the file):
   ```bash
   cat ~/.config/claude-peers/forensics/<machine>-*.json | jq -r '.file_hash'
   ```
3. **Another fleet machine's binary** (only trustworthy if that machine is not also compromised):
   ```bash
   sha256sum ~/.local/bin/claude-peers
   ```

Compare against the tampered binary (DO NOT execute it -- use ssh to run hash on the remote machine):

```bash
# Linux machines
ssh <machine> "sha256sum /usr/local/bin/claude-peers"

# macOS machines
ssh <user>@<laptop-1-ip><laptop-1-ip> "shasum -a 256 /usr/local/bin/claude-peers"
```

### Step 3: Check binary metadata without executing

```bash
# File type (should be ELF 64-bit for linux, Mach-O for macOS)
ssh <machine> "file /usr/local/bin/claude-peers"

# File size (compare against known-good -- significant size difference = replacement, small difference = injection)
ssh <machine> "ls -la /usr/local/bin/claude-peers"

# Modification time
ssh <machine> "stat /usr/local/bin/claude-peers"

# Ownership (should be root:root or user:user depending on install method)
ssh <machine> "ls -la /usr/local/bin/claude-peers"
```

### Decision point

| Finding | Action |
|---------|--------|
| Hash matches known-good, you deployed recently | False positive. Unquarantine. Fix your deploy process to use `~/.local/bin`. |
| Hash does NOT match, file size similar | Trojanized binary (added functionality). Proceed to full investigation. |
| Hash does NOT match, file size very different | Complete replacement. Proceed to full investigation. |
| Binary is not an ELF/Mach-O at all (e.g., shell script) | Obvious attack. Proceed to containment + full machine audit. |
| Rule 100200 also fired (compound) | Active intrusion. Credential + binary change = attacker is on the machine NOW. Skip to containment. |

---

## 3. Containment

The machine is already auto-quarantined by the broker (health score jumped to quarantine tier when L13 event was processed). This means:

- All API requests from the machine to `http://<broker-ip>:7899` return 403 `QUARANTINED`
- The machine's UCAN token is effectively revoked at the broker level
- Other machines can still communicate with each other

### DO NOT execute the tampered binary

The binary at `/usr/local/bin/claude-peers` may be malicious. Do not:
- Run `claude-peers` on the affected machine
- Run `claude-peers status` to "check if it works"
- Copy the binary to another machine and run it there
- Run the binary under strace (it may detect debugging and behave differently)

### Isolate the machine further if needed

If the compound rule 100200 fired, or if you suspect active intrusion:

```bash
# Block all non-Tailscale traffic on the machine (leaves SSH via Tailscale working)
ssh <machine> "sudo iptables -A INPUT -i tailscale0 -j ACCEPT && sudo iptables -A INPUT -i lo -j ACCEPT && sudo iptables -P INPUT DROP"

# Or more aggressive: disconnect from Tailscale entirely (you lose SSH access)
ssh <machine> "sudo tailscale down"
```

**WARNING:** If you `tailscale down`, you need physical access or an out-of-band console to recover. Only do this for machines you can physically reach (workstation, edge-node, iot-device, workstation-2). Do NOT do this for broker-server (the broker).

### Preserve the tampered binary for forensics

```bash
# Copy the tampered binary off the machine BEFORE replacing it
ssh <machine> "cp /usr/local/bin/claude-peers /tmp/claude-peers.tampered"
scp <machine>:/tmp/claude-peers.tampered ~/.config/claude-peers/forensics/claude-peers-tampered-<machine>-$(date +%Y%m%d)
```

---

## 4. Forensic Analysis

### Examine the binary without executing it

All analysis is done on a trusted machine (workstation or broker-server) after copying the tampered binary off.

```bash
TAMPERED=~/.config/claude-peers/forensics/claude-peers-tampered-<machine>-$(date +%Y%m%d)

# File type
file "$TAMPERED"

# SHA-256 for records
sha256sum "$TAMPERED"

# Size comparison
ls -la "$TAMPERED"
ls -la ~/.local/bin/claude-peers

# Strings analysis: look for URLs, IPs, domains that shouldn't be there
strings "$TAMPERED" | grep -iE 'http|https|ftp|\.com|\.io|\.net|\.org' | sort -u

# Look for hardcoded NATS tokens or credentials
strings "$TAMPERED" | grep -iE 'nats://|token|secret|password|key'

# Look for suspicious system calls
strings "$TAMPERED" | grep -iE '/etc/shadow|/etc/passwd|chmod|chown|curl|wget|nc |netcat|reverse.shell'

# Diff the symbol tables (if Go binary, look for unexpected packages)
go tool nm "$TAMPERED" 2>/dev/null | grep -v 'runtime\|reflect\|fmt\|os\|io\|net\|crypto' | head -50

# Compare against known-good symbol table
go tool nm ~/.local/bin/claude-peers 2>/dev/null > /tmp/good-symbols.txt
go tool nm "$TAMPERED" 2>/dev/null > /tmp/tampered-symbols.txt
diff /tmp/good-symbols.txt /tmp/tampered-symbols.txt | head -100
```

### What to look for

| Finding | Interpretation |
|---------|---------------|
| Extra HTTP endpoints in strings | Binary phones home to attacker C2 |
| Hardcoded NATS URL/token | Binary designed to inject fleet events |
| Extra Go packages (unexpected imports) | Trojanized build with added dependencies |
| Shell commands in strings (curl, wget, nc) | Binary runs shell commands for exfiltration |
| Completely different symbol table | Not a modified `claude-peers` at all -- full replacement |
| Same size, slightly different hash | Subtle modification (patched jump instruction, modified constant) |

---

## 5. Investigation: How Did They Get Write Access?

The attacker needed write access to `/usr/local/bin/` (requires root or sudo) or `/usr/bin/` (requires root). Determine the attack vector.

### Check sudo and auth logs

```bash
# Linux (Arch, Ubuntu, Debian)
ssh <machine> "journalctl -u sudo --since '24 hours ago' --no-pager"
ssh <machine> "journalctl -u sshd --since '24 hours ago' --no-pager | tail -50"
ssh <machine> "last -50"
ssh <machine> "who"

# macOS
ssh <user>@<laptop-1-ip><laptop-1-ip> "log show --predicate 'process == \"sudo\"' --last 24h --style compact"
```

### Check for privilege escalation

```bash
# SUID binaries (any unexpected ones?)
ssh <machine> "find / -perm -4000 -type f 2>/dev/null"

# World-writable directories in PATH
ssh <machine> "echo \$PATH | tr ':' '\n' | while read d; do ls -ld \"\$d\" 2>/dev/null; done"

# Check if /usr/local/bin has wrong permissions
ssh <machine> "ls -ld /usr/local/bin"
# Should be: drwxr-xr-x root root

# Check for capability-enhanced binaries
ssh <machine> "getcap -r /usr/local/bin 2>/dev/null"
```

### Check for supply chain attack

If the binary was built from a compromised dependency:

```bash
# Check go.sum for unexpected changes
cd ~/projects/claude-peers
git diff HEAD~10 go.sum

# Check if any dependencies were recently updated
git log --oneline -20 -- go.mod go.sum

# Verify module checksums against Go's checksum database
GONOSUMCHECK= go mod verify
```

### Check for persistence mechanisms the attacker may have installed

The binary tamper may not be the only thing the attacker did.

```bash
# Crontabs
ssh <machine> "crontab -l 2>/dev/null"
ssh <machine> "sudo crontab -l 2>/dev/null"
ssh <machine> "ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ 2>/dev/null"

# Systemd (user and system level)
ssh <machine> "systemctl --user list-unit-files --state=enabled --no-pager"
ssh <machine> "systemctl list-unit-files --state=enabled --no-pager | grep -v '^$'"
ssh <machine> "ls -la ~/.config/systemd/user/"
ssh <machine> "ls -la /etc/systemd/system/ | grep -v '^$'"

# SSH authorized keys (any new entries?)
ssh <machine> "cat ~/.ssh/authorized_keys"
ssh <machine> "cat /root/.ssh/authorized_keys 2>/dev/null"

# Shell profiles (backdoor aliases, sourced scripts)
ssh <machine> "cat ~/.bashrc ~/.bash_profile ~/.zshrc ~/.profile 2>/dev/null | grep -iE 'curl|wget|nc |eval|base64'"

# Check for LD_PRELOAD hijacks
ssh <machine> "cat /etc/ld.so.preload 2>/dev/null"
ssh <machine> "env | grep LD_PRELOAD"

# Tmpfiles (attacker staging area)
ssh <machine> "find /tmp /var/tmp -type f -mtime -1 2>/dev/null"

# Check running processes for anything unexpected
ssh <machine> "ps auxf" # Linux
ssh <machine> "ps aux"  # macOS

# Open network connections
ssh <machine> "ss -tnp"  # Linux
ssh <machine> "lsof -iTCP -n -P"  # macOS
```

### Check package manager logs

```bash
# Arch (pacman)
ssh <machine> "grep -E 'installed|upgraded|removed' /var/log/pacman.log | tail -30"

# Ubuntu/Debian (apt)
ssh <machine> "grep -E 'install|upgrade|remove' /var/log/apt/history.log | tail -30"

# macOS (homebrew)
ssh <user>@<laptop-1-ip><laptop-1-ip> "cat ~/.homebrew/logs/*.log 2>/dev/null | tail -30"
```

---

## 6. Eradication

### Replace the binary from a trusted source

Build fresh from the git repo on a trusted machine (workstation or broker-server, whichever is NOT compromised):

```bash
cd ~/projects/claude-peers
git pull  # Ensure latest
git log --oneline -3  # Verify the commit you expect

# Build
go build -o /tmp/claude-peers-clean .

# Verify the build
sha256sum /tmp/claude-peers-clean
file /tmp/claude-peers-clean

# Deploy to the affected machine's CORRECT path (~/.local/bin, NOT /usr/local/bin)
scp /tmp/claude-peers-clean <machine>:~/.local/bin/claude-peers
ssh <machine> "chmod 755 ~/.local/bin/claude-peers"

# Remove the tampered binary from the system path
ssh <machine> "sudo rm /usr/local/bin/claude-peers"

# Verify
ssh <machine> "sha256sum ~/.local/bin/claude-peers"
ssh <machine> "which claude-peers"  # Should resolve to ~/.local/bin/claude-peers
```

### Cross-platform deploy

```bash
# For macOS machines (cross-compile)
GOOS=darwin GOARCH=arm64 go build -o /tmp/claude-peers-darwin .
scp /tmp/claude-peers-darwin <user>@<laptop-1-ip><laptop-1-ip>:~/.local/bin/claude-peers

# For Pi Zero 2W (ARMv7)
GOOS=linux GOARCH=arm GOARM=7 go build -o /tmp/claude-peers-arm7 .
scp /tmp/claude-peers-arm7 <iot-device-ip>:~/.local/bin/claude-peers

# For Pi 5 (ARM64)
GOOS=linux GOARCH=arm64 go build -o /tmp/claude-peers-arm64 .
scp /tmp/claude-peers-arm64 edge-node:~/.local/bin/claude-peers
```

### Remove persistence mechanisms found during investigation

```bash
# Remove unauthorized crontab entries
ssh <machine> "crontab -e"  # Manually remove bad entries

# Remove unauthorized systemd units
ssh <machine> "systemctl --user stop <bad-service> && systemctl --user disable <bad-service>"
ssh <machine> "rm ~/.config/systemd/user/<bad-service>.service"
ssh <machine> "systemctl --user daemon-reload"

# Remove unauthorized SSH keys
ssh <machine> "vim ~/.ssh/authorized_keys"  # Remove unknown entries

# Remove LD_PRELOAD hijacks
ssh <machine> "sudo rm /etc/ld.so.preload"
```

---

## 7. Full Machine Audit

When a binary tamper is detected, the machine CANNOT be trusted. The binary had root-level write access at some point. Everything on the machine is suspect.

### Rootkit check

```bash
# Install and run rkhunter (Linux only)
ssh <machine> "sudo pacman -S rkhunter && sudo rkhunter --update && sudo rkhunter --check --skip-keypress"  # Arch
ssh <machine> "sudo apt install rkhunter && sudo rkhunter --update && sudo rkhunter --check --skip-keypress"  # Debian/Ubuntu

# Install and run chkrootkit (alternative)
ssh <machine> "sudo pacman -S chkrootkit && sudo chkrootkit"  # Arch
ssh <machine> "sudo apt install chkrootkit && sudo chkrootkit"  # Debian/Ubuntu

# Manual checks that rootkits often tamper with
ssh <machine> "md5sum /usr/bin/ls /usr/bin/ps /usr/bin/netstat /usr/bin/ss /usr/bin/find /usr/bin/who /usr/bin/w 2>/dev/null"
# Compare these against another clean machine of the same OS/arch
```

### Full filesystem scan

```bash
# Find all files modified in the last 24 hours in sensitive directories
ssh <machine> "find /usr/local/bin /usr/bin /usr/sbin /sbin -mtime -1 -type f 2>/dev/null"
ssh <machine> "find /etc -mtime -1 -type f 2>/dev/null"

# Find all SUID/SGID binaries
ssh <machine> "find / -perm -4000 -o -perm -2000 -type f 2>/dev/null"

# Check for hidden files in unexpected places
ssh <machine> "find / -name '.*' -not -path '/home/*' -not -path '/root/*' -not -path '/proc/*' -not -path '/sys/*' -type f 2>/dev/null | head -50"
```

### Process and network audit

```bash
# All processes with full command lines
ssh <machine> "ps auxww"

# All listening ports with process info
ssh <machine> "ss -tlnp"  # Linux
ssh <machine> "lsof -iTCP -sTCP:LISTEN -n -P"  # macOS

# All established connections
ssh <machine> "ss -tnp"  # Linux
ssh <machine> "lsof -iTCP -sTCP:ESTABLISHED -n -P"  # macOS

# Check for processes running from /tmp or /var/tmp
ssh <machine> "ls -la /proc/*/exe 2>/dev/null | grep -E '/tmp|/var/tmp'"

# Loaded kernel modules (Linux only -- look for unknown modules)
ssh <machine> "lsmod"
```

### UCAN credential audit

```bash
# Check if credentials were exfiltrated
ssh <machine> "ls -la ~/.config/claude-peers/"
ssh <machine> "stat ~/.config/claude-peers/identity.pem"
ssh <machine> "stat ~/.config/claude-peers/token.jwt"

# If the attacker had access to these files, they have:
# - The machine's Ed25519 private key (can impersonate this machine)
# - The UCAN token (can make broker API calls as this machine)
# ROTATE IMMEDIATELY if there's any doubt.
```

---

## 8. Recovery

### Decision: Rebuild from Scratch vs Targeted Cleanup

| Criteria | Rebuild | Targeted Cleanup |
|----------|---------|-----------------|
| Root cause identified with certainty | No | Yes |
| Rootkit scanner found nothing | N/A | Required |
| Attacker had root access | Yes (always rebuild) | N/A |
| Only claude-peers binary was touched | Maybe cleanup | Yes |
| Persistence mechanisms found | Yes | N/A |
| Kernel modules tampered | Yes | N/A |
| Machine is broker-server (broker) | Yes -- this is the worst case | Only if root cause is 100% certain |
| Machine is iot-device/edge-node (low value) | Rebuild is fast | Cleanup is fine |

### Targeted cleanup (low severity, root cause known)

1. Replace the binary (see Eradication above)
2. Rotate UCAN credentials:
   ```bash
   # On the affected machine
   ssh <machine> "cd ~/.config/claude-peers && cp identity.pem identity.pem.compromised && cp token.jwt token.jwt.compromised"

   # Generate new keypair
   ssh <machine> "claude-peers init client http://<broker-ip>:7899"

   # Issue new token from broker (on broker-server)
   ssh broker-server "claude-peers issue-token /path/to/<machine>-identity.pub peer-session"

   # Save new token on affected machine
   ssh <machine> "claude-peers save-token <new-jwt>"
   ```
3. Unquarantine:
   ```bash
   claude-peers unquarantine <machine>
   ```
4. Verify:
   ```bash
   ssh <machine> "claude-peers status"
   curl -s -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt)" \
     http://<broker-ip>:7899/machine-health | jq '.<machine>'
   ```

### Full rebuild (high severity, unknown root cause)

For each machine type:

**Arch machines (workstation, workstation-2):**
```bash
# Backup critical data first (from another machine via SCP)
scp <machine>:~/.config/claude-peers/forensics/* /tmp/forensics-backup/
# Reinstall Arch, reapply dotfiles via chezmoi
# Re-deploy claude-peers from trusted build
# Re-issue UCAN credentials
```

**Debian machines (edge-node, iot-device):**
```bash
# Re-flash SD card with clean Debian image
# Re-install Wazuh agent
# Re-deploy claude-peers
# Re-issue UCAN credentials
```

**macOS machines (laptop-1):**
```bash
# Wipe and reinstall macOS from recovery
# Re-install Wazuh agent
# Re-deploy claude-peers
# Re-issue UCAN credentials
```

**broker-server (THE BROKER -- worst case scenario):**
If the broker is compromised, the entire fleet's trust chain is broken. The root key lives on this machine.
```bash
# 1. Stop everything
ssh broker-server "systemctl --user stop claude-peers-broker sontara-wazuh-bridge"
ssh broker-server "docker compose -f ~/docker/wazuh/docker-compose.yml down"

# 2. Backup forensics and data
scp broker-server:~/.config/claude-peers/forensics/* /tmp/forensics-backup/
scp broker-server:~/.claude-peers.db /tmp/db-backup/

# 3. Rebuild the machine from scratch

# 4. Re-initialize the broker (new root key)
claude-peers init broker

# 5. Re-issue ALL fleet tokens (every machine needs a new token)
for machine in workstation edge-node workstation-2 laptop-1 iot-device; do
  claude-peers issue-token /path/to/${machine}-identity.pub peer-session
  # Distribute tokens to each machine
done

# 6. Rotate NATS token (update on every machine)
# 7. Re-deploy Wazuh manager
# 8. Verify each machine can communicate with the new broker
```

---

## 9. Post-Incident Improvements

### Binary signing (not yet implemented)

Add build-time signing so tampered binaries can be detected instantly:

1. Sign the binary with an Ed25519 key at build time: `claude-peers sign-binary`
2. On startup, verify the signature: `claude-peers verify-binary`
3. Wazuh checks can call `claude-peers verify-binary` and alert on failure

### Hash verification on deploy

Add a deploy step that:
1. Builds the binary
2. Computes SHA-256
3. Publishes the hash to NATS subject `fleet.deploy.hash`
4. Each machine verifies the deployed binary matches the published hash

### Immutable system directories

```bash
# On Linux machines, mount /usr/local/bin as read-only
# Add to /etc/fstab:
# /usr/local/bin /usr/local/bin none bind,ro 0 0

# Remount writable only during deploys:
# sudo mount -o remount,rw /usr/local/bin
# ... deploy ...
# sudo mount -o remount,ro /usr/local/bin
```

### Expanded FIM monitoring

Current Wazuh FIM only monitors `claude-peers` in system paths. Expand to cover all binaries:

```xml
<!-- Add to agent.conf shared config -->
<directories check_all="yes" realtime="yes">/usr/local/bin</directories>
<directories check_all="yes">/usr/bin</directories>
<directories check_all="yes">/usr/sbin</directories>
```

### Deploy path enforcement

Always deploy `claude-peers` to `~/.local/bin/` (rule 100099, L7, warning only). Never deploy to `/usr/local/bin/` or `/usr/bin/`. Document this in the deploy script and enforce it in CI.

---

## 10. Testing This Playbook

Use the simulation harness to validate the full detection-response chain:

```bash
# Dry run (no actual changes)
claude-peers sim-attack binary-tamper --target=edge-node --dry-run

# Live test on edge-node (safe, low-priority machine)
claude-peers sim-attack binary-tamper --target=edge-node

# Verify detection
curl -s -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt)" \
  http://<broker-ip>:7899/machine-health | jq '.edge-node'

# The sim-attack command cleans up after itself (unquarantines, removes test files)
```

**NEVER target broker-server** without explicit confirmation -- the sim-attack command will refuse to run against the broker without manual override.
