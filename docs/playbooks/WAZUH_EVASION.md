# Wazuh Evasion Incident Response Playbook

Sontara Lattice fleet -- last updated 2026-03-28.

**Tier:** Varies -- this playbook covers an attacker who has read our Wazuh rules (they are in the public repo at `wazuh/local_rules.xml` and `wazuh/shared_agent.conf`) and specifically crafts attacks to avoid detection.

**Core problem:** Our 14 custom rules are in version control. An attacker who reads the repo knows exactly what we monitor and can work around every rule.

**Fleet machines:**
| Machine | IP | OS | Role | SSH Target |
|---------|----|----|------|------------|
| workstation | <workstation-ip> | Arch | Daily driver | `<workstation-ip>` |
| broker-server | <broker-ip> | Ubuntu 24.04 | Broker, Wazuh manager | `<broker-ip>` |
| edge-node | tailscale | Debian Pi 5 | Kiosk dashboard | `edge-node` |
| workstation-2 | <workstation-2-ip> | Arch | Secondary dev | `workstation-2-workstation` |
| laptop-1 | <laptop-1-ip> | macOS | HFL work | `<user>@<laptop-1-ip><laptop-1-ip>` |
| iot-device | <iot-device-ip> | Debian Pi Zero 2W | Cyberdeck | `<iot-device-ip>` |
| laptop-2 | <laptop-2-ip> | macOS | LLM server (not owned) | N/A |

---

## Our 14 Custom Rules and How to Evade Each

### Rule 100099 (L7): Binary deploy to `~/.local/bin/`
**What it catches:** FIM event matching `claude-peers` AND `/.local/bin/`
**Evasion:** Rename the binary. Deploy as `fleet-agent` or `cp` to `~/.local/bin/fleet-tool`. The regex requires both `claude-peers` in the filename AND `/.local/bin/` in the path.

### Rule 100100 (L12): UCAN credential file modification
**What it catches:** FIM on `identity.pem`, `token.jwt`, `root.pub` in `~/.config/claude-peers/`
**Evasion:** Copy credentials instead of modifying them. `cat ~/.config/claude-peers/identity.pem > /tmp/stolen.pem` generates a READ, not a WRITE to the monitored path. FIM only triggers on modifications to the monitored file, not reads.

### Rule 100101 (L13): Binary tamper in `/usr/local/bin/` or `/usr/bin/`
**What it catches:** FIM matching `claude-peers` AND `/usr/local/bin/|/usr/bin/`
**Evasion:** Same as 100099 -- rename the replacement binary. Or place the trojanized binary in `~/.local/bin/` (caught by 100099 at L7 only, which is just a warning, not quarantine). Or use `LD_PRELOAD` to inject code without touching the binary at all.

### Rule 100102 (L10): SSH key/config modification
**What it catches:** FIM on files matching `id_`, `authorized_keys`, or `config` in `~/.ssh/`
**Evasion:** Add SSH access via a different mechanism: add a `ForceCommand` in `/etc/ssh/sshd_config` (not monitored), or add a user account with SSH access (`useradd` + adding their key to `/home/newuser/.ssh/authorized_keys`, which is outside the FIM scope of `~/.ssh/`).

### Rule 100110 (L10): Shell startup file modification
**What it catches:** FIM on `.bashrc`, `.zshrc`, `.profile`, `.bash_profile`
**Evasion:** Modify `.bash_logout` (not monitored). Add a file to `/etc/profile.d/` (caught by 100112 but only L10). Or modify `~/.config/fish/config.fish` if fish shell is installed. Or add a function to `~/.local/share/bash-completion/` or `~/.bashrc.d/` (not monitored). Or use `~/.pam_environment` for environment variable persistence.

### Rule 100111 (L9): Crontab modification
**What it catches:** FIM on paths containing `/cron`
**Evasion:** Use `at` daemon (`at` command) for one-time scheduled execution. Use systemd timers instead of cron (caught by 100130 but only L9). Or use `inotifywait` in a background process to trigger on file changes.

### Rule 100112 (L10): System environment modification
**What it catches:** FIM on `/etc/environment` and `/etc/profile.d/`
**Evasion:** Use `~/.pam_environment` (not monitored). Set env vars via systemd unit environment directives. Use `LD_PRELOAD` via `/etc/ld.so.preload` (not monitored -- this is the biggest gap).

### Rule 100113 (L11): claude-peers config.json modification
**What it catches:** FIM on `~/.config/claude-peers/config.json`
**Evasion:** Override config via environment variables instead. The config system reads env vars first: `CLAUDE_PEERS_BROKER_URL`, `CLAUDE_PEERS_NATS`, `CLAUDE_PEERS_LLM_URL`. Set these in a systemd unit override or `~/.pam_environment`.

### Rule 100114 (L9): System cron config
**What it catches:** FIM on `/etc/cron.*`
**Evasion:** Same as 100111 -- use `at`, systemd timers, or other scheduling mechanisms.

### Rule 100115 (L12): DNS config modification
**What it catches:** FIM on `/etc/hosts`, `/etc/resolv.conf`, `/etc/nsswitch.conf`
**Evasion:** Modify DNS at the network level (DHCP poisoning, router DNS change). Or use `iptables -t nat` to redirect DNS queries to an attacker's server (iptables rules are not monitored). Or modify systemd-resolved config at `/etc/systemd/resolved.conf` (not monitored).

### Rule 100116 (L11): Go module checksum modification
**What it catches:** FIM on `go.sum`
**Evasion:** Modify `go.mod` (not monitored) to pin a malicious version. Or inject via `GOFLAGS`, `GONOSUMCHECK`, or `GONOSUMDB` environment variables. Or replace the `go` binary itself.

### Rule 100130 (L9): Systemd unit file change
**What it catches:** FIM on paths containing `/systemd/`
**Evasion:** Use other init systems or persistence mechanisms: XDG autostart (`~/.config/autostart/`), login hooks, or kernel modules. Or use `systemd-run --user --scope` for transient units that don't create unit files.

### Rule 100200 (L15): Compound credential + binary change
**What it catches:** Frequency rule -- 2+ `credential_change` events from same source within 300s
**Evasion:** Stagger actions. Modify the binary first, wait 6+ minutes, then touch credentials. The frequency window is 300 seconds.

### Rule 100201 (L13): Compound shell persistence + SSH key change
**What it catches:** Both `shell_persistence` AND `ssh_key_change` from same source within 300s
**Evasion:** Same stagger approach. Or use alternative persistence that doesn't trigger either rule.

---

## What Our Rules DO NOT Catch

### 1. LD_PRELOAD injection
**Attack:** `echo /tmp/evil.so > /etc/ld.so.preload` or `export LD_PRELOAD=/tmp/evil.so`
**Impact:** Every process loads the attacker's shared library. Can hook any function (connect, read, write, exec).
**Why missed:** `/etc/ld.so.preload` is not in the FIM scope. LD_PRELOAD as an env var doesn't touch any monitored file.

### 2. Kernel module loading
**Attack:** `insmod /tmp/rootkit.ko`
**Impact:** Full kernel-level rootkit. Can hide processes, files, network connections from all userspace tools including Wazuh.
**Why missed:** No monitoring on `/lib/modules/` or `modprobe` activity.

### 3. Container escape on broker-server
**Attack:** Exploit Docker socket, escape Wazuh manager container to host.
**Impact:** Root on broker-server from inside a container.
**Why missed:** Docker container activity is not covered by our rules. See CONTAINER_ESCAPE.md playbook.

### 4. NATS message injection
**Attack:** Publish fake security events or fleet events to NATS.
**Impact:** Can trigger false quarantines (DoS), inject false data into fleet-digest, manipulate daemon triggers.
**Why missed:** NATS auth is a single shared token. No per-publisher verification.

### 5. Timestamp manipulation
**Attack:** `touch -t 202501010000 /usr/local/bin/claude-peers` -- set mtime to an old date.
**Impact:** FIM may not detect the change if the attacker modifies the file and resets the timestamp between FIM scans (300s interval for non-realtime paths).
**Why missed:** Non-realtime FIM paths only check on interval. If the file's mtime/size/hash are restored before the next scan, the change is invisible.

### 6. Wazuh agent disable
**Attack:** `sudo systemctl stop wazuh-agent` or `kill -9 $(pidof wazuh-agentd)`
**Impact:** All detection on that machine stops.
**Why missed:** Wazuh agent can't report its own death. The manager notices after the agent keepalive timeout (default: 10 minutes), but there's no rule to automatically quarantine a machine whose agent goes silent.

### 7. Network-level attacks
**Attack:** ARP spoofing, MITM on non-Tailscale traffic, rogue DHCP.
**Impact:** Intercept unencrypted traffic, redirect DNS, capture credentials for non-mesh services.
**Why missed:** No network monitoring rules. Wazuh is configured for host-based detection only.

### 8. Process hollowing / memory-only malware
**Attack:** Inject code into a running process, never write to disk.
**Impact:** Runs as a trusted process, no file changes to detect.
**Why missed:** FIM is file-based. No process behavior monitoring configured.

---

## 1. Detection Signals for Evasion Attempts

Even if specific rules are evaded, look for these meta-signals:

### Wazuh agent silence

```bash
# Check agent connectivity from the manager
ssh broker-server "docker exec wazuh-manager /var/ossec/bin/agent_control -l"
# Look for agents showing "Disconnected" status

# Check agent keepalive times
ssh broker-server "docker exec wazuh-manager /var/ossec/bin/agent_control -i 001"  # edge-node
ssh broker-server "docker exec wazuh-manager /var/ossec/bin/agent_control -i 002"  # workstation
ssh broker-server "docker exec wazuh-manager /var/ossec/bin/agent_control -i 003"  # workstation-2
ssh broker-server "docker exec wazuh-manager /var/ossec/bin/agent_control -i 004"  # broker-server
```

### Unusual process trees

```bash
# Compare process lists across fleet (look for outliers)
for machine in <workstation-ip> <broker-ip> edge-node workstation-2-workstation; do
  echo "=== $machine ==="
  ssh "$machine" "ps auxf --no-headers | wc -l" 2>/dev/null
done
```

### LD_PRELOAD check

```bash
for machine in <workstation-ip> <broker-ip> edge-node workstation-2-workstation <iot-device-ip>; do
  echo "=== $machine ==="
  ssh "$machine" "cat /etc/ld.so.preload 2>/dev/null; echo '---'; env | grep LD_PRELOAD 2>/dev/null; echo '---'; grep -r LD_PRELOAD /etc/environment /etc/profile.d/ ~/.pam_environment 2>/dev/null" 2>/dev/null
done
```

### Kernel module audit

```bash
for machine in <workstation-ip> <broker-ip> edge-node workstation-2-workstation <iot-device-ip>; do
  echo "=== $machine ==="
  ssh "$machine" "lsmod | wc -l; lsmod | grep -viE 'intel|amd|nvidia|usb|hid|net|snd|bluetooth|video|input|i2c|gpio|spi|thermal|acpi'" 2>/dev/null
done
```

---

## 2. Immediate Triage

If you suspect Wazuh evasion:

### Step 1: Verify Wazuh agents are running

```bash
ssh broker-server "docker exec wazuh-manager /var/ossec/bin/agent_control -l"
```

Any agent not showing as "Active" is immediately suspicious.

### Step 2: Check for LD_PRELOAD on all machines

```bash
for machine in <workstation-ip> <broker-ip> edge-node workstation-2-workstation <iot-device-ip>; do
  echo "=== $machine ==="
  ssh "$machine" "cat /etc/ld.so.preload 2>/dev/null || echo 'clean'; env | grep LD_PRELOAD || echo 'clean'" 2>/dev/null
done
```

### Step 3: Check for timestomped files

```bash
# On suspected machine -- look for files with timestamps that don't match expected patterns
ssh <machine> "find /usr/local/bin ~/.local/bin ~/.config/claude-peers -type f -exec stat --format='%n %y %z' {} \;" 2>/dev/null
# Compare modify time (%y) vs change time (%z) -- if ctime > mtime significantly, timestomping occurred
```

### Step 4: Run manual FIM

Force an immediate Wazuh syscheck scan:

```bash
ssh broker-server "docker exec wazuh-manager /var/ossec/bin/agent_control -r -a"
# Wait 60 seconds for results
```

---

## 3. Containment

### If Wazuh agent was killed on a machine

```bash
# Restart the agent remotely
ssh <machine> "sudo systemctl restart wazuh-agent"

# Verify it reconnects
ssh broker-server "docker exec wazuh-manager /var/ossec/bin/agent_control -i <agent-id>"
```

### If LD_PRELOAD was set

```bash
# Remove the preload
ssh <machine> "sudo rm -f /etc/ld.so.preload"
ssh <machine> "unset LD_PRELOAD"

# Check running processes -- any process started while LD_PRELOAD was active is compromised
# Restart all critical services
ssh <machine> "sudo systemctl restart sshd wazuh-agent"
ssh <machine> "systemctl --user restart claude-peers-server" 2>/dev/null
```

### If kernel module was loaded

```bash
# List loaded modules
ssh <machine> "lsmod"

# Remove suspicious module
ssh <machine> "sudo rmmod <module-name>"

# If a rootkit kernel module was loaded, the machine cannot be trusted
# The rootkit may be hiding itself from lsmod
# Full machine rebuild required
```

---

## 4. Investigation

### Audit for all known evasion techniques simultaneously

```bash
SSH_TARGET="<machine>"

# 1. LD_PRELOAD
ssh "$SSH_TARGET" "cat /etc/ld.so.preload 2>/dev/null"
ssh "$SSH_TARGET" "grep -r LD_PRELOAD /etc/ /home/ 2>/dev/null"

# 2. Alternative persistence (not caught by our rules)
ssh "$SSH_TARGET" "ls ~/.config/autostart/ 2>/dev/null"
ssh "$SSH_TARGET" "ls ~/.pam_environment 2>/dev/null"
ssh "$SSH_TARGET" "cat /etc/systemd/resolved.conf 2>/dev/null"
ssh "$SSH_TARGET" "ls /etc/xdg/autostart/ 2>/dev/null"

# 3. Renamed binaries
ssh "$SSH_TARGET" "ls -la ~/.local/bin/ /usr/local/bin/" 2>/dev/null
# Look for recently modified binaries with unfamiliar names

# 4. Transient systemd units
ssh "$SSH_TARGET" "systemctl --user list-units --type=service --state=running --no-pager"
ssh "$SSH_TARGET" "systemctl list-units --type=scope --state=running --no-pager"

# 5. iptables NAT rules (DNS redirect)
ssh "$SSH_TARGET" "sudo iptables -t nat -L -n 2>/dev/null"

# 6. at jobs
ssh "$SSH_TARGET" "atq 2>/dev/null"

# 7. Config override via env vars
ssh "$SSH_TARGET" "env | grep CLAUDE_PEERS"
ssh "$SSH_TARGET" "cat /etc/environment 2>/dev/null"

# 8. Unusual open files
ssh "$SSH_TARGET" "lsof -i -n -P 2>/dev/null | grep -v ESTABLISHED | grep -v LISTEN | head -20"
```

---

## 5. Post-Incident Improvements

### Add Wazuh agent health monitoring

Create a rule or external script that checks agent connectivity and quarantines silent machines:

```bash
# Cron job on broker-server, every 5 minutes:
# Check agent status, publish NATS event if agent is disconnected
docker exec wazuh-manager /var/ossec/bin/agent_control -l | grep -i disconnected
# If any disconnected, publish fleet.security.agent_down event
```

### Add LD_PRELOAD monitoring

Add to `wazuh/shared_agent.conf`:

```xml
<directories check_all="yes" realtime="yes">/etc/ld.so.preload</directories>
```

Add to `wazuh/local_rules.xml`:

```xml
<rule id="100141" level="14">
  <if_group>syscheck</if_group>
  <match type="pcre2">ld\.so\.preload</match>
  <description>QUARANTINE: LD_PRELOAD file modified (library injection): $(file)</description>
  <group>fim,rootkit,quarantine,</group>
</rule>
```

### Expand FIM to cover evasion paths

```xml
<!-- Alternative persistence locations -->
<directories check_all="yes" realtime="yes">~/.config/autostart</directories>
<directories check_all="yes" realtime="yes">~/.pam_environment</directories>
<directories check_all="yes">/etc/ld.so.preload</directories>
<directories check_all="yes">/etc/systemd/resolved.conf</directories>
<directories check_all="yes">/etc/ssh/sshd_config</directories>
<directories check_all="yes">/etc/ssh/sshd_config.d</directories>
```

### Add behavioral detection beyond FIM

FIM is necessary but insufficient. Add:

1. **Process monitoring:** Alert on new listening ports, unexpected outbound connections
2. **Login anomaly detection:** Alert on logins from new source IPs (Wazuh has built-in rules for this)
3. **Command auditing:** Enable `auditd` on Linux machines, log all `exec` calls
4. **Kernel module monitoring:** Alert on `insmod`/`modprobe` via auditd

### Move sensitive rules to a private location

The custom rules are in the public repo. Consider:

1. Keep generic rules in the repo (educational value, easy deployment)
2. Add additional "canary" rules that are NOT in the repo -- these catch attackers who evade only the published rules
3. Implement decoy files (honeypots) that generate alerts when accessed -- an attacker avoiding known monitored paths may still trigger these

### Implement Wazuh active response

Configure Wazuh to automatically block IPs and quarantine machines when high-severity rules fire, instead of relying solely on the NATS pipeline:

```xml
<!-- ossec.conf on manager -->
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100101,100200,100201</rules_id>
  <timeout>3600</timeout>
</active-response>
```

This provides a backup response mechanism that doesn't depend on the wazuh-bridge, NATS, or the broker being operational.
