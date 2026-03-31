# Playbook 5: Rogue Systemd Service

When Wazuh rule 100130 fires, a systemd unit file was created or modified. This could be a legitimate deployment, a package update, or an attacker establishing persistence. This playbook covers the full lifecycle from alert to verified clean.

## Background: How Attackers Use Systemd

Systemd is the most common persistence mechanism on modern Linux. An attacker who gains shell access will drop a unit file to survive reboots, auto-restart on crash, and blend in with legitimate services.

**User-level units** (`~/.config/systemd/user/`): No root required. Any process running as `user` can create these. They start automatically via `systemctl --user enable`. They survive reboots if lingering is enabled (`loginctl enable-linger user`). This is the most likely vector on our fleet because all machines run services as the `user` user.

**System-level units** (`/etc/systemd/system/`): Requires root. More suspicious if unexpected because normal deployments on this fleet use user-level units. Attackers who escalate to root will prefer this path because system units start before any user logs in.

**Timer-based persistence**: Instead of a `.service` file, attackers create a `.timer` that triggers a `.service` on a schedule. This avoids the service being constantly visible in `systemctl status`. The timer fires, runs the payload, exits. Harder to catch in a snapshot of running processes.

**Socket activation**: A `.socket` unit listens on a port and spawns a `.service` on connection. The service is not running until someone connects. Useful for backdoors that appear dormant.

**What makes a unit file suspicious**:
- `ExecStart` points to a binary in `/tmp`, `/var/tmp`, `/dev/shm`, or a hidden directory
- `ExecStart` uses `bash -c` with base64-encoded or obfuscated commands
- `Restart=always` with `RestartSec=5` (auto-restart backdoor)
- `WantedBy=default.target` or `multi-user.target` (starts on boot)
- File ownership does not match expected user
- File was created at an unusual hour
- The unit name mimics a legitimate service (typosquatting: `dbus-daemon.service` vs `dbus.service`)
- `ExecStartPre` or `ExecStartPost` running additional hidden commands
- `Environment` or `EnvironmentFile` pointing to suspicious paths
- Network-facing service (`Type=notify` or socket-activated) that was not part of any deployment

## Detection Signals

| Signal | Source | Details |
|--------|--------|---------|
| Wazuh rule 100130 | FIM via wazuh-bridge | Level 9 (warning), +1 health score. Alert includes the file path. |
| FIM paths monitored | `/etc/systemd/system/`, `~/.config/systemd/user/` | Realtime on broker-server and edge-node. 5-minute scan cycle on Arch machines (workstation, workstation-2). |
| NATS subject | `fleet.security.fim` | The wazuh-bridge publishes the full alert including file path and change type (added/modified/deleted). |
| Gridwatch | Dashboard at `http://<broker-ip>:8888` | Machine turns yellow if health score accumulates from repeated warnings. |
| Email | `[fleet-security] WARNING on <machine>: rogue_service` | Unit file contents included inline. |

**Important**: The health score impact is only +1 per event. A single rogue service alert will NOT quarantine the machine. If you see a machine go yellow from accumulated warnings, check if multiple unit files were created -- that is more suspicious than a single change.

## Immediate Triage (First 5 Minutes)

### Step 1: Read the alert

The email from the response daemon includes the unit file contents. Read it first. If you do not have the email, pull the alert from the forensics directory:

```bash
# On the affected machine
ls -lt ~/.config/claude-peers/forensics/ | head -5
cat ~/.config/claude-peers/forensics/<machine>-<latest-timestamp>.json | python3 -m json.tool
```

### Step 2: Read the unit file

```bash
# Replace <machine> with: workstation, broker-server, edge-node, workstation-2, laptop-1, iot-device
# Replace <unit-file-path> with the path from the alert

# System-level unit
ssh <machine> "cat /etc/systemd/system/<service-name>.service"

# User-level unit
ssh <machine> "cat ~/.config/systemd/user/<service-name>.service"
```

### Step 3: Answer these questions

1. **What does ExecStart point to?** Read the binary path. Is it a known binary? Is it in a suspicious location?
2. **Who created it?** Check file metadata:
   ```bash
   ssh <machine> "stat <unit-file-path>"
   ```
   Look at `Birth` (creation time) and `Modify` time. Was this during a known deployment window?
3. **Is it enabled?**
   ```bash
   ssh <machine> "systemctl --user is-enabled <service-name> 2>/dev/null; systemctl is-enabled <service-name> 2>/dev/null"
   ```
4. **Is it running right now?**
   ```bash
   ssh <machine> "systemctl --user status <service-name> 2>/dev/null; systemctl status <service-name> 2>/dev/null"
   ```

## Classification

| Evidence | Verdict | Action |
|----------|---------|--------|
| ExecStart points to a known binary (claude-peers, sontara-*, litellm, etc.) AND you remember deploying it | **Legitimate** | No action. Log and close. |
| ExecStart points to a binary installed by a package manager (check with `pacman -Qo` on Arch or `dpkg -S` on Debian) | **Legitimate** | No action. Log and close. |
| ExecStart points to an unknown binary in a normal path (/usr/local/bin, ~/.local/bin) AND creation time correlates with a known SSH session | **Suspicious, likely legitimate** | Investigate the binary (Step 4 below). |
| ExecStart points to a binary in /tmp, /var/tmp, /dev/shm, or a hidden directory | **Malicious until proven otherwise** | Skip to Containment immediately. |
| ExecStart uses bash -c with encoded/obfuscated content | **Malicious** | Skip to Containment immediately. |
| Unit file name mimics a system service but is slightly different | **Malicious** | Skip to Containment immediately. |
| You did not deploy anything recently and cannot explain the file | **Suspicious** | Full investigation (Step 4). |

## Investigation

### Step 4: Investigate on Linux (workstation, broker-server, edge-node, workstation-2, iot-device)

**List all running user services:**
```bash
ssh <machine> "systemctl --user list-units --type=service --state=running"
```

**List all user timers (timer-based persistence):**
```bash
ssh <machine> "systemctl --user list-timers --all"
```

**List all system-level services (not default):**
```bash
ssh <machine> "systemctl list-unit-files --type=service --state=enabled | grep -v '/usr/lib/systemd'"
```

**Check the binary that ExecStart points to:**
```bash
# Get the binary path from the unit file
BINARY=$(ssh <machine> "grep ExecStart <unit-file-path> | head -1 | sed 's/ExecStart=//' | awk '{print \$1}'")

# File type
ssh <machine> "file $BINARY"

# SHA256 hash (save this for comparison)
ssh <machine> "sha256sum $BINARY"

# Strings analysis (look for URLs, IPs, API keys, base64)
ssh <machine> "strings $BINARY | grep -iE 'http|https|api|key|token|password|base64|/dev/tcp|nc |ncat|curl|wget' | head -30"

# File permissions and ownership
ssh <machine> "ls -la $BINARY"
```

**Check if the service has network access:**
```bash
# Get the PID
PID=$(ssh <machine> "systemctl --user show -p MainPID <service-name> 2>/dev/null | cut -d= -f2")

# If system-level
PID=$(ssh <machine> "systemctl show -p MainPID <service-name> 2>/dev/null | cut -d= -f2")

# Check listening sockets for that PID
ssh <machine> "ss -tlnp | grep pid=$PID"

# Check established connections
ssh <machine> "ss -tnp | grep pid=$PID"
```

**Check if it is communicating with external (non-Tailscale) IPs:**
```bash
ssh <machine> "ss -tnp | grep pid=$PID | grep -v '100\.\|127\.0\.0\.1\|::1'"
```
Any connections to IPs outside the 100.x.x.x Tailscale range or localhost are suspicious.

**Check recent journal logs for the service:**
```bash
ssh <machine> "journalctl --user -u <service-name> --since '24 hours ago' --no-pager | tail -50"
```

**Check what process created the unit file (if auditd is running):**
```bash
ssh <machine> "ausearch -f <unit-file-path> 2>/dev/null | tail -20"
```

### Step 5: Investigate on macOS (laptop-1, laptop-2)

macOS does not use systemd. The equivalent persistence mechanism is launchd. If a Wazuh alert fires for a macOS machine about persistence, check launchd instead.

**List all non-Apple launch agents and daemons:**
```bash
ssh laptop-1 "launchctl list | grep -v 'com.apple'"
```

**Check user-level launch agents:**
```bash
ssh laptop-1 "ls -la ~/Library/LaunchAgents/"
```

**Check system-level launch daemons:**
```bash
ssh laptop-1 "ls -la /Library/LaunchDaemons/"
ssh laptop-1 "ls -la /Library/LaunchAgents/"
```

**Read a specific plist:**
```bash
ssh laptop-1 "cat ~/Library/LaunchAgents/<service>.plist"
```

**Get details on a running service:**
```bash
ssh laptop-1 "launchctl print gui/$(id -u)/<service-label>"
# Or for system services:
ssh laptop-1 "sudo launchctl print system/<service-label>"
```

**Check if a launch agent has network access:**
```bash
ssh laptop-1 "lsof -i -n -P | grep <process-name>"
```

## Containment

Do NOT delete the unit file yet. It is evidence.

### Stop and disable the service

**Linux (user-level):**
```bash
ssh <machine> "systemctl --user stop <service-name>"
ssh <machine> "systemctl --user disable <service-name>"
```

**Linux (system-level):**
```bash
ssh <machine> "sudo systemctl stop <service-name>"
ssh <machine> "sudo systemctl disable <service-name>"
```

**macOS:**
```bash
ssh laptop-1 "launchctl bootout gui/$(id -u)/<service-label>"
```

### Kill the process if it is still running

```bash
ssh <machine> "systemctl --user kill <service-name> 2>/dev/null; pkill -f <binary-name>"
```

### Preserve evidence

```bash
# Copy the unit file to forensics
ssh <machine> "cp <unit-file-path> ~/.config/claude-peers/forensics/<service-name>.service.evidence"

# Copy the binary to forensics
ssh <machine> "cp <binary-path> ~/.config/claude-peers/forensics/<service-name>.binary.evidence"

# Capture the process tree and network state at time of containment
ssh <machine> "ps auxf > ~/.config/claude-peers/forensics/ps-$(date +%s).txt"
ssh <machine> "ss -tlnp > ~/.config/claude-peers/forensics/ss-$(date +%s).txt"
```

## Eradication

### Remove the rogue service

```bash
# Remove the unit file
ssh <machine> "rm <unit-file-path>"

# Remove the binary it pointed to
ssh <machine> "rm <binary-path>"

# Reload systemd to clear the removed unit
ssh <machine> "systemctl --user daemon-reload"
# Or for system-level:
ssh <machine> "sudo systemctl daemon-reload"
```

### Check for companion persistence

An attacker who installed a systemd service likely installed other persistence mechanisms too. Check all of these:

```bash
# Cron
ssh <machine> "crontab -l 2>/dev/null"
ssh <machine> "ls /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ 2>/dev/null"

# Shell RC files (look for recently added lines)
ssh <machine> "tail -20 ~/.bashrc ~/.zshrc ~/.profile ~/.bash_profile 2>/dev/null"

# SSH authorized_keys (look for keys you do not recognize)
ssh <machine> "cat ~/.ssh/authorized_keys"

# Other systemd units created around the same time
ssh <machine> "find ~/.config/systemd/user/ /etc/systemd/system/ -newer <unit-file-path> -o -newermt '$(stat -c %y <unit-file-path> | cut -d. -f1)' 2>/dev/null"

# Suspicious files in temp directories
ssh <machine> "find /tmp /var/tmp /dev/shm -type f -newer <unit-file-path> 2>/dev/null"

# Check for LD_PRELOAD hijacking
ssh <machine> "cat /etc/ld.so.preload 2>/dev/null; echo \$LD_PRELOAD"
ssh <machine> "grep -r LD_PRELOAD /etc/environment /etc/profile.d/ 2>/dev/null"
```

## Recovery

### Full systemd audit

Run this on the affected machine to verify no other rogue services remain:

```bash
# All user-level enabled services
ssh <machine> "systemctl --user list-unit-files --state=enabled --type=service"

# All user-level timers
ssh <machine> "systemctl --user list-timers --all"

# All system-level enabled services (compare against known baseline)
ssh <machine> "systemctl list-unit-files --state=enabled --type=service"

# All system-level timers
ssh <machine> "systemctl list-timers --all"

# Look for unit files not owned by a package (Arch)
ssh workstation "find /etc/systemd/system/ -maxdepth 1 -type f -exec pacman -Qo {} \; 2>&1 | grep 'not owned'"
ssh workstation-2 "find /etc/systemd/system/ -maxdepth 1 -type f -exec pacman -Qo {} \; 2>&1 | grep 'not owned'"

# Look for unit files not owned by a package (Debian/Ubuntu)
ssh broker-server "find /etc/systemd/system/ -maxdepth 1 -type f -exec dpkg -S {} \; 2>&1 | grep 'not found'"
ssh edge-node "find /etc/systemd/system/ -maxdepth 1 -type f -exec dpkg -S {} \; 2>&1 | grep 'not found'"
```

### Known legitimate user-level services on this fleet

Reference list. If a user-level service is NOT on this list, investigate it.

| Machine | Expected User Services |
|---------|----------------------|
| broker-server | sontara-broker, sontara-wazuh-bridge, sontara-response, sontara-security-watch, sontara-daemons, litellm |
| workstation | claude-peers MCP server (started by Claude Code, not a persistent unit) |
| edge-node | sontara-gridwatch |
| workstation-2 | claude-peers MCP server (started by Claude Code) |
| iot-device | sontara-lite, voice-assistant |
| laptop-1 | None expected as persistent services |

### Verify machine health

```bash
curl -s -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt)" \
  http://<broker-ip>:7899/machine-health | python3 -m json.tool
```

If the machine accumulated enough warnings to reach degraded status, and you have confirmed the alert was resolved:

```bash
claude-peers unquarantine <machine>
```

## Simulation Testing

Test this playbook using the simulation harness:

```bash
# Dry run
claude-peers sim-attack rogue-service --target=edge-node --dry-run

# Live test
claude-peers sim-attack rogue-service --target=edge-node
```

The simulation creates a test unit file in `~/.config/systemd/user/`, waits for Wazuh detection, verifies the alert propagates through the pipeline, then cleans up.
