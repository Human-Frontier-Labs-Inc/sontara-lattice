# Playbook: Clipboard and Keylogger Attacks

**System:** Sontara Lattice (claude-peers) fleet
**Last updated:** 2026-03-28
**Audience:** the operator (fleet operator)
**Severity tier:** Tier 3 (Approval Required) -- passive credential capture

---

## Table of Contents

1. [Attack Model](#attack-model)
2. [What Gets Captured](#what-gets-captured)
3. [Detection Signals](#detection-signals)
4. [Immediate Triage (0-5 minutes)](#immediate-triage)
5. [Investigation](#investigation)
6. [Containment](#containment)
7. [Recovery](#recovery)
8. [Decision Tree](#decision-tree)
9. [Machine-Specific Notes](#machine-specific-notes)
10. [Monitoring Gaps](#monitoring-gaps)
11. [Hardening Recommendations](#hardening-recommendations)

---

## Attack Model

Fleet machines include both Linux (Arch, Debian) and macOS systems. Each platform has different input capture mechanisms an attacker can exploit.

### Linux Attack Vectors (workstation, workstation-2, edge-node, iot-device)

**Keylogging:**

| Method | Requires | Detection Difficulty |
|--------|----------|---------------------|
| `/dev/input/event*` reader | Read access to input devices (root or `input` group) | Medium -- process has open fd on /dev/input |
| `xinput test` | X11 session (workstation/workstation-2 use Hyprland/Wayland, so X11 is not default) | Low -- visible process |
| `libinput debug-events` | Root or input group membership | Medium |
| `evtest` | Root or input group membership | Medium |
| eBPF keylogger | Root (CAP_BPF) | High -- embedded in kernel |
| LD_PRELOAD hooking | Write access to shell config or `/etc/ld.so.preload` | High -- intercepts library calls |
| Wayland compositor hook | Access to Wayland socket | High -- Hyprland-specific |

**Clipboard monitoring:**

| Method | Requires | Detection Difficulty |
|--------|----------|---------------------|
| `wl-paste --watch` | Wayland session (workstation, workstation-2) | Low -- visible process |
| `xclip -selection clipboard -o` polling | X11 session | Low -- repeated process calls |
| `xsel --clipboard` polling | X11 session | Low |
| D-Bus clipboard monitoring | Session D-Bus access | Medium |

### macOS Attack Vectors (laptop-1, laptop-2)

**Keylogging:**

| Method | Requires | Detection Difficulty |
|--------|----------|---------------------|
| IOKit HID API | Accessibility permissions (TCC) | Medium -- check TCC.db |
| CGEventTap | Accessibility permissions | Medium |
| `Input Monitoring` permission apps | User grants permission | Low -- visible in System Settings |

**Clipboard monitoring:**

| Method | Requires | Detection Difficulty |
|--------|----------|---------------------|
| `pbpaste` polling | No special permissions | Low -- repeated process |
| NSPasteboard observer | No special permissions | Medium -- library-level |
| AppleScript clipboard access | Script execution | Low |

### What the CLAUDE.md Instructions Say

The `CLAUDE.md` instructions include: "Whenever user asks for a command, copy it to the clipboard for convenience." This means tokens, passwords, and sensitive commands routinely pass through the clipboard as part of normal workflow.

---

## What Gets Captured

### Keylogger Captures

| Activity | Data Exposed |
|----------|-------------|
| SSH password entry (if password auth is used anywhere) | SSH passwords |
| 1Password master password | Access to all shared credentials |
| Sudo password | Root access on the machine |
| Browser login forms | Web service credentials |
| Terminal input | Commands including `claude-peers save-token <jwt>`, API keys pasted into prompts |
| Claude Code conversations | Prompts containing sensitive context, file contents, architecture details |

### Clipboard Captures

| Activity | Data Exposed |
|----------|-------------|
| `claude-peers save-token <jwt>` | UCAN JWT token |
| Copy-paste from 1Password | Any credential from the vault |
| Commands copied to clipboard (per CLAUDE.md instruction) | All commands issued to Claude, which may include `curl` with auth headers |
| SSH keys copied between machines | Private key material |
| .env contents | API keys, database URLs, secrets |
| Source code copy-paste | Intellectual property |

---

## Detection Signals

### Primary: Suspicious Processes Accessing Input Devices

**CRITICAL GAP: There is currently NO input device monitoring on any fleet machine.** No Wazuh rules, no daemon checks, no process auditing for /dev/input access.

Manual check:
```bash
# Linux: check for processes reading input devices
# On workstation/workstation-2 (Arch):
ls -la /dev/input/event* 2>/dev/null
# Check who has them open
for dev in /dev/input/event*; do
  fuser "$dev" 2>/dev/null | while read -r pid; do
    echo "$dev -> PID $pid -> $(ps -p $pid -o comm= 2>/dev/null)"
  done
done

# Check for known keylogger processes
pgrep -fa "evtest\|xinput.*test\|libinput.*debug\|logkeys\|keylogger" 2>/dev/null

# Check for clipboard watchers
pgrep -fa "wl-paste.*watch\|xclip\|xsel\|pbpaste" 2>/dev/null
```

### Secondary: LD_PRELOAD Hooks

```bash
# Check for system-wide preload
cat /etc/ld.so.preload 2>/dev/null

# Check for per-user preload in shell configs
grep -r 'LD_PRELOAD' ~/.bashrc ~/.zshrc ~/.profile ~/.bash_profile /etc/environment /etc/profile.d/ 2>/dev/null

# Check current environment
env | grep LD_PRELOAD
```

### Tertiary: macOS TCC Database (laptop-1, laptop-2)

```bash
# Check which apps have Input Monitoring permission
ssh laptop-1 "sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \"
SELECT client, auth_value, auth_reason
FROM access
WHERE service = 'kTCCServiceListenEvent'
\"" 2>/dev/null

# Check which apps have Accessibility permission (required for CGEventTap)
ssh laptop-1 "sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \"
SELECT client, auth_value, auth_reason
FROM access
WHERE service = 'kTCCServiceAccessibility'
\"" 2>/dev/null
```

### Quaternary: Unusual Network Traffic from Input Capture

```bash
# Check for processes that are both reading input AND making network connections
# This is the smoking gun -- a keylogger that phones home
lsof -i -P 2>/dev/null | while read -r line; do
  pid=$(echo "$line" | awk '{print $2}')
  if [ -n "$pid" ] && ls -l /proc/$pid/fd 2>/dev/null | grep -q '/dev/input'; then
    echo "INPUT+NETWORK: $line"
  fi
done
```

---

## Immediate Triage (0-5 minutes)

### Step 1: Scan for keylogger and clipboard monitor processes

```bash
# Comprehensive scan on the suspected machine
echo "=== INPUT DEVICE READERS ==="
for dev in /dev/input/event*; do
  pids=$(fuser "$dev" 2>/dev/null)
  if [ -n "$pids" ]; then
    for pid in $pids; do
      cmd=$(ps -p $pid -o cmd= 2>/dev/null)
      echo "  $dev -> PID $pid: $cmd"
    done
  fi
done

echo ""
echo "=== SUSPICIOUS PROCESSES ==="
ps aux | grep -iE 'keylog|evtest|xinput|libinput.*debug|logkeys|wl-paste.*watch|xclip|xsel|pbpaste|clipboard|input.*monitor' | grep -v grep

echo ""
echo "=== LD_PRELOAD ==="
cat /etc/ld.so.preload 2>/dev/null || echo "  No system preload"
grep -r 'LD_PRELOAD' ~/.bashrc ~/.zshrc ~/.profile ~/.bash_profile /etc/environment /etc/profile.d/ 2>/dev/null || echo "  No user preload"

echo ""
echo "=== OPEN FILES ON /dev/input ==="
lsof /dev/input/* 2>/dev/null

echo ""
echo "=== KERNEL MODULES (eBPF/kprobes) ==="
lsmod 2>/dev/null | grep -iE 'bpf|kprobe|keylog' || echo "  No suspicious modules"
```

### Step 2: Check for data exfiltration from the capture tool

```bash
# Check if any suspicious process has network connections
for pid in $(pgrep -f 'keylog\|evtest\|clipboard\|input.*monitor' 2>/dev/null); do
  echo "PID $pid network connections:"
  ls -l /proc/$pid/fd 2>/dev/null | grep socket
  ss -tnp 2>/dev/null | grep "pid=$pid"
done

# Check for files being written (log files from keyloggers)
find /tmp /var/tmp /dev/shm ~/.cache -name "*.log" -o -name "*.txt" -newer /proc/1/status 2>/dev/null | head -20
```

### Step 3: Kill identified keylogger/clipboard monitor

```bash
# Kill the process
kill <pid>

# If it respawns, check what's restarting it
cat /proc/<pid>/status 2>/dev/null | grep PPid
# Then investigate the parent process
```

---

## Investigation

### Determine how long the capture was active

```bash
# Process start time
ps -p <pid> -o lstart= 2>/dev/null

# Check when the binary was placed on disk
stat <binary-path>

# Check Wazuh FIM for file creation events
ssh broker-server "journalctl --user -u sontara-wazuh-bridge --since '7 days ago' --no-pager 2>/dev/null | grep '<binary-name>'"
```

### Determine what was captured

```bash
# Find the capture output file
# Common keylogger output locations:
find /tmp /var/tmp /dev/shm ~/.cache ~/. -name "*.log" -o -name "*.key" -o -name "*.capture" 2>/dev/null | head -20

# Check for network exfiltration of captured data
# Review iptables log or netstat output for the keylogger PID
cat /var/log/iptables.log 2>/dev/null | grep <pid>

# Check if the capture was sent via peer messages
ssh broker-server "sqlite3 ~/.claude-peers.db \"
SELECT from_id, to_id, length(text), sent_at
FROM messages
WHERE text LIKE '%password%' OR text LIKE '%key%' OR text LIKE '%token%'
ORDER BY sent_at DESC
LIMIT 10
\""
```

### Determine the installation vector

```bash
# Was it installed via a package?
pacman -Qo <binary-path> 2>/dev/null  # Arch
dpkg -S <binary-path> 2>/dev/null      # Debian

# Was it compiled locally?
file <binary-path>

# Was it downloaded?
grep -r '<binary-name>' ~/.bash_history ~/.zsh_history 2>/dev/null

# Was it installed by a daemon or Claude session?
journalctl --user --since "7 days ago" --no-pager 2>/dev/null | grep '<binary-name>'
```

---

## Containment

### Step 1: Kill the capture process and remove the binary

```bash
# Kill the process
kill -9 <pid>

# Move the binary to quarantine (keep for forensics)
mkdir -p ~/.config/claude-peers/forensics/quarantine
mv <binary-path> ~/.config/claude-peers/forensics/quarantine/

# Remove any LD_PRELOAD hooks
# If in /etc/ld.so.preload:
sudo rm /etc/ld.so.preload
# If in shell config, edit the file to remove the LD_PRELOAD line

# Remove any persistence (cron, systemd)
crontab -l | grep -v '<binary-name>' | crontab -
systemctl --user stop <service-name> 2>/dev/null
systemctl --user disable <service-name> 2>/dev/null
```

### Step 2: Change all passwords and credentials that may have been captured

This is the expensive part. If a keylogger was active, assume ALL keyboard input during the capture window is compromised:

| Credential | Rotation Method |
|-----------|-----------------|
| sudo password | `passwd` |
| 1Password master password | Change in 1Password settings |
| SSH keys | `ssh-keygen -t ed25519`, update authorized_keys on all machines |
| UCAN tokens | `claude-peers init client`, re-issue tokens |
| Browser passwords | Change via each service's settings |
| Any API key typed or pasted | Rotate in the service dashboard |

### Step 3: On macOS, revoke suspicious permissions

```bash
# On laptop-1 or laptop-2:
# Open System Settings > Privacy & Security > Input Monitoring
# Remove any suspicious apps

# Or via command line (requires restart):
ssh laptop-1 "tccutil reset ListenEvent <bundle-id>"
ssh laptop-1 "tccutil reset Accessibility <bundle-id>"
```

---

## Recovery

### Step 1: Verify the capture tool is fully removed

```bash
# Re-scan the machine
echo "=== Re-scan ==="
pgrep -fa "keylog\|evtest\|xinput\|logkeys\|clipboard\|input.*monitor" 2>/dev/null || echo "No capture processes found"
cat /etc/ld.so.preload 2>/dev/null || echo "No LD_PRELOAD"
grep -r 'LD_PRELOAD' ~/.bashrc ~/.zshrc ~/.profile /etc/environment /etc/profile.d/ 2>/dev/null || echo "No user LD_PRELOAD"
```

### Step 2: Assess exposure window and rotate credentials

Use the process start time from the investigation to determine which credentials were entered during the capture window. Rotate all of them.

### Step 3: Monitor for reinstallation

Watch for the capture tool to reappear over the next 48 hours:
```bash
# Add to crontab as a temporary monitor
# */5 * * * * pgrep -fa 'keylog|evtest|logkeys' && curl -s -X POST ... (alert)
```

---

## Decision Tree

```
Keylogger/clipboard capture suspected
|
+-- Which platform?
|   +-- Linux (workstation, workstation-2, edge-node, iot-device)
|   |   +-- Check /dev/input readers
|   |   +-- Check for LD_PRELOAD hooks
|   |   +-- Check for wl-paste --watch (Wayland clipboard)
|   |   +-- Check for suspicious processes
|   |
|   +-- macOS (laptop-1, laptop-2)
|       +-- Check TCC.db for Input Monitoring permissions
|       +-- Check TCC.db for Accessibility permissions
|       +-- Check for pbpaste polling processes
|       +-- Check Activity Monitor for suspicious apps
|
+-- Is a capture process currently running?
|   +-- YES: kill immediately
|   |   +-- Quarantine the binary for forensics
|   |   +-- Check for persistence (cron, systemd, LaunchAgent)
|   |   +-- Determine process start time (exposure window)
|   |   +-- Rotate ALL credentials entered during exposure window
|   |
|   +-- NO: no active capture found
|       +-- Check for recently removed processes (forensics)
|       +-- Check for capture output files in /tmp, /var/tmp, /dev/shm
|       +-- Check if data was already exfiltrated (network logs, peer messages)
|
+-- Was captured data exfiltrated?
|   +-- To a network endpoint: block the IP, rotate all exposed credentials
|   +-- Via peer messages: see PEER_MESSAGE_EXFIL playbook
|   +-- To a local file: quarantine the file, assess contents
|   +-- Unknown: assume worst case, full credential rotation
|
+-- How was the capture tool installed?
    +-- Daemon/Claude session with bash access? (check daemon logs)
    +-- SSH access by attacker? (check auth logs)
    +-- Package manager? (check pacman/apt/brew history)
    +-- Supply chain attack? (compromised dependency)
```

---

## Machine-Specific Notes

### workstation (<workstation-ip>, Arch, Hyprland/Wayland)

- Daily driver -- highest exposure. 1Password, browser sessions, all fleet operations happen here.
- Wayland compositor (Hyprland) -- X11 keyloggers don't work. Wayland-specific attacks needed.
- Clipboard tool: `wl-copy`/`wl-paste`. Watch for `wl-paste --watch` processes.
- Input devices: `/dev/input/event*` -- check group membership: `ls -la /dev/input/`.
- CLAUDE.md instructs copying commands to clipboard -- any clipboard monitor catches tokens and commands.

### workstation-2 (<workstation-2-ip>, Arch)

- Similar to workstation (Arch, likely Wayland). Same detection methods apply.

### edge-node (Raspberry Pi 5, Debian Trixie)

- Kiosk mode -- limited interactive use, lower exposure.
- But has SSH access to entire fleet -- keylogger on edge-node captures SSH sessions.

### laptop-1 (<laptop-1-ip>, macOS)

- Client work + banking. Highest sensitivity for credential theft.
- macOS TCC protections provide some defense -- check if suspicious apps have Input Monitoring permission.
- 1Password CLI and browser extension used here -- master password typed frequently.

### iot-device (<iot-device-ip>, Pi Zero 2W)

- Cyberdeck with push-to-talk and mic -- voice input captured via Whisplay HAT.
- Physical security: portable device, easier to tamper with physically.
- Limited processing power -- eBPF keylogger unlikely.

### laptop-2 (<laptop-2-ip>, macOS)

- LLM server -- less interactive use.
- Same macOS TCC protections as laptop-1.

---

## Monitoring Gaps

| Gap | Severity | Status | Remediation |
|-----|----------|--------|-------------|
| **NO input device monitoring on any machine** | **CRITICAL** | NOT IMPLEMENTED | Add Wazuh rules or daemon checks for processes reading /dev/input |
| **NO clipboard monitoring detection** | **CRITICAL** | NOT IMPLEMENTED | Detect `wl-paste --watch`, `pbpaste` polling, clipboard D-Bus monitors |
| **NO LD_PRELOAD monitoring** | **HIGH** | NOT IMPLEMENTED | FIM on `/etc/ld.so.preload`. Shell config FIM exists (rule 100110) but is classified as `shell_persistence`, not `keylogger`. |
| **NO macOS TCC change monitoring** | **HIGH** | NOT IMPLEMENTED | Alert when new apps receive Input Monitoring or Accessibility permissions |
| **No eBPF/kprobe monitoring** | **MEDIUM** | NOT IMPLEMENTED | Advanced keyloggers use eBPF. Difficult to detect without kernel-level monitoring. |

---

## Hardening Recommendations

1. **Restrict /dev/input permissions.** On Linux machines, ensure `/dev/input/event*` devices are owned by `root:input` and only processes that genuinely need input access (compositor, libinput) are in the `input` group:
   ```bash
   # Check current permissions
   ls -la /dev/input/
   # Check who is in the input group
   getent group input
   ```

2. **Add /dev/input monitoring.** Create a periodic check (daemon or cron) that:
   - Lists all processes with open file descriptors on `/dev/input/*`
   - Compares against an allowlist (Hyprland, libinput)
   - Publishes a security alert if unknown processes are reading input devices

3. **Monitor /etc/ld.so.preload with Wazuh FIM.** Add to `shared_agent.conf`:
   ```xml
   <directories check_all="yes" realtime="yes">/etc/ld.so.preload</directories>
   ```

4. **Clipboard hygiene.** Avoid leaving sensitive data in the clipboard. Consider a clipboard manager that auto-clears after 30 seconds (like CopyQ with auto-clear, or 1Password's built-in clipboard clearing).

5. **macOS: Audit TCC database periodically.** Create a script that queries the TCC database for Input Monitoring and Accessibility permissions and alerts on new entries.

6. **Minimize password entry.** Use SSH key auth exclusively (no password auth). Use 1Password's browser extension for autofill instead of copy-paste. Use biometric unlock where possible.
