# Playbook 6: Persistence Audit (Non-Systemd)

This playbook covers every persistence mechanism beyond systemd that an attacker could use on the fleet. Use it when you suspect a machine has been compromised and need to do a full sweep, or as a periodic audit.

## Background: Persistence Mechanisms by OS

An attacker with shell access has dozens of ways to survive reboots and maintain access. Systemd is the most common on Linux, but far from the only option. This playbook catalogs them all and provides exact commands for each machine type in the fleet.

### Linux Persistence Mechanisms

| Mechanism | Path/Location | Root Required | Wazuh Monitored |
|-----------|--------------|---------------|-----------------|
| Crontab (user) | `crontab -e` / `/var/spool/cron/` | No | YES (default syscheck) |
| Crontab (system) | `/etc/crontab`, `/etc/cron.d/`, `/etc/cron.{daily,hourly,weekly,monthly}/` | Yes | NO |
| at/anacron jobs | `/var/spool/at/`, `/etc/anacrontab` | Varies | NO |
| Shell RC injection | `~/.bashrc`, `~/.zshrc`, `~/.profile`, `~/.bash_profile`, `~/.zprofile` | No | NO |
| SSH authorized_keys | `~/.ssh/authorized_keys` | No | YES (rule 100102, L10) |
| SSH config | `~/.ssh/config` | No | YES (rule 100102, L10) |
| LD_PRELOAD | `/etc/ld.so.preload`, `/etc/environment`, `~/.bashrc` | Varies | NO |
| Systemd user units | `~/.config/systemd/user/` | No | YES (rule 100130, L9) |
| Systemd system units | `/etc/systemd/system/` | Yes | YES (rule 100130, L9) |
| XDG autostart | `~/.config/autostart/`, `/etc/xdg/autostart/` | No | NO |
| /etc/rc.local | `/etc/rc.local` | Yes | NO |
| /etc/init.d/ scripts | `/etc/init.d/` | Yes | NO |
| Modified /etc/hosts | `/etc/hosts` | Yes | NO |
| Modified /etc/resolv.conf | `/etc/resolv.conf` | Yes | NO |
| Python startup | `PYTHONSTARTUP`, `~/.pythonrc`, `usercustomize.py` | No | NO |
| Git hooks | `~/.config/git/hooks/`, `.git/hooks/` in any repo | No | NO |
| npm global hooks | `~/.npmrc`, global `preinstall`/`postinstall` scripts | No | NO |
| Kernel modules | `/etc/modules-load.d/`, `modprobe.d/` | Yes | NO |
| udev rules | `/etc/udev/rules.d/` | Yes | NO |
| PAM modules | `/etc/pam.d/` | Yes | NO |
| MOTD scripts | `/etc/update-motd.d/` | Yes | NO |
| Bash PROMPT_COMMAND | Set in `~/.bashrc` | No | NO |
| Vim/Neovim plugins | `~/.config/nvim/`, `~/.vimrc` | No | NO |
| Tmux plugins | `~/.config/tmux/plugins/` | No | NO |
| Polkit rules | `/etc/polkit-1/rules.d/` | Yes | NO |

### macOS Persistence Mechanisms

| Mechanism | Path/Location | Root Required | Wazuh Monitored |
|-----------|--------------|---------------|-----------------|
| LaunchAgents (user) | `~/Library/LaunchAgents/` | No | NO (macOS FIM not configured for this path) |
| LaunchAgents (system) | `/Library/LaunchAgents/` | Yes | NO |
| LaunchDaemons | `/Library/LaunchDaemons/` | Yes | NO |
| Crontab | `crontab -e` | No | YES (default syscheck) |
| Login Items | System Settings > Login Items | No | NO |
| Shell RC injection | `~/.zshrc`, `~/.zprofile`, `~/.zshenv` | No | NO |
| SSH authorized_keys | `~/.ssh/authorized_keys` | No | Depends on agent config |
| Periodic scripts | `/etc/periodic/{daily,weekly,monthly}/` | Yes | NO |
| Authorization plugins | `/Library/Security/SecurityAgentPlugins/` | Yes | NO |

## Detection Gaps

**What Wazuh IS monitoring on this fleet:**

- `~/.config/claude-peers/` (realtime FIM, all agents)
- `~/.ssh/` (realtime FIM, excluding known_hosts)
- `~/.local/bin/` (realtime FIM)
- `/usr/local/bin/` (realtime FIM)
- `/etc/systemd/system/` (realtime FIM)
- `~/.config/systemd/user/` (realtime FIM)
- User crontab changes (default Wazuh syscheck on /var/spool/cron/)
- Auth logs (journald sshd and sudo)

**What Wazuh is NOT monitoring (gaps):**

| Gap | Risk Level | Machines Affected |
|-----|-----------|-------------------|
| `~/.bashrc`, `~/.zshrc`, `~/.profile` | HIGH | All |
| `~/.config/autostart/` | MEDIUM | workstation, workstation-2 (Hyprland exec-once reads these) |
| `/etc/cron.d/`, `/etc/cron.daily/`, etc. | HIGH | broker-server, edge-node, iot-device |
| `/etc/rc.local` | MEDIUM | broker-server, edge-node, iot-device |
| `/etc/environment`, `/etc/ld.so.preload` | HIGH | All Linux |
| `~/Library/LaunchAgents/` | HIGH | laptop-1, laptop-2 |
| `/Library/LaunchDaemons/` | HIGH | laptop-1, laptop-2 |
| `/etc/hosts`, `/etc/resolv.conf` | MEDIUM | All |
| `/etc/pam.d/` | HIGH | All Linux |
| Git hooks in `~/projects/` repos | LOW | workstation, workstation-2 |
| `/etc/udev/rules.d/` | MEDIUM | All Linux |
| `/etc/modules-load.d/` | HIGH | All Linux |

## Full Persistence Audit Commands

Run these on a suspected compromised machine. Grouped by machine type.

### Arch Linux (workstation at <workstation-ip>, workstation-2 at <workstation-2-ip>)

```bash
MACHINE=workstation  # or workstation-2

echo "=== CRON ==="
ssh $MACHINE "crontab -l 2>/dev/null || echo 'no user crontab'"
ssh $MACHINE "sudo crontab -l 2>/dev/null || echo 'no root crontab'"
ssh $MACHINE "ls -la /etc/cron.d/ 2>/dev/null"
ssh $MACHINE "cat /etc/anacrontab 2>/dev/null"
ssh $MACHINE "atq 2>/dev/null || echo 'at not installed'"

echo "=== SHELL RC FILES ==="
ssh $MACHINE "stat -c '%n %y' ~/.bashrc ~/.zshrc ~/.profile ~/.bash_profile ~/.zprofile 2>/dev/null"
# Look for suspicious additions (curl, wget, nc, base64, /dev/tcp, reverse shell patterns)
ssh $MACHINE "grep -nE 'curl|wget|nc |ncat|base64|/dev/tcp|python.*-c|perl.*-e|ruby.*-e|bash.*-i' ~/.bashrc ~/.zshrc ~/.profile ~/.bash_profile 2>/dev/null"

echo "=== SSH ==="
ssh $MACHINE "cat ~/.ssh/authorized_keys 2>/dev/null"
ssh $MACHINE "cat ~/.ssh/config 2>/dev/null"

echo "=== LD_PRELOAD ==="
ssh $MACHINE "cat /etc/ld.so.preload 2>/dev/null || echo 'no ld.so.preload'"
ssh $MACHINE "grep LD_PRELOAD /etc/environment 2>/dev/null"
ssh $MACHINE "grep -r LD_PRELOAD /etc/profile.d/ 2>/dev/null"

echo "=== SYSTEMD (user) ==="
ssh $MACHINE "systemctl --user list-unit-files --state=enabled --type=service"
ssh $MACHINE "systemctl --user list-timers --all"
ssh $MACHINE "ls -la ~/.config/systemd/user/ 2>/dev/null"

echo "=== SYSTEMD (system) ==="
ssh $MACHINE "systemctl list-unit-files --state=enabled --type=service | grep -v '/usr/lib/systemd'"
ssh $MACHINE "systemctl list-timers --all"
# Find unit files NOT owned by any pacman package
ssh $MACHINE "find /etc/systemd/system/ -maxdepth 1 -type f -exec pacman -Qo {} \; 2>&1 | grep 'not owned'"

echo "=== XDG AUTOSTART ==="
ssh $MACHINE "ls -la ~/.config/autostart/ 2>/dev/null"
ssh $MACHINE "ls -la /etc/xdg/autostart/ 2>/dev/null"

echo "=== ENVIRONMENT ==="
ssh $MACHINE "cat /etc/environment 2>/dev/null"
ssh $MACHINE "ls -la /etc/profile.d/"

echo "=== HOSTS / DNS ==="
ssh $MACHINE "cat /etc/hosts"
ssh $MACHINE "cat /etc/resolv.conf"

echo "=== KERNEL MODULES ==="
ssh $MACHINE "ls /etc/modules-load.d/"
ssh $MACHINE "ls /etc/modprobe.d/"

echo "=== UDEV RULES ==="
ssh $MACHINE "ls /etc/udev/rules.d/"

echo "=== PAM ==="
ssh $MACHINE "ls -la /etc/pam.d/ | grep -v '^\.\|^total'"

echo "=== SUSPICIOUS TEMP FILES ==="
ssh $MACHINE "find /tmp /var/tmp /dev/shm -type f -mtime -7 -ls 2>/dev/null"

echo "=== PYTHON STARTUP ==="
ssh $MACHINE "echo \$PYTHONSTARTUP; ls ~/.pythonrc 2>/dev/null; python3 -c 'import site; print(site.getusersitepackages())' 2>/dev/null"

echo "=== GIT HOOKS (all repos) ==="
ssh $MACHINE "find ~/projects/ -path '*/.git/hooks/*' -type f ! -name '*.sample' 2>/dev/null"

echo "=== POLKIT ==="
ssh $MACHINE "ls /etc/polkit-1/rules.d/ 2>/dev/null"

echo "=== RUNNING PROCESSES (unexpected) ==="
ssh $MACHINE "ps auxf | grep -vE 'sshd|bash|ps|grep|systemd|kworker|rcu|irq|migration|watchdog|Hyprland|waybar|kitty|pipewire|wireplumber|xdg|dbus|gvfs|gcr|polkit|udisk|wpa_supplicant|NetworkManager|tailscale|wazuh'"

echo "=== LISTENING PORTS ==="
ssh $MACHINE "ss -tlnp"
```

### Ubuntu/Debian (broker-server at <broker-ip>, edge-node)

Same as Arch, with these additions:

```bash
MACHINE=broker-server  # or edge-node

echo "=== DEBIAN-SPECIFIC CRON ==="
ssh $MACHINE "ls -la /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/"

echo "=== RC.LOCAL ==="
ssh $MACHINE "cat /etc/rc.local 2>/dev/null || echo 'no rc.local'"
ssh $MACHINE "systemctl status rc-local 2>/dev/null"

echo "=== INIT.D ==="
ssh $MACHINE "ls /etc/init.d/ | grep -v README"

echo "=== MOTD SCRIPTS ==="
ssh $MACHINE "ls -la /etc/update-motd.d/ 2>/dev/null"

echo "=== PACKAGE VERIFICATION ==="
# Find unit files NOT owned by any dpkg package
ssh $MACHINE "find /etc/systemd/system/ -maxdepth 1 -type f -exec dpkg -S {} \; 2>&1 | grep 'not found'"

echo "=== APT HOOKS (can run arbitrary commands on apt install) ==="
ssh $MACHINE "ls /etc/apt/apt.conf.d/"
ssh $MACHINE "grep -rl 'DPkg::Post-Invoke\|DPkg::Pre-Invoke\|APT::Update::Post-Invoke' /etc/apt/apt.conf.d/ 2>/dev/null"
```

### Pi Zero 2W (iot-device at <iot-device-ip>)

Same as Debian, with these additions:

```bash
MACHINE=<iot-device-ip>

echo "=== RC.LOCAL (common on Pi) ==="
ssh $MACHINE "cat /etc/rc.local 2>/dev/null"

echo "=== GPIO-TRIGGERED SCRIPTS ==="
ssh $MACHINE "grep -r 'gpio\|GPIO\|pigpio\|RPi.GPIO\|gpiod' /etc/systemd/system/ /etc/udev/rules.d/ 2>/dev/null"

echo "=== AIDE INTEGRITY (iot-device specific) ==="
ssh $MACHINE "aide --check 2>/dev/null | head -50"
ssh $MACHINE "cat /etc/aide/aide.conf 2>/dev/null | grep -v '^#' | head -30"

echo "=== BOOT CONFIG ==="
ssh $MACHINE "cat /boot/config.txt 2>/dev/null | grep -i 'dtoverlay\|enable_uart\|gpio'"
ssh $MACHINE "cat /boot/cmdline.txt 2>/dev/null"
```

### macOS (laptop-1 at <laptop-1-ip>, laptop-2 at <laptop-2-ip>)

```bash
MACHINE=laptop-1  # SSH as: <user>@<laptop-1-ip><laptop-1-ip>
# For laptop-2: adjust SSH user accordingly

echo "=== LAUNCH AGENTS (user) ==="
ssh $MACHINE "ls -la ~/Library/LaunchAgents/ 2>/dev/null"
ssh $MACHINE "for f in ~/Library/LaunchAgents/*.plist; do echo '--- \$f ---'; plutil -p \"\$f\"; done 2>/dev/null"

echo "=== LAUNCH AGENTS (system) ==="
ssh $MACHINE "ls -la /Library/LaunchAgents/ 2>/dev/null"

echo "=== LAUNCH DAEMONS ==="
ssh $MACHINE "ls -la /Library/LaunchDaemons/ 2>/dev/null"

echo "=== RUNNING NON-APPLE SERVICES ==="
ssh $MACHINE "launchctl list | grep -v 'com.apple' | grep -v '^\-'"

echo "=== CRON ==="
ssh $MACHINE "crontab -l 2>/dev/null || echo 'no user crontab'"

echo "=== SHELL RC ==="
ssh $MACHINE "stat -f '%N %Sm' ~/.zshrc ~/.zprofile ~/.zshenv ~/.zlogin 2>/dev/null"
ssh $MACHINE "grep -nE 'curl|wget|nc |ncat|base64|python.*-c|perl.*-e|osascript' ~/.zshrc ~/.zprofile ~/.zshenv 2>/dev/null"

echo "=== SSH ==="
ssh $MACHINE "cat ~/.ssh/authorized_keys 2>/dev/null"

echo "=== LOGIN ITEMS ==="
ssh $MACHINE "osascript -e 'tell application \"System Events\" to get the name of every login item' 2>/dev/null"

echo "=== PERIODIC SCRIPTS ==="
ssh $MACHINE "ls /etc/periodic/daily/ /etc/periodic/weekly/ /etc/periodic/monthly/ 2>/dev/null"

echo "=== SECURITY PLUGINS ==="
ssh $MACHINE "ls /Library/Security/SecurityAgentPlugins/ 2>/dev/null"

echo "=== HOSTS ==="
ssh $MACHINE "cat /etc/hosts"

echo "=== LISTENING PORTS ==="
ssh $MACHINE "lsof -i -n -P | grep LISTEN | grep -v 'com.apple'"

echo "=== BROWSER EXTENSIONS (common malware vector) ==="
ssh $MACHINE "ls ~/Library/Application\ Support/Google/Chrome/Default/Extensions/ 2>/dev/null | head -20"
```

## Investigation Workflow

When you suspect a machine is compromised, follow this sequence:

### Phase 1: Snapshot (do NOT change anything yet)

```bash
MACHINE=<target>
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTDIR=~/.config/claude-peers/forensics/$MACHINE-audit-$TIMESTAMP

mkdir -p $OUTDIR

# Capture everything in parallel
ssh $MACHINE "ps auxf" > $OUTDIR/processes.txt
ssh $MACHINE "ss -tlnp" > $OUTDIR/listeners.txt
ssh $MACHINE "ss -tnp" > $OUTDIR/connections.txt
ssh $MACHINE "last -50" > $OUTDIR/logins.txt
ssh $MACHINE "who" > $OUTDIR/who.txt
ssh $MACHINE "crontab -l 2>/dev/null" > $OUTDIR/crontab.txt
ssh $MACHINE "cat ~/.ssh/authorized_keys 2>/dev/null" > $OUTDIR/authorized_keys.txt
ssh $MACHINE "systemctl --user list-unit-files --state=enabled 2>/dev/null" > $OUTDIR/user-units.txt
ssh $MACHINE "find /tmp /var/tmp /dev/shm -type f -ls 2>/dev/null" > $OUTDIR/tempfiles.txt
```

### Phase 2: Analyze the snapshot

Review each file in `$OUTDIR/`. Look for:

1. **processes.txt**: Unknown processes, processes running from /tmp or hidden dirs, processes with high CPU that you do not recognize
2. **listeners.txt**: Ports that should not be open. Expected ports per machine:
   - broker-server: 7899 (broker), 4222 (NATS), 1514/1515 (Wazuh), 8888 (gridwatch)
   - edge-node: 8888 (gridwatch display)
   - workstation: nothing persistent expected
   - workstation-2: nothing persistent expected
   - iot-device: voice assistant port
   - laptop-1: nothing persistent expected
3. **connections.txt**: Active connections to non-Tailscale IPs
4. **logins.txt**: Logins from unexpected IPs or at unexpected times
5. **crontab.txt**: Any entries you did not create
6. **authorized_keys.txt**: Any keys you do not recognize
7. **user-units.txt**: Compare against the known-good list in Playbook 5

### Phase 3: Deep dive on suspicious findings

Run the full audit commands from the relevant machine type section above, focusing on the areas that showed anomalies in Phase 2.

### Phase 4: Cross-machine correlation

If one machine is compromised, check if the attacker pivoted:

```bash
# Get the attacker's likely IPs from the compromised machine's connections
ATTACKER_IPS=$(cat $OUTDIR/connections.txt | grep -v '100\.\|127\.0\.\|::1' | awk '{print $5}' | cut -d: -f1 | sort -u)

# Check those IPs against all other fleet machines
for machine in workstation broker-server edge-node workstation-2 iot-device; do
  echo "=== $machine ==="
  for ip in $ATTACKER_IPS; do
    ssh $machine "journalctl --since '7 days ago' 2>/dev/null | grep $ip | tail -5"
    ssh $machine "last | grep $ip" 2>/dev/null
  done
done
```

## Eradication by Mechanism

### Crontab

```bash
# View before removing
ssh <machine> "crontab -l"

# Edit and remove the malicious entry
ssh <machine> "crontab -e"
# Or remove all user cron jobs:
ssh <machine> "crontab -r"

# System cron
ssh <machine> "sudo rm /etc/cron.d/<malicious-file>"
```

### Shell RC injection

```bash
# Diff against a known-good copy or check git history
ssh <machine> "cat ~/.bashrc"

# Remove the injected lines (edit manually, do not blindly overwrite)
ssh <machine> "vim ~/.bashrc"

# Source to verify no errors
ssh <machine> "bash -n ~/.bashrc && echo 'syntax ok'"
```

### SSH authorized_keys

```bash
# Remove the unauthorized key (edit, do not overwrite)
ssh <machine> "vim ~/.ssh/authorized_keys"

# Verify permissions
ssh <machine> "chmod 600 ~/.ssh/authorized_keys"
```

### LD_PRELOAD

```bash
# Remove the preload entry
ssh <machine> "sudo rm /etc/ld.so.preload"
# Or edit /etc/environment to remove LD_PRELOAD line
ssh <machine> "sudo vim /etc/environment"

# Verify the malicious .so file and remove it
ssh <machine> "sudo rm <path-to-malicious.so>"
```

### XDG autostart

```bash
ssh <machine> "rm ~/.config/autostart/<malicious>.desktop"
```

### macOS LaunchAgent/LaunchDaemon

```bash
# Unload first
ssh laptop-1 "launchctl bootout gui/$(id -u)/<label>"
# Or for system:
ssh laptop-1 "sudo launchctl bootout system/<label>"

# Remove the plist
ssh laptop-1 "rm ~/Library/LaunchAgents/<malicious>.plist"
# Or:
ssh laptop-1 "sudo rm /Library/LaunchDaemons/<malicious>.plist"

# Remove the binary it pointed to
ssh laptop-1 "rm <program-path-from-plist>"
```

### /etc/hosts or /etc/resolv.conf tampering

```bash
# Restore to known-good state
# /etc/hosts should contain only localhost entries on most fleet machines
ssh <machine> "cat /etc/hosts"
# Fix manually:
ssh <machine> "sudo vim /etc/hosts"

# resolv.conf - on systemd machines this is managed by systemd-resolved
ssh <machine> "sudo systemctl restart systemd-resolved"
```

### Git hooks

```bash
# Find and remove
ssh <machine> "find ~/projects/ -path '*/.git/hooks/*' -type f ! -name '*.sample' -exec rm {} \;"
```

## Recommended Monitoring Additions

These are the highest-priority gaps to close. Add these FIM paths to the Wazuh shared agent config:

### Priority 1 (HIGH -- should be added immediately)

```xml
<!-- Add to wazuh/shared_agent.conf inside <syscheck> -->
<directories check_all="yes" report_changes="yes">~/.bashrc</directories>
<directories check_all="yes" report_changes="yes">~/.zshrc</directories>
<directories check_all="yes" report_changes="yes">~/.profile</directories>
<directories check_all="yes" report_changes="yes">~/.bash_profile</directories>
<directories check_all="yes" report_changes="yes">/etc/environment</directories>
<directories check_all="yes" report_changes="yes">/etc/ld.so.preload</directories>
<directories check_all="yes">/etc/cron.d</directories>
<directories check_all="yes">/etc/cron.daily</directories>
<directories check_all="yes">/etc/cron.hourly</directories>
```

### Priority 2 (MEDIUM -- add when convenient)

```xml
<directories check_all="yes">/etc/hosts</directories>
<directories check_all="yes">/etc/pam.d</directories>
<directories check_all="yes">/etc/modules-load.d</directories>
<directories check_all="yes">/etc/udev/rules.d</directories>
<directories check_all="yes">~/.config/autostart</directories>
```

### Priority 3 (macOS-specific -- add to macOS agent ossec.conf)

```xml
<!-- macOS agents need separate config since paths differ -->
<directories check_all="yes" realtime="yes">/Users/<user>/Library/LaunchAgents</directories>
<directories check_all="yes">/Library/LaunchAgents</directories>
<directories check_all="yes">/Library/LaunchDaemons</directories>
<directories check_all="yes" report_changes="yes">/Users/<user>/.zshrc</directories>
<directories check_all="yes" report_changes="yes">/Users/<user>/.zprofile</directories>
```

### New Wazuh rules to add

```xml
<!-- Add to wazuh/local_rules.xml -->

<!-- Shell RC file modified -->
<rule id="100131" level="10">
  <if_group>syscheck</if_group>
  <match type="pcre2">\.(bashrc|zshrc|profile|bash_profile|zprofile)$</match>
  <description>Shell RC file modified (potential persistence): $(file)</description>
  <group>fim,persistence,shell_rc,</group>
</rule>

<!-- LD_PRELOAD or /etc/environment modified -->
<rule id="100132" level="12">
  <if_group>syscheck</if_group>
  <match type="pcre2">/etc/(ld\.so\.preload|environment)$</match>
  <description>System environment/preload file modified: $(file)</description>
  <group>fim,persistence,preload,</group>
</rule>

<!-- Cron directory modified -->
<rule id="100133" level="9">
  <if_group>syscheck</if_group>
  <match type="pcre2">/etc/cron\.</match>
  <description>System cron directory modified: $(file)</description>
  <group>fim,persistence,cron,</group>
</rule>

<!-- macOS LaunchAgent/Daemon modified -->
<rule id="100134" level="10">
  <if_group>syscheck</if_group>
  <match type="pcre2">/(Library/Launch(Agents|Daemons))/</match>
  <description>macOS launch agent/daemon modified: $(file)</description>
  <group>fim,persistence,launchd,</group>
</rule>
```

## Hardening Recommendations

### Immediate (low effort, high impact)

1. **Lock down shell RC files**: `chattr +i ~/.bashrc ~/.zshrc` on machines where these rarely change (edge-node, iot-device). Use `chattr -i` temporarily when you need to edit.

2. **Restrict cron**: On machines that do not need user cron (edge-node, iot-device), disable it:
   ```bash
   echo user | sudo tee /etc/cron.deny
   ```

3. **Restrict at**: Same machines:
   ```bash
   echo user | sudo tee /etc/at.deny
   ```

4. **SSH key pinning**: On each machine, ensure `~/.ssh/authorized_keys` contains ONLY keys you recognize. Set immutable on machines where keys should never change:
   ```bash
   sudo chattr +i ~/.ssh/authorized_keys  # on iot-device, edge-node
   ```

### Medium-term

5. **Deploy the recommended FIM additions** from the section above.

6. **Enable auditd on broker-server**: This gives process-level visibility into who modifies files:
   ```bash
   sudo apt install auditd
   sudo auditctl -w /etc/systemd/system/ -p wa -k persistence
   sudo auditctl -w ~/.config/systemd/user/ -p wa -k persistence
   sudo auditctl -w ~/.bashrc -p wa -k shell_rc
   sudo auditctl -w ~/.ssh/authorized_keys -p wa -k ssh_keys
   ```

7. **Periodic automated audits**: Create a systemd timer on each Linux machine that runs the audit commands and publishes results to NATS. The fleet-scout daemon can consume these.

### Long-term

8. **Immutable infrastructure on iot-device**: iot-device is a constrained device. Consider making its rootfs read-only (overlay filesystem) so persistence is impossible without physical access.

9. **macOS endpoint monitoring**: The current Wazuh config does not cover macOS LaunchAgents at all. This is the biggest gap in the fleet. Deploy the macOS-specific FIM config.

10. **Git hook auditing**: Add a pre-commit hook across all repos that verifies no suspicious hooks exist in `.git/hooks/`.
