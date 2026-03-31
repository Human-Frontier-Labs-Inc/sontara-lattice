# Package Manager Compromise Incident Response Playbook

**System:** Sontara Lattice (claude-peers) fleet
**Last updated:** 2026-03-28
**Audience:** the operator (fleet operator)
**Severity tier:** Tier 2 (Investigate) escalating to Tier 3 if malicious package confirmed

---

## Table of Contents

1. [Attack Model](#attack-model)
2. [Detection](#detection)
3. [Immediate Triage (0-5 minutes)](#immediate-triage)
4. [Containment](#containment)
5. [Investigation](#investigation)
6. [Recovery](#recovery)
7. [Post-Incident Hardening](#post-incident-hardening)
8. [Monitoring Gaps](#monitoring-gaps)

---

## Attack Model

### Fleet package manager landscape

| Machine | OS | Package Manager | Repos | Risk Level |
|---------|-----|----------------|-------|-----------|
| workstation (<workstation-ip>) | Arch Linux | pacman + AUR (yay/paru) | Official repos + AUR (untrusted user packages) | **HIGH** -- AUR packages are unvetted user submissions |
| workstation-2 (<workstation-2-ip>) | Arch Linux | pacman + AUR | Same as workstation | **HIGH** |
| broker-server (<broker-ip>) | Ubuntu 24.04 | apt | Official repos + possible PPAs | **MEDIUM** -- PPAs can be malicious |
| edge-node (Pi 5) | Debian Trixie | apt | Official Debian repos + Pi repos | **LOW-MEDIUM** -- mostly stable repos |
| iot-device (<iot-device-ip>) | Debian Trixie | apt | Same as edge-node | **LOW-MEDIUM** |
| laptop-1 (<laptop-1-ip>) | macOS 15 | Homebrew | Homebrew core + casks (GitHub-sourced formulae) | **MEDIUM** -- formula source is public GitHub |
| laptop-2 (<laptop-2-ip>) | macOS | Unknown | Unknown | **UNKNOWN** -- not the operator's machine |

### Known anomaly: Wazuh agent installation

The Wazuh agent on Arch Linux machines was installed from a DEB package extraction rather than a native pacman package. This is unusual and creates a trust issue:

- The package did not go through pacman's signature verification
- Files were manually placed on the system outside the package manager
- Updates and integrity verification via pacman are not possible for these files

### Attack scenarios

**Scenario A: Malicious AUR package**

```
1. Attacker creates or takes over an AUR package that workstation/workstation-2 use
2. Package install script (PKGBUILD) runs arbitrary code as root during install
3. The code:
   - Installs a backdoor or rootkit
   - Steals credentials from ~/.config/claude-peers/
   - Adds SSH keys to authorized_keys
   - Modifies system binaries
4. Since AUR packages are built from user-submitted PKGBUILDs, this is trivial
```

**Scenario B: Compromised PPA on Ubuntu**

```
1. A PPA repository is compromised or a malicious PPA is added to broker-server
2. apt install pulls a trojanized package
3. Package runs post-install script as root
4. Attacker gains persistent root access to broker-server (the fleet's central server)
```

**Scenario C: Homebrew formula tampering**

```
1. A Homebrew formula on laptop-1 is updated with malicious code
2. brew upgrade installs the trojanized version
3. Since Homebrew runs without sudo, the attacker gets user-level access
4. User-level access on laptop-1 gives access to SSH keys, claude-peers config, HFL project data
```

**Scenario D: Package manager config modification**

```
1. Attacker modifies /etc/pacman.conf to add a malicious repository
2. Or modifies /etc/apt/sources.list to add a rogue repo
3. Next package update pulls from the attacker's repository
4. All subsequent updates are potentially compromised
```

---

## Detection

### Audit foreign packages on Arch (workstation, workstation-2)

```bash
echo "=== Arch Foreign Package Audit ==="
echo "--- workstation ---"
echo "Foreign packages (not in official repos):"
pacman -Qm
echo ""
echo "Recently installed packages (last 7 days):"
grep -E "^\[.*\] \[ALPM\] installed" /var/log/pacman.log | tail -20
echo ""
echo "Recently upgraded packages:"
grep -E "^\[.*\] \[ALPM\] upgraded" /var/log/pacman.log | tail -20

echo "--- workstation-2 ---"
ssh <workstation-2-ip> "
pacman -Qm
echo ''
grep -E '^\[.*\] \[ALPM\] installed' /var/log/pacman.log | tail -20
" 2>/dev/null
```

### Audit installed packages on Ubuntu

```bash
ssh broker-server "
echo '=== Ubuntu Package Audit ==='
echo 'Third-party repositories:'
grep -r '^deb ' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null | grep -v 'ubuntu.com\|debian.org'

echo ''
echo 'Recently installed packages:'
grep ' install ' /var/log/dpkg.log 2>/dev/null | tail -20 || \
    zgrep ' install ' /var/log/dpkg.log.*.gz 2>/dev/null | tail -20

echo ''
echo 'Packages not from official repos:'
apt list --installed 2>/dev/null | grep -v 'ubuntu' | head -20

echo ''
echo 'Modified package files:'
dpkg --verify 2>/dev/null | head -20
"
```

### Audit Homebrew on laptop-1

```bash
ssh <user>@<laptop-1-ip><laptop-1-ip> "
echo '=== Homebrew Audit ==='
echo 'Installed formulae:'
brew list --formula | wc -l
echo 'Installed casks:'
brew list --cask | wc -l
echo ''
echo 'Taps (repositories):'
brew tap
echo ''
echo 'Recently installed:'
brew log --oneline -20 2>/dev/null || echo 'Check brew install history manually'
" 2>/dev/null
```

### Check package manager config integrity

```bash
echo "=== Package Manager Config Integrity ==="

# Arch: check pacman.conf
echo "--- workstation: pacman.conf ---"
grep -E '^\[' /etc/pacman.conf
grep -E '^Server|^Include' /etc/pacman.conf

echo "--- workstation-2: pacman.conf ---"
ssh <workstation-2-ip> "grep -E '^\[|^Server|^Include' /etc/pacman.conf" 2>/dev/null

# Ubuntu: check sources
echo "--- broker-server: apt sources ---"
ssh broker-server "
cat /etc/apt/sources.list 2>/dev/null | grep -v '^#' | grep -v '^\$'
ls /etc/apt/sources.list.d/
for f in /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
    echo \"--- \$f ---\"
    cat \"\$f\" 2>/dev/null | grep -v '^#' | grep -v '^\$'
done
" 2>/dev/null
```

### Verify package signatures

```bash
# Arch: check that signature verification is enabled
echo "=== Signature Verification ==="
echo "--- workstation ---"
grep 'SigLevel' /etc/pacman.conf

echo "--- broker-server ---"
ssh broker-server "
apt-key list 2>/dev/null | head -20
echo 'GPG keys in trusted.gpg.d:'
ls /etc/apt/trusted.gpg.d/
" 2>/dev/null
```

### Detect unexpected package installs (Wazuh)

```bash
# Check if Wazuh is monitoring package manager activity
ssh broker-server "
docker exec wazuh-manager cat /var/ossec/logs/alerts/alerts.json 2>/dev/null | \
    python3 -c '
import sys, json
for line in sys.stdin:
    try:
        alert = json.loads(line.strip())
        rule = alert.get(\"rule\", {})
        desc = rule.get(\"description\", \"\")
        if any(kw in desc.lower() for kw in [\"package\", \"apt\", \"pacman\", \"dpkg\", \"yum\"]):
            print(f\"  Level {rule.get(\"level\")}: {desc}\")
    except:
        pass
' 2>/dev/null | tail -10
"
```

---

## Immediate Triage (0-5 minutes)

### Step 1: Identify the suspicious package

```bash
SUSPECT_PKG="package-name"  # Replace
SUSPECT_MACHINE="workstation"   # Replace

# Arch
pacman -Qi $SUSPECT_PKG 2>/dev/null
pacman -Ql $SUSPECT_PKG 2>/dev/null | head -20

# Ubuntu
ssh broker-server "
dpkg -s $SUSPECT_PKG 2>/dev/null
dpkg -L $SUSPECT_PKG 2>/dev/null | head -20
" 2>/dev/null
```

### Step 2: Check what the package install script did

```bash
# Arch: check PKGBUILD for post-install scripts
# If installed from AUR, the PKGBUILD is cached
find ~/.cache/yay -name "PKGBUILD" -path "*/$SUSPECT_PKG/*" 2>/dev/null -exec cat {} \;
find ~/.cache/paru -name "PKGBUILD" -path "*/$SUSPECT_PKG/*" 2>/dev/null -exec cat {} \;

# Ubuntu: check maintainer scripts
ssh broker-server "
cat /var/lib/dpkg/info/${SUSPECT_PKG}.postinst 2>/dev/null
cat /var/lib/dpkg/info/${SUSPECT_PKG}.preinst 2>/dev/null
" 2>/dev/null
```

### Step 3: Check for immediate signs of compromise

```bash
# Check if the package added any cron jobs, services, or SSH keys
ssh $SUSPECT_MACHINE "
echo '=== New cron entries ==='
crontab -l 2>/dev/null
ls -la /etc/cron.d/ | tail -5

echo '=== New services ==='
systemctl list-units --type=service --state=running | grep -v 'systemd\|network\|ssh\|docker\|tailscale\|wazuh'

echo '=== SSH authorized keys ==='
cat ~/.ssh/authorized_keys 2>/dev/null

echo '=== New setuid binaries ==='
find /usr/bin /usr/sbin /usr/local/bin -perm -4000 -newer /var/log/pacman.log 2>/dev/null || \
find /usr/bin /usr/sbin /usr/local/bin -perm -4000 -newer /var/log/dpkg.log 2>/dev/null | head -10
" 2>/dev/null
```

---

## Containment

### Remove the malicious package

```bash
# Arch
sudo pacman -Rns $SUSPECT_PKG

# Ubuntu
ssh broker-server "sudo apt remove --purge $SUSPECT_PKG" 2>/dev/null

# macOS
ssh <user>@<laptop-1-ip><laptop-1-ip> "brew uninstall $SUSPECT_PKG" 2>/dev/null
```

### Disable the malicious repository

```bash
# Arch: remove from pacman.conf or AUR
sudo nano /etc/pacman.conf  # Remove the bad repo section

# Ubuntu: remove PPA
ssh broker-server "
sudo rm /etc/apt/sources.list.d/MALICIOUS_REPO.list
sudo apt update
" 2>/dev/null
```

### Check other machines for the same package

```bash
echo "=== Cross-fleet package check for: $SUSPECT_PKG ==="
for machine in "<workstation-ip>" "broker-server" "edge-node" "<workstation-2-ip>" "<user>@<laptop-1-ip><laptop-1-ip>" "<iot-device-ip>"; do
    FOUND=$(ssh -o ConnectTimeout=5 $machine "
        pacman -Q $SUSPECT_PKG 2>/dev/null || \
        dpkg -s $SUSPECT_PKG 2>/dev/null | grep Status || \
        brew list $SUSPECT_PKG 2>/dev/null
    " 2>/dev/null)
    if [ -n "$FOUND" ]; then
        echo "  $machine: INSTALLED -- $FOUND"
    else
        echo "  $machine: not found"
    fi
done
```

---

## Investigation

### Analyze what the package modified

```bash
# Arch: check pacman log for the full install record
grep "$SUSPECT_PKG" /var/log/pacman.log

# Check file timestamps to see what was modified during install
INSTALL_TIME="2026-03-28 12:00"  # Replace with actual install time
find / -newer /tmp/before-install-marker -not -newer /tmp/after-install-marker 2>/dev/null | head -50
# (If markers aren't available, use approximate timestamps from pacman.log)
```

### Check for install-time code execution

```bash
# AUR packages run PKGBUILD functions during install, which can do anything
# Check if the PKGBUILD downloaded or executed anything suspicious

# Review the PKGBUILD
echo "=== PKGBUILD review ==="
PKGBUILD_PATH=$(find ~/.cache/yay ~/.cache/paru -name "PKGBUILD" -path "*/$SUSPECT_PKG/*" 2>/dev/null | head -1)
if [ -n "$PKGBUILD_PATH" ]; then
    echo "Found: $PKGBUILD_PATH"
    cat "$PKGBUILD_PATH"
else
    echo "PKGBUILD not cached -- check AUR web interface"
    echo "https://aur.archlinux.org/packages/$SUSPECT_PKG"
fi
```

### Check for Wazuh agent integrity (special case)

```bash
# The Wazuh agent was installed from DEB extraction, not pacman
# Verify its files haven't been tampered
for machine in "<workstation-ip>" "<workstation-2-ip>"; do
    echo "=== $machine: Wazuh agent file integrity ==="
    ssh -o ConnectTimeout=5 $machine "
        # Check Wazuh agent binary
        sha256sum /var/ossec/bin/wazuh-agentd 2>/dev/null
        # Check Wazuh agent config
        ls -la /var/ossec/etc/ossec.conf 2>/dev/null
        # Check if Wazuh agent is running
        ps aux | grep wazuh | grep -v grep
    " 2>/dev/null || echo "  UNREACHABLE"
done
```

---

## Recovery

### Step 1: Remove the package and all its files

```bash
# Arch: full removal including dependencies
sudo pacman -Rns $SUSPECT_PKG

# Check for orphaned files left behind
pacman -Ql $SUSPECT_PKG 2>/dev/null | while read pkg file; do
    [ -e "$file" ] && echo "LEFTOVER: $file"
done
```

### Step 2: Verify system integrity

```bash
# Arch: check all installed packages for modified files
pacman -Qkk 2>/dev/null | grep -i 'warning' | head -30

# Ubuntu:
ssh broker-server "dpkg --verify 2>/dev/null | head -30"
```

### Step 3: Rotate credentials if package had access

```bash
# If the malicious package ran as root (which AUR/apt packages do during install),
# assume all credentials on that machine are compromised
# Follow credential rotation from TAILSCALE_COMPROMISE playbook
```

---

## Post-Incident Hardening

### 1. Minimize AUR usage on Arch machines

```bash
# Audit current AUR packages -- consider official alternatives
pacman -Qm | while read pkg ver; do
    echo "AUR: $pkg $ver"
    # Check if there's an official repo alternative
    pacman -Ss "^${pkg}$" 2>/dev/null | grep -q "core/\|extra/" && echo "  OFFICIAL ALTERNATIVE AVAILABLE"
done
```

### 2. Review PKGBUILDs before installing AUR packages

Always read the PKGBUILD before installing any AUR package. Check for:
- `curl` or `wget` commands downloading external content
- Unusual `install` or `post_install` functions
- References to unknown domains or IPs
- Base64-encoded content
- Execution of downloaded scripts

### 3. Lock down package manager configs

```bash
# Arch: ensure signature verification is required
# In /etc/pacman.conf:
# SigLevel = Required DatabaseOptional
# LocalFileSigLevel = Optional

# Ubuntu: don't add PPAs without verification
# Remove any unnecessary PPAs
ssh broker-server "ls /etc/apt/sources.list.d/" 2>/dev/null
```

### 4. Monitor package manager activity via Wazuh

```bash
# Add Wazuh rules to alert on package installation
# Monitor: /var/log/pacman.log (Arch), /var/log/dpkg.log (Ubuntu/Debian)
ssh broker-server "
echo 'Verify Wazuh monitors package manager logs:'
docker exec wazuh-manager cat /var/ossec/etc/ossec.conf 2>/dev/null | grep -A3 'pacman\|dpkg\|apt'
"
```

### 5. Use pacman hooks for security

```bash
# Add a pacman hook that logs all installs with sha256 hashes
# /etc/pacman.d/hooks/package-audit.hook
cat << 'HOOK'
[Trigger]
Operation = Install
Operation = Upgrade
Type = Package
Target = *

[Action]
Description = Logging package install/upgrade
When = PostTransaction
Exec = /usr/bin/bash -c 'echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) PACKAGE_CHANGE" >> /var/log/package-audit.log'
HOOK
```

---

## Monitoring Gaps

| Gap | Severity | Status | Remediation |
|-----|----------|--------|-------------|
| AUR packages are unvetted user submissions | **HIGH** | INHERENT | Minimize AUR usage, always review PKGBUILDs |
| Wazuh agent installed from DEB extraction on Arch | **HIGH** | KNOWN | Consider rebuilding from official Wazuh Arch package or source |
| No automated package install alerting | **HIGH** | NOT CONFIRMED | Verify Wazuh monitors pacman.log and dpkg.log |
| No PKGBUILD review process | **MEDIUM** | NOT IMPLEMENTED | Discipline: always read PKGBUILD before `yay -S` |
| Package manager config not monitored for changes | **MEDIUM** | NOT CONFIRMED | Wazuh FIM should monitor /etc/pacman.conf, /etc/apt/sources.list.d/ |
| No package signature enforcement on all repos | **MEDIUM** | NOT CONFIRMED | Verify SigLevel settings in pacman.conf |
| Homebrew packages on laptop-1 not audited | **MEDIUM** | NOT IMPLEMENTED | Periodic `brew list` audit |
| laptop-2 package state unknown | **LOW** | BY DESIGN | Not the operator's machine |
| No automated dependency vulnerability scanning | **MEDIUM** | NOT IMPLEMENTED | Use `arch-audit` on Arch, `apt list --upgradable` on Ubuntu |
