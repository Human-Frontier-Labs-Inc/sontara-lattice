# Firmware / Boot Integrity Attack Playbook

Sontara Lattice fleet -- last updated 2026-03-28.

**Tier:** 3 (Approval) -- physical access attacks require full machine audit and potential rebuild. No automated detection exists for boot-level tampering.

**Current Detection: NONE** -- No boot integrity monitoring on any fleet machine. Raspberry Pi devices have no Secure Boot. x86 machines (workstation, workstation-2) may or may not have Secure Boot enabled. No dm-verity, no measured boot, no TPM attestation configured.

**Fleet machines by boot risk:**
| Machine | Architecture | Boot Media | Secure Boot | Physical Access Risk |
|---------|-------------|-----------|-------------|---------------------|
| edge-node | ARM64, Pi 5 | microSD card | Not available | HIGH -- cyberdeck, carried around |
| iot-device | ARM64, Pi Zero 2W | microSD card | Not available | HIGH -- portable backpack cyberdeck |
| workstation | x86_64, N100 | NVMe/SSD | Unknown/unchecked | MEDIUM -- stationary desktop |
| workstation-2 | x86_64, i5 | NVMe/SSD | Unknown/unchecked | MEDIUM -- laptop, carried to cafes |
| broker-server | x86_64 | NVMe/SSD | Unknown/unchecked | LOW -- homelab, physically secured |
| laptop-1 | ARM64, M-series | Internal SSD | Apple Secure Boot | LOW -- T2/Apple Silicon secure boot |
| laptop-2 | ARM64, M-series | Internal SSD | Apple Secure Boot | NOT CONTROLLED |

---

## Attack Surface

### Raspberry Pi SD Card Attacks (edge-node, iot-device)

**SD card swap:** The attacker physically removes the SD card, modifies it on their machine, re-inserts it. The Pi boots the modified OS without any integrity check.

**Boot partition modification:** The Pi boot partition (`/boot/firmware/` on Debian) is FAT32 and contains:
- `config.txt` -- hardware config, can enable UART debug, change boot behavior
- `cmdline.txt` -- kernel command line, can add `init=/bin/sh` for single-user root shell
- `kernel*.img` -- the actual kernel, can be replaced entirely
- `initramfs` -- initial ramdisk, can contain backdoors that execute before the real OS
- `overlays/` -- device tree overlays, can modify hardware behavior

**Evil maid on iot-device:** iot-device is carried in a backpack. If left unattended (cafe, conference), an attacker could swap the SD card in under 30 seconds. The Pi Zero 2W has no tamper detection.

### x86 Boot Attacks (workstation, workstation-2, broker-server)

**UEFI firmware modification:** If Secure Boot is not enabled, the attacker can:
- Replace the bootloader (GRUB, systemd-boot) with a trojaned version
- Add a UEFI rootkit that persists across OS reinstalls
- Modify kernel command line to disable security features

**initramfs injection:** Modify `/boot/initramfs-*.img` to include a backdoor that runs before the real init system. The attacker needs root access (or physical access + boot from USB).

**Evil maid on workstation-2:** Laptop at a cafe. Boot from USB, modify the boot partition, reboot into the original OS. If full-disk encryption is used, the attacker can install a keylogger in the bootloader to capture the passphrase.

### macOS Secure Boot (laptop-1, laptop-2)

Apple Silicon Macs have hardware-enforced secure boot. The attack surface is significantly smaller:
- Can't modify the boot chain without Apple-signed code
- Recovery mode requires the user's password
- FileVault encryption key is hardware-bound

**Risk is primarily logical, not physical:** macOS compromise happens via software (malware, phishing, browser exploits), not boot-level attacks. See the existing STOLEN_DEVICE.md playbook for macOS scenarios.

---

## 1. Detection Signals

### Current state: NO automated detection

There are no boot integrity checks configured on any fleet machine. If an attacker modifies the boot partition, kernel, or initramfs, nothing will alert.

### Manual detection signals

**Machine behavior changes after physical access window:**
- Machine takes longer to boot
- Network interfaces have unexpected IPs
- Tailscale identity changes (Tailscale keys are stored on the OS filesystem)
- Services fail to start (modified systemd unit files in initramfs)
- SSH host key changes (the machine presents a different host key -- SSH will warn "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED")

**Hardware-level signals on Pi devices:**
- SD card slot shows signs of removal (scratches, misalignment)
- SD card LED activity during unexpected times
- SD card has different capacity or brand than expected

### What you receive (currently nothing)

No email. No Gridwatch alert. No Wazuh event. Boot-level modifications happen below the OS level where Wazuh operates.

---

## 2. Immediate Triage

If you suspect boot tampering (e.g., machine was unattended in a public place, or you notice behavior changes after a physical access window):

### Step 1: Check SSH host key continuity

```bash
# If SSH warns about changed host key for a fleet machine, DO NOT PROCEED
# This is the strongest signal of a machine swap/rebuild
ssh -o StrictHostKeyChecking=ask <machine>
```

### Step 2: Check Tailscale identity

```bash
# On the suspected machine
ssh <machine> "tailscale status --json | jq '.Self.PublicKey'"
# Compare against known key (keep a record)
```

### Step 3: Verify kernel and boot files

**For Raspberry Pi (edge-node, iot-device):**

```bash
# Check boot partition contents
ssh <machine> "ls -la /boot/firmware/"
ssh <machine> "sha256sum /boot/firmware/kernel*.img"
ssh <machine> "cat /boot/firmware/config.txt"
ssh <machine> "cat /boot/firmware/cmdline.txt"

# Check for unexpected kernel parameters
ssh <machine> "cat /proc/cmdline"

# Check kernel version matches expected
ssh <machine> "uname -a"
```

**For x86 Linux (workstation, workstation-2, broker-server):**

```bash
# Check bootloader
ssh <machine> "ls -la /boot/"
ssh <machine> "sha256sum /boot/vmlinuz-*"
ssh <machine> "sha256sum /boot/initramfs-*.img" 2>/dev/null || ssh <machine> "sha256sum /boot/initrd.img-*" 2>/dev/null

# Check kernel command line
ssh <machine> "cat /proc/cmdline"

# Check Secure Boot status
ssh <machine> "mokutil --sb-state" 2>/dev/null || echo "mokutil not available"

# Check UEFI variables (if available)
ssh <machine> "efivar -l 2>/dev/null | head -10" || echo "efivar not available"
```

**For macOS (laptop-1):**

```bash
ssh <user>@<laptop-1-ip><laptop-1-ip> "csrutil status"
ssh <user>@<laptop-1-ip><laptop-1-ip> "system_profiler SPHardwareDataType | grep 'Secure Boot'"
```

### Step 4: Check initramfs contents

```bash
# Extract and inspect initramfs on x86 Linux
ssh <machine> "lsinitramfs /boot/initramfs-$(uname -r).img 2>/dev/null | head -50" || \
ssh <machine> "lsinitrd /boot/initramfs-$(uname -r).img 2>/dev/null | head -50"

# Look for unexpected files in initramfs
ssh <machine> "lsinitramfs /boot/initramfs-$(uname -r).img 2>/dev/null | grep -viE 'lib/modules|lib/firmware|bin/|sbin/|etc/|usr/'" || echo "lsinitramfs not available"

# On Raspberry Pi
ssh <machine> "ls -la /boot/firmware/initramfs*"
```

### Decision point

| Finding | Action |
|---------|--------|
| SSH host key changed | Machine identity compromised. Do NOT trust. Proceed to containment. |
| Kernel hash mismatch against known-good | Kernel replaced. Full rebuild required. |
| cmdline.txt has unexpected parameters (`init=/bin/sh`, `nosec`, etc.) | Boot parameter injection. Rebuild. |
| config.txt has `enable_uart=1` that wasn't there before | Debug interface enabled. Check for data exfil via UART. |
| initramfs contains unexpected scripts | Bootkit installed. Full rebuild required. |
| Everything matches, no anomalies | Probably not a boot attack. Investigate other vectors. |

---

## 3. Containment

### If boot tampering is confirmed on a Pi device

```bash
# Immediately disconnect from Tailscale to prevent lateral movement
ssh <machine> "sudo tailscale down"

# If reachable via local network, power off
ssh <machine> "sudo poweroff"

# Physical: remove the SD card
```

### If boot tampering is confirmed on an x86 machine

```bash
# Disconnect from Tailscale
ssh <machine> "sudo tailscale down"

# Do NOT power off yet -- capture forensics first (see section 4)
# The compromised boot chain is on disk; powering off doesn't destroy it
# But running processes may have volatile evidence
```

### Quarantine at the fleet level

```bash
# Quarantine the machine at the broker level
curl -X POST -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt)" \
  http://<broker-ip>:7899/machine-health \
  -d '{"machine": "<machine>", "severity": "quarantine", "description": "boot integrity compromise"}'
```

---

## 4. Forensic Analysis

### Preserve the compromised boot media

**For Pi SD card:**

1. Power off the Pi
2. Remove the SD card
3. On a trusted machine, create a full image:
   ```bash
   sudo dd if=/dev/sdX of=/tmp/compromised-sd-<machine>-$(date +%Y%m%d).img bs=4M
   sha256sum /tmp/compromised-sd-<machine>-$(date +%Y%m%d).img
   ```
4. Mount the image read-only for analysis:
   ```bash
   sudo mkdir -p /mnt/compromised-boot /mnt/compromised-root
   LOOP=$(sudo losetup --find --show --partscan /tmp/compromised-sd-<machine>-$(date +%Y%m%d).img)
   sudo mount -o ro ${LOOP}p1 /mnt/compromised-boot
   sudo mount -o ro ${LOOP}p2 /mnt/compromised-root
   ```

**For x86 boot partition:**

```bash
# From a live USB or another machine, mount the disk read-only
sudo mount -o ro /dev/<boot-partition> /mnt/compromised-boot
```

### Analyze boot modifications

```bash
# Compare config.txt against known-good (from git or backup)
diff /mnt/compromised-boot/config.txt /path/to/known-good/config.txt

# Check kernel binary
sha256sum /mnt/compromised-boot/kernel*.img
file /mnt/compromised-boot/kernel*.img

# Check for added files
ls -laR /mnt/compromised-boot/ > /tmp/compromised-boot-listing.txt
# Compare against clean SD card listing

# Check initramfs
# Extract on a trusted machine
mkdir /tmp/initramfs-extract && cd /tmp/initramfs-extract
zcat /mnt/compromised-boot/initramfs*.img 2>/dev/null | cpio -idm 2>/dev/null
# Or for modern initramfs:
unmkinitramfs /mnt/compromised-boot/initramfs*.img /tmp/initramfs-extract/ 2>/dev/null

# Look for suspicious scripts
grep -r "curl\|wget\|nc \|bash\|/dev/tcp\|base64" /tmp/initramfs-extract/
```

### Check for persistent rootkits on the root filesystem

```bash
# Check for modified system binaries
for bin in ssh sshd sudo su login passwd; do
  sha256sum /mnt/compromised-root/usr/bin/$bin 2>/dev/null
  sha256sum /mnt/compromised-root/usr/sbin/$bin 2>/dev/null
done

# Check for LD_PRELOAD
cat /mnt/compromised-root/etc/ld.so.preload 2>/dev/null

# Check for kernel modules
ls /mnt/compromised-root/lib/modules/*/extra/ 2>/dev/null
ls /mnt/compromised-root/lib/modules/*/updates/ 2>/dev/null

# Check SSH authorized_keys
cat /mnt/compromised-root~/.ssh/authorized_keys

# Check claude-peers credentials
ls -la /mnt/compromised-root~/.config/claude-peers/
```

---

## 5. Recovery

### Full SD card re-flash (Pi devices)

This is the ONLY safe recovery for a compromised Pi. Do not attempt targeted cleanup.

```bash
# Download fresh OS image
# For edge-node (Pi 5, Debian):
wget https://downloads.raspberrypi.com/raspios_arm64/images/...

# Flash to a NEW SD card (never reuse the compromised one for the same machine)
sudo dd if=fresh-image.img of=/dev/sdX bs=4M status=progress

# After first boot:
# 1. Install Wazuh agent
# 2. Install claude-peers binary from trusted build
# 3. Configure Tailscale
# 4. Re-issue UCAN credentials
# 5. Restore application configs from dotfiles (chezmoi)
```

### x86 machine rebuild

```bash
# 1. Boot from USB installer
# 2. Full wipe and reinstall
# 3. Enable Secure Boot in BIOS if available
# 4. Re-apply configuration via chezmoi
# 5. Re-install Wazuh agent
# 6. Re-deploy claude-peers
# 7. Re-issue UCAN credentials
```

### Rotate credentials after boot compromise

A boot-level compromise means the attacker had access to everything on disk:

```bash
# Rotate SSH keys on the rebuilt machine
ssh <machine> "ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ''"

# Rotate claude-peers credentials
ssh <machine> "claude-peers init client http://<broker-ip>:7899"
# Issue new token from broker
ssh broker-server "claude-peers issue-token /path/to/<machine>-identity.pub peer-session"

# Rotate Tailscale key
ssh <machine> "sudo tailscale down && sudo tailscale up --reset"

# Update authorized_keys on all other machines to remove the old key
```

---

## 6. Post-Incident Improvements

### For Raspberry Pi devices

**Encrypted root filesystem:**
Use LUKS on the root partition. The boot partition is still FAT32 (Pi limitation), but the root filesystem and all credentials are encrypted at rest. An attacker who swaps the SD card gets the boot partition but not the credentials.

```bash
# Set up LUKS on root partition during initial install
# Requires initramfs with cryptsetup support
# Key can be stored in hardware (Pi 5 has a secure element, Pi Zero 2W does not)
```

**Boot hash verification script:**
Create a systemd service that runs early in boot and verifies boot file hashes:

```bash
#!/bin/bash
# /usr/local/bin/verify-boot.sh
EXPECTED_KERNEL_HASH="<hash>"
ACTUAL=$(sha256sum /boot/firmware/kernel*.img | awk '{print $1}')
if [ "$ACTUAL" != "$EXPECTED_KERNEL_HASH" ]; then
  # Alert via NATS if network is up, or blink LED, or refuse to start services
  logger -p auth.crit "BOOT INTEGRITY FAILURE: kernel hash mismatch"
fi
```

**Physical tamper indicators:**
- Mark the SD card slot with tamper-evident tape or nail polish
- For iot-device: the cyberdeck case could have a micro-switch that detects opening

### For x86 machines

**Enable UEFI Secure Boot:**

```bash
# Check current status
mokutil --sb-state

# If disabled, enable in BIOS/UEFI settings
# Enroll distribution keys (Arch, Ubuntu handle this automatically)
# Verify after reboot:
mokutil --sb-state  # Should show "SecureBoot enabled"
```

**Enable TPM measured boot (if TPM available):**

```bash
# Check for TPM
ls /dev/tpm*
cat /sys/class/tpm/tpm0/tpm_version_major

# With TPM 2.0, use systemd-pcrphase to measure boot stages
# Bind LUKS key to TPM PCR values -- disk won't decrypt if boot chain is modified
```

**Enable dm-verity for read-only root:**
For broker-server (the most critical machine), consider dm-verity to cryptographically verify the root filesystem at every read. Any modification causes IO errors immediately.

### Boot integrity monitoring service

Create a fleet-wide boot hash inventory:

```bash
# Collect boot hashes from all machines
for machine in workstation broker-server edge-node workstation-2 iot-device; do
  echo "=== $machine ==="
  ssh "$machine" "sha256sum /boot/vmlinuz-* /boot/initramfs-* /boot/firmware/kernel* 2>/dev/null"
done > ~/boot-hash-inventory-$(date +%Y%m%d).txt

# Store in a secure location (not on the fleet machines themselves)
# Compare periodically
```

Add this as a fleet-scout check: hash the boot files on every health check run and compare against the inventory. Alert on mismatch.
