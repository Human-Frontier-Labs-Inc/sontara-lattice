# Playbook: Stolen or Lost Device (Physical Access)

**Severity:** Critical
**Scope:** Per-device, with fleet-wide credential rotation required
**Last updated:** 2026-03-28

## Scenario

A fleet device is physically stolen, lost, or left unlocked in an untrusted location. The attacker gains physical access to the hardware, which may include disk access, active sessions, and persistent authentication tokens.

This playbook covers three specific scenarios ranked by impact:

1. **iot-device stolen from backpack** -- portable cyberdeck, battery-powered, has 4G
2. **laptop-1 stolen from a cafe** -- client work, banking, 1Password
3. **workstation-2 left unlocked at a coworking space** -- secondary dev machine

## What the Attacker Gets Per Device

### iot-device (Pi Zero 2W, Debian, carried in backpack)

| Asset | Location | Risk |
|---|---|---|
| Tailscale auth | Persists across reboots, device stays on the mesh | Attacker can reach every machine on the Tailscale network |
| UCAN token | `~/.config/claude-peers/token.jwt` | Can register as a peer, send messages to Claude sessions, read fleet memory, read events |
| Ed25519 private key | `~/.config/claude-peers/identity.pem` | Can mint delegated tokens if they also have the root public key |
| SSH keys | `~/.ssh/` | Can SSH to broker-server, edge-node, workstation, and any machine with authorized_keys entries |
| NATS token | In environment or `~/.config/claude-peers/config.json` | Can publish/subscribe to the entire FLEET stream |
| sontara-lite agent binary | `~/.local/bin/` | Runs as root, has voice assistant capabilities |
| 4G SIM HAT | Physical hardware | Device can connect from anywhere, not limited to WiFi. Attacker can use it as a remote pivot. |
| Root access | Device runs sontara-lite as root | Full system control |

**Key danger:** iot-device has 4G connectivity. Even if you change your WiFi password, the device can still reach the Tailscale network over cellular. The attacker can be anywhere in the world and still have mesh access. The device runs as root, so there are no local privilege escalation barriers.

### laptop-1 (macOS, HFL work + banking)

| Asset | Location | Risk |
|---|---|---|
| Tailscale auth | Persists | Mesh access |
| UCAN token + identity | `~/.config/claude-peers/` | Peer messaging, fleet memory |
| SSH keys | `~/.ssh/` | Fleet machine access |
| 1Password vault | Desktop app + browser extension | Client credentials, HFL secrets, API keys, banking |
| Browser sessions | Safari/Chrome | Banking sessions, GitHub, GCP console, Vercel, Clerk, Stripe |
| Client data (HFL) | `~/hfl-projects/` | Client source code, contracts, business data |
| Git credentials | `gh` CLI auth, `.gitconfig` | Can push to HFL repos, the operatorV3 repos |
| Email | Browser sessions | Full email access (Gmail) |
| Claude API keys | Environment or config | Anthropic, Vertex AI access |

**Key danger:** This machine has client data and financial access. A breach here is not just a technical incident -- it's a business liability. Client trust, banking security, and 1Password vault contents are all at risk. If disk encryption is not enabled or the screen was unlocked, the attacker has everything.

### workstation-2 (Arch, secondary dev)

| Asset | Location | Risk |
|---|---|---|
| Tailscale auth | Persists | Mesh access |
| UCAN token + identity | `~/.config/claude-peers/` | Peer messaging, fleet access |
| SSH keys | `~/.ssh/` | Fleet machine access |
| Development projects | `~/projects/`, `~/hfl-projects/` (synced via Syncthing) | Source code access |
| Git credentials | `gh` CLI auth | Repo access |
| Claude Code sessions | Active tmux sessions | May have active Claude sessions with full tool access |

**Key danger:** If left unlocked with active tmux sessions, the attacker has live Claude Code sessions that can execute arbitrary commands on any fleet machine. This is instant full fleet compromise without needing to crack any credentials.

## Detection

### How You Know a Device Is Stolen

- **Obvious:** You notice it's missing.
- **Less obvious:** Device goes offline in Tailscale admin panel, then comes back online from an unexpected IP.
- **Worst case:** The attacker uses it while it's still online. You see peer registrations from the stolen device, unexpected messages being sent, or unusual SSH logins from the device's Tailscale IP.

### Detection Signals

```bash
# Check Tailscale admin panel for device status
# https://login.tailscale.com/admin/machines
# Look for: device online from unexpected IP, unexpected last-seen time

# Check broker events for activity from the stolen device's machine name
curl -s -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt)" \
  http://<broker-ip>:7899/events?limit=200 | \
  jq '.[] | select(.machine == "iot-device")'  # or laptop-1, workstation-2

# Check SSH auth logs on broker-server for logins from the device
ssh broker-server "journalctl -u sshd --since '24 hours ago' | grep '<iot-device-ip>'"  # iot-device IP
```

## Response Checklist

### Immediate (Do These First -- Order Matters)

#### 1. Remove the device from Tailscale (cuts mesh access)

```
Go to https://login.tailscale.com/admin/machines
Find the stolen device
Click "..." > "Remove device"
```

This is the single most important action. It immediately cuts the attacker off from every other machine on the mesh. Do this BEFORE anything else.

#### 2. Revoke the UCAN token

The device's token is still valid even after Tailscale removal if the attacker noted the broker URL and token. But without Tailscale, they can't reach the broker (it's only on the mesh). Still, revoke it:

```bash
# The broker doesn't currently support token revocation -- GAP
# Workaround: restart the broker (clears the in-memory token registry)
ssh broker-server "systemctl --user restart claude-peers-broker"
```

**GAP: There is no UCAN token revocation mechanism.** The broker's `TokenValidator` keeps an in-memory `knownTokens` map that grows as tokens are validated. Restarting the broker clears it, but the token itself is still cryptographically valid until expiry. Any machine that cached the token can still use it until the broker restarts.

#### 3. Rotate SSH keys

```bash
# On every fleet machine, remove the stolen device's SSH key from authorized_keys
for machine in broker-server workstation edge-node workstation-2 laptop-1; do
  echo "=== $machine ==="
  ssh $machine "grep -n 'stolen-device-key-comment' ~/.ssh/authorized_keys"
  # Then remove the matching line
done

# Generate new SSH keys on the stolen device's replacement (when you have one)
```

#### 4. Rotate the NATS token

```bash
# On broker-server, generate a new NATS token
# Update nats-server.conf with the new token
# Restart NATS
ssh broker-server "sudo systemctl restart nats-server"

# Update config.json on every remaining fleet machine with the new token
```

### Device-Specific Actions

#### If iot-device Was Stolen

- [ ] Remove from Tailscale (immediately -- it has 4G, can connect from anywhere)
- [ ] Rotate NATS token (iot-device has it in config)
- [ ] Check broker-server SSH logs for recent iot-device connections
- [ ] Check broker events for peer registrations from iot-device
- [ ] Rotate any API keys that were in iot-device's environment
- [ ] Consider: can you remotely wipe? Pi Zero has no remote management. If the 4G is active and SSH is still reachable via the old Tailscale IP... it's a race condition. Remove from Tailscale first, then try SSH via 4G direct IP if known.
- [ ] The SIM card: contact the carrier to suspend the 4G line if the attacker could use it for data exfiltration or as a pivot

#### If laptop-1 Was Stolen

- [ ] Remove from Tailscale
- [ ] **Lock 1Password immediately:** Log into 1Password.com from another device, go to Settings > Sign out everywhere. Change the master password.
- [ ] **Revoke browser sessions:** Gmail, GitHub, GCP, Vercel, Clerk, Stripe -- sign out all sessions from each service's security settings
- [ ] **GitHub:** Go to Settings > Sessions > Revoke all. Rotate any personal access tokens.
- [ ] **GCP:** Go to IAM > Service accounts > Rotate keys. Check for unauthorized API calls in Cloud Audit Logs.
- [ ] **Banking:** Contact your bank. Lock online banking access. Monitor for unauthorized transactions.
- [ ] **HFL client notification:** If client data was on the machine and disk was not encrypted, you may have a legal obligation to notify affected clients. Consult with partner.
- [ ] Check if FileVault (disk encryption) was enabled: if yes, the disk is encrypted at rest and the attacker needs your password. If no, assume all data is compromised.
- [ ] Apple: Mark as lost/stolen via Find My Mac. Initiate remote wipe if possible.

#### If workstation-2 Was Left Unlocked

- [ ] **If you can physically get to it:** Lock it immediately. Check `last` for recent logins, check browser history, check clipboard, check running processes.
- [ ] **If you can't get to it:** SSH to it from another machine and lock the screen: `ssh workstation-2 "loginctl lock-sessions"`
- [ ] Check for active Claude Code sessions: `ssh workstation-2 "tmux list-sessions"`
- [ ] If Claude sessions were active, assume the attacker had full tool access. Follow the full credential rotation path.
- [ ] If the machine was only unlocked for a few minutes and you can verify no one touched it, the risk is lower. Still rotate claude-peers credentials as a precaution.

### Full Credential Rotation (Required for All Stolen Devices)

1. **Claude-peers credentials** on the stolen device: keypair + token. Cannot be individually revoked (GAP), so restart the broker.
2. **SSH keys:** Remove from authorized_keys on all machines.
3. **NATS token:** Rotate and distribute new token to all remaining machines.
4. **LLM API keys:** Rotate Anthropic and Vertex AI keys if they were accessible on the stolen device.
5. **GitHub tokens:** Revoke and regenerate.
6. **Tailscale:** Already removed from mesh, but also revoke the Tailscale auth key if one was used.

## Prevention

### Must-Do

1. **Full disk encryption on every device:**
   - laptop-1: FileVault (check: `fdesetup status`)
   - workstation-2: LUKS (`lsblk -f` to verify)
   - iot-device: dm-crypt on the SD card (currently NOT encrypted -- GAP)
   - If the disk is encrypted and the device is powered off, the attacker gets nothing.

2. **Auto-lock on all devices:**
   - laptop-1: System Preferences > Lock Screen > Require password immediately
   - workstation-2: Hyprland idle lock via `hyprlock`
   - iot-device: Auto-lock doesn't apply (headless), but ensure SSH requires key auth

3. **UCAN token revocation mechanism:** Implement a revocation list in the broker. When a device is stolen, add its token hash to the revocation list. The broker rejects the token even if it's cryptographically valid.

4. **Tailscale device approval:** Enable device approval in Tailscale admin so new devices require manual approval before joining the mesh. This prevents an attacker from re-adding a removed device.

### Should-Do

5. **Remote wipe capability:** For iot-device specifically (portable, battery-powered, 4G), implement a kill switch: a cron job that checks a remote endpoint. If the endpoint returns a wipe signal, the device erases its credentials and shuts down.

6. **Credential storage:** Don't store tokens and keys as plain files. Use a TPM or secure enclave where available (laptop-1 has Secure Enclave, workstation-2 may have a TPM).

7. **Session timeouts:** Claude-peers UCAN tokens are minted with 365-day TTL (`365*24*time.Hour` in config.go). This is far too long. Reduce to 7-30 days with automatic renewal.

## Architectural Weakness

Three compounding problems make device theft devastating:

1. **Long-lived credentials everywhere:** UCAN tokens last 365 days. SSH keys don't expire. NATS tokens don't expire. A stolen device's credentials remain valid for months.

2. **No token revocation:** The broker has no revocation list. A valid token is always accepted until it expires or the broker restarts. You cannot selectively invalidate a single device's access.

3. **Flat trust model:** Every device with a valid UCAN token has the same access. iot-device (a Pi Zero carried in a backpack) has the same fleet capabilities as workstation (the primary dev machine in a controlled environment). There are no trust tiers based on device type, location, or security posture.

4. **iot-device is uniquely dangerous:** It's portable (carried everywhere), battery-powered (stays on when stolen), has 4G (reaches the mesh from anywhere), runs as root (no privilege barriers), and has full fleet credentials. It's the most likely device to be physically compromised and the hardest to remotely neutralize.
