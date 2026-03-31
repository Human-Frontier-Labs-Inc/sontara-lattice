# UCAN Credential Theft Incident Response Playbook

**System:** Sontara Lattice (claude-peers) fleet
**Last updated:** 2026-03-28
**Audience:** the operator (fleet operator)
**Severity tier:** Tier 3 (Approval Required) -- requires manual credential rotation

---

## Table of Contents

1. [Attack Model](#attack-model)
2. [Detection Signals](#detection-signals)
3. [Immediate Triage (0-5 minutes)](#immediate-triage)
4. [Containment](#containment)
5. [Credential Rotation Procedure](#credential-rotation-procedure)
6. [Root Key Compromise](#root-key-compromise)
7. [Investigation](#investigation)
8. [Recovery](#recovery)
9. [Post-Incident](#post-incident)
10. [Machine-Specific Notes](#machine-specific-notes)

---

## Attack Model

### What UCAN credentials exist and where

Each fleet machine stores credentials in `~/.config/claude-peers/` (or `/root/.config/claude-peers/` on iot-device):

| File | Purpose | Permissions | Sensitivity |
|------|---------|-------------|-------------|
| `identity.pem` | Ed25519 private key (PKCS8 PEM) | 0600 | **CRITICAL** -- proves machine identity |
| `identity.pub` | Ed25519 public key | 0644 | Low -- public by design |
| `root.pub` | Broker's root public key | 0644 | Low -- public, used for chain validation |
| `token.jwt` | Signed JWT with capabilities | 0600 | **HIGH** -- grants API access for 24h (peers) or 1 year (broker root) |

### What an attacker can do with stolen credentials

**Scenario 1: Attacker steals `identity.pem` + `token.jwt` from a peer machine**

The token.jwt contains scoped capabilities (peer-session role):
- `peer/register`, `peer/heartbeat`, `peer/unregister`, `peer/set-summary`
- `peer/list`, `msg/send`, `msg/poll`, `msg/ack`
- `events/read`, `memory/read`

With these, the attacker can:
- **Impersonate the machine** on the broker. Register as that machine, see all peers, read fleet events and memory.
- **Send messages as the machine** to any other peer. Other Claude Code instances will see messages "from" the compromised machine.
- **Read fleet events** including security events, heartbeats, and NATS stream data.
- **NOT write to fleet memory** (peer-session lacks `memory/write`).
- **NOT subscribe to raw NATS** (peer-session lacks `nats/subscribe`).
- **NOT issue new tokens** (only the broker root key can do that).

The attacker does NOT need to be on the Tailscale network. The token is validated by cryptographic signature, not by source IP. They can use it from any IP that can reach the broker (which listens on 0.0.0.0:7899).

**Scenario 2: Attacker steals the broker's `identity.pem` (root key)**

This is catastrophic. The root private key can:
- **Mint new tokens** with any capability set, any TTL, for any audience.
- **Impersonate the broker** completely.
- **Issue tokens that pass validation** on all machines.
- Effectively own the entire fleet's trust infrastructure.

See [Root Key Compromise](#root-key-compromise) for this scenario.

**Scenario 3: Attacker MODIFIES credential files (write, not read)**

If FIM detects a write to identity.pem, the attacker replaced the machine's key. This means:
- The machine's legitimate identity is now destroyed.
- The machine can no longer authenticate to the broker (token was signed for the old key).
- The attacker may have installed their own key to intercept traffic or to deny service.
- This is a destructive attack, not a stealth attack.

### How credential theft happens in practice

1. **SSH compromise leads to file read:** Attacker gains shell access (see BRUTE_FORCE.md), then `cat ~/.config/claude-peers/identity.pem` and `cat ~/.config/claude-peers/token.jwt`.
2. **Process memory dump:** Attacker with root access reads the private key from a running claude-peers process memory.
3. **Backup exposure:** Credential files accidentally included in a backup, git commit, or Syncthing sync to an unprotected machine.
4. **Physical access:** SD card pulled from edge-node or iot-device, mounted, credentials copied.
5. **Supply chain:** Compromised claude-peers binary reads and exfiltrates credentials at runtime.

---

## Detection Signals

### What fires automatically

| Layer | Signal | Detail |
|-------|--------|--------|
| **Wazuh** | Rule 100100 (level 12 = critical) | FIM detects modification of `identity.pem`, `token.jwt`, or `root.pub` |
| **wazuh-bridge** | Publishes to `fleet.security.fim` | SecurityEvent with type=fim, file_path containing the credential file |
| **security-watch** | `checkCredentialTheft()` | Correlates FIM on credential files + peer registration events within 5 minutes |
| **response-daemon** | `IncidentCredentialTheft` (Tier 3) | Captures forensics, sends email, sets status to `approval_pending` |
| **Broker** | Health score +10 (critical) | Machine enters quarantined status. UCAN middleware returns 403. |
| **Wazuh** | Rule 100200 (level 15 = quarantine) | Compound rule: credential change + binary change on same host within 5 minutes |

### What iot-device (AIDE sentinel) detects

iot-device doesn't run Wazuh -- it runs AIDE + auditd. The ghostbox Go awareness sensor monitors:
- AIDE database changes (file integrity)
- auditd file access logs
- Publishes to the same NATS `fleet.security.*` subjects

```bash
# Check AIDE status on iot-device
ssh <iot-device-ip> "aide --check 2>/dev/null | grep -E 'identity|token'"

# Check auditd logs for credential file access
ssh <iot-device-ip> "ausearch -f /root/.config/claude-peers/identity.pem --start recent 2>/dev/null"
```

### What you see

**Email:** Subject line `[fleet-security] ACTION REQUIRED on <machine>: credential_theft`
- Status: `approval_pending` (not auto-resolved -- requires manual rotation)
- Body includes all FIM events and any correlated peer registration events

**Gridwatch Security Page:**
- Machine card shows "quarantined" with score >= 10
- Event feed shows FIM events on credential files
- Perimeter status: "BREACH DETECTED"

**NATS subjects:**
- `fleet.security.fim` -- FIM event for the credential file
- `fleet.security.quarantine` -- escalation from security-watch correlation

---

## Immediate Triage (0-5 minutes)

### Step 1: Determine READ vs WRITE

The Wazuh FIM event tells you whether the file was read, modified, added, or deleted. This distinction is critical.

The syscheck event in the Wazuh alert has a field `syscheck.event` that can be: `modified`, `added`, `deleted`. The FIM configuration in `shared_agent.conf` has `report_changes="yes"` for the claude-peers config directory, so the diff will be available.

**Check the forensic snapshot email or NATS event for the FIM detail:**

```bash
# On broker-server, check recent wazuh-bridge logs
ssh broker-server "journalctl --user -u claude-peers-wazuh-bridge --since '10 min ago' --no-pager | grep -i 'identity\|token'"

# Check the raw Wazuh alert
ssh broker-server "tail -50 /opt/wazuh-data/logs/alerts/alerts.json | jq 'select(.syscheck.path | test(\"identity|token\"))'"
```

**If the event is `modified` or `deleted` (WRITE):**
The attacker replaced or destroyed the key. The machine's identity is gone.
- The legitimate machine can no longer authenticate.
- The attacker may have installed their own key.
- This is visible because the machine will stop heartbeating and fall off the broker.
- **Priority: restore the machine's identity, then investigate how they got write access.**

**If the event shows access time change only (READ):**
The attacker copied the credentials. The machine still works fine.
- The attacker now has a valid token and private key.
- They can impersonate the machine from anywhere.
- **Priority: rotate credentials immediately, then investigate how they got read access.**

### Step 2: Check for anomalous peer registrations

The attacker may already be using the stolen credentials. Check the broker for duplicate registrations:

```bash
# List all registered peers
curl -s http://<broker-ip>:7899/peers \
  -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt)" | jq '.[] | {id, machine, cwd, last_seen}'

# Look for:
# - Two peers claiming the same machine name
# - Peers with unusual cwd paths
# - Peers with recent registration times that don't match your activity
```

### Step 3: Check NATS for suspicious messages

If the attacker has the token, they may be reading or publishing on NATS:

```bash
# Check NATS connections (requires NATS monitoring endpoint)
ssh broker-server "nats server report connections 2>/dev/null | head -30"

# Check for unusual NATS consumer activity
ssh broker-server "nats consumer report FLEET 2>/dev/null"
```

### Step 4: Determine which credential files were accessed

```bash
# Check file timestamps on the affected machine
ssh edge-node "stat ~/.config/claude-peers/identity.pem ~/.config/claude-peers/token.jwt ~/.config/claude-peers/root.pub ~/.config/claude-peers/identity.pub"

# Check if auditd is running and has access logs (Linux)
ssh edge-node "ausearch -f identity.pem --start recent 2>/dev/null"
ssh edge-node "ausearch -f token.jwt --start recent 2>/dev/null"
```

---

## Containment

### Automated containment (already happened)

The response-daemon has:
1. Captured forensic snapshot
2. Sent email with `approval_pending` status
3. Machine health set to quarantined (UCAN middleware blocks it)

But: **the stolen token still works from other IPs.** Quarantining the machine only blocks the machine's own legitimate traffic. The attacker, using the stolen token from a different IP, is NOT blocked by machine quarantine.

### Critical containment gap

The UCAN middleware checks `claims.MachineName` against the health map. But the machine name is embedded in the token by the signer. If the attacker has the token, the request will have the quarantined machine's name, and the middleware WILL block it (returning 403 QUARANTINED).

This means quarantine DOES effectively block the stolen token, as long as the token contains a `MachineName` claim. Verify this:

```bash
# Decode the token (without validation) to check claims
ssh edge-node "cat ~/.config/claude-peers/token.jwt | cut -d. -f2 | base64 -d 2>/dev/null | jq ."
```

If the token has `"machine_name": "edge-node"`, then quarantine blocks it from any IP. If the field is empty, the quarantine check is bypassed and you must rotate immediately.

### Manual containment: invalidate the token

The TokenValidator keeps a map of known token hashes. There is currently no revocation API. To invalidate a stolen token:

**Option 1: Restart the broker (clears the in-memory token validator)**

```bash
ssh broker-server "systemctl --user restart claude-peers-broker"
```

This clears ALL registered tokens. Every machine will need to re-register. The root token still works because it validates against the root public key directly. But all delegated tokens will fail until re-presented.

This is disruptive but effective.

**Option 2: Rotate only the compromised machine's credentials (preferred)**

See [Credential Rotation Procedure](#credential-rotation-procedure) below.

---

## Credential Rotation Procedure

### Single machine rotation (stolen peer token)

This rotates the compromised machine's identity without affecting other machines.

**Step 1: On the compromised machine, generate a new keypair:**

```bash
# SSH to the machine (it's quarantined but SSH still works -- quarantine only affects the broker API)
ssh edge-node

# Backup the old credentials (for forensic purposes)
cd ~/.config/claude-peers
cp identity.pem identity.pem.compromised.$(date +%s)
cp token.jwt token.jwt.compromised.$(date +%s)

# Generate new keypair
claude-peers init client http://<broker-ip>:7899
# This generates new identity.pem + identity.pub and writes config.json
```

**Step 2: On the broker (broker-server), issue a new token:**

```bash
ssh broker-server

# Copy the new public key from the compromised machine
scp edge-node:~/.config/claude-peers/identity.pub /tmp/edge-node-new.pub

# Issue a new peer-session token
claude-peers issue-token /tmp/edge-node-new.pub peer-session

# The command outputs a JWT. Copy it.
```

**Step 3: On the compromised machine, save the new token:**

```bash
ssh edge-node "claude-peers save-token '<paste-jwt-here>'"
```

**Step 4: Unquarantine the machine:**

```bash
curl -X POST http://<broker-ip>:7899/unquarantine \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt)" \
  -d '{"machine": "edge-node"}'
```

**Step 5: Verify the machine reconnects:**

```bash
# Check the machine registers with its new identity
curl -s http://<broker-ip>:7899/peers \
  -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt)" | jq '.[] | select(.machine == "edge-node")'
```

The old token is now invalid because:
- The machine is quarantined (blocks the old token's machine_name claim)
- The broker restart (if done) cleared the token from the validator cache
- Even without restart, the old token's proof chain is still technically valid, but the quarantine blocks it

### Fleet-wide token rotation (if multiple machines compromised)

If the attacker had access to multiple machines' credentials, rotate all of them:

```bash
# On broker-server (broker), for each machine:
MACHINES="workstation edge-node workstation-2 laptop-1 iot-device"

for machine in $MACHINES; do
  echo "=== Rotating $machine ==="

  # Generate new keypair on the machine
  case $machine in
    workstation)    HOST="<workstation-ip>" ;;
    edge-node)   HOST="edge-node" ;;
    workstation-2)  HOST="workstation-2-workstation" ;;
    laptop-1)   HOST="<user>@<laptop-1-ip><laptop-1-ip>" ;;
    iot-device)    HOST="<iot-device-ip>" ;;
  esac

  ssh $HOST "cd ~/.config/claude-peers && cp identity.pem identity.pem.rotated.\$(date +%s) && cp token.jwt token.jwt.rotated.\$(date +%s)"
  ssh $HOST "claude-peers init client http://<broker-ip>:7899"

  # Copy new public key to broker
  scp $HOST:~/.config/claude-peers/identity.pub /tmp/${machine}-new.pub

  # Issue new token
  NEW_TOKEN=$(claude-peers issue-token /tmp/${machine}-new.pub peer-session 2>&1 | tail -1)

  # Save token on the machine
  ssh $HOST "claude-peers save-token '$NEW_TOKEN'"

  echo "  $machine rotated"
done
```

---

## Root Key Compromise

### When to suspect root key compromise

- FIM alert on broker-server's `~/.config/claude-peers/identity.pem` (the broker's root private key)
- The broker machine itself was compromised (SSH brute force succeeded on broker-server)
- Unknown tokens are validating successfully on the broker
- Peers are registering that you didn't authorize

### Impact of root key compromise

The root key (`identity.pem` on broker-server) is an Ed25519 private key that:
- Signs the root token (1 year TTL, all capabilities)
- Is the trust anchor for the entire UCAN chain
- Can mint tokens with ANY capability for ANY audience

If compromised, the attacker can:
- Create tokens for any machine name with all capabilities
- Read and write fleet memory
- Send messages as any machine
- Subscribe to NATS streams
- Effectively become a second broker

### Full PKI rotation (nuclear option)

This takes down the entire fleet temporarily. Every machine must re-enroll.

**Step 1: Stop all services on broker-server:**

```bash
ssh broker-server "systemctl --user stop claude-peers-broker claude-peers-dream claude-peers-supervisor claude-peers-wazuh-bridge claude-peers-security-watch claude-peers-response-daemon"
```

**Step 2: Generate new root keypair on broker-server:**

```bash
ssh broker-server "cd ~/.config/claude-peers && \
  mv identity.pem identity.pem.compromised.\$(date +%s) && \
  mv identity.pub identity.pub.compromised.\$(date +%s) && \
  mv root.pub root.pub.compromised.\$(date +%s) && \
  mv token.jwt token.jwt.compromised.\$(date +%s) && \
  claude-peers init broker"
```

This generates a new root keypair + root token.

**Step 3: Distribute the new root.pub to all fleet machines:**

```bash
NEW_ROOT_PUB="broker-server:~/.config/claude-peers/root.pub"

for machine_host in \
  "<workstation-ip>" \
  "edge-node" \
  "workstation-2-workstation" \
  "<user>@<laptop-1-ip><laptop-1-ip>" \
  "<iot-device-ip>"; do
  scp $NEW_ROOT_PUB ${machine_host}:~/.config/claude-peers/root.pub
done
```

**Step 4: Re-enroll every machine (new keypair + new token):**

Follow the fleet-wide rotation procedure from above, but note that this time the root.pub has changed, so ALL old tokens are now completely invalid (they were signed by the old root key).

**Step 5: Restart broker and all services:**

```bash
ssh broker-server "systemctl --user start claude-peers-broker claude-peers-dream claude-peers-supervisor claude-peers-wazuh-bridge claude-peers-security-watch claude-peers-response-daemon"
```

**Step 6: Verify all machines re-register:**

```bash
# Wait 2 minutes for machines to heartbeat
sleep 120

curl -s http://<broker-ip>:7899/peers \
  -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt)" | jq '.[].machine'
```

### Minimizing downtime during root rotation

The fleet will be down for the duration of steps 2-5. To minimize this:
1. Prepare all new keypairs on the machines BEFORE stopping the broker (step 2 can be done in advance)
2. Have the `issue-token` commands scripted
3. The entire rotation can be done in under 5 minutes if scripted

The NATS token (`CLAUDE_PEERS_NATS_TOKEN`) is separate from UCAN tokens. NATS connections will not be affected by PKI rotation (they use a shared secret, not UCAN).

---

## Investigation

### How were the credentials accessed?

#### Check file access logs

```bash
# If auditd is running (check first)
ssh edge-node "auditctl -l"

# Search for access to credential files
ssh edge-node "ausearch -f identity.pem --start today 2>/dev/null"
ssh edge-node "ausearch -f token.jwt --start today 2>/dev/null"

# If auditd is NOT running, check process list for anything that might have read the files
ssh edge-node "lsof ~/.config/claude-peers/identity.pem 2>/dev/null"
ssh edge-node "lsof ~/.config/claude-peers/token.jwt 2>/dev/null"
```

#### Check for the attacker's entry point

This likely started with an SSH compromise. Run the full investigation from BRUTE_FORCE.md:

```bash
# Recent logins
ssh edge-node "last -20"
ssh edge-node "who"

# SSH logs
ssh edge-node 'journalctl -u sshd --since "2 hours ago" --no-pager | tail -50'

# Process tree
ssh edge-node "ps auxf"
```

#### Check if credentials were exfiltrated

```bash
# Network connections -- look for outbound data transfers
ssh edge-node "ss -tnp | grep ESTAB"

# Check for curl/wget/scp/nc activity in process list
ssh edge-node "ps aux | grep -E '(curl|wget|scp|nc|ncat|socat)'"

# Check bash history for credential access
ssh edge-node "cat ~/.bash_history | grep -E '(identity|token|\.pem|\.jwt|cat |cp |scp )' | tail -20"

# Check if the files were recently read (atime, if not noatime mount)
ssh edge-node "stat -c '%x %n' ~/.config/claude-peers/identity.pem ~/.config/claude-peers/token.jwt"
```

#### Check if the stolen credentials were used

```bash
# On broker-server, check broker access logs
ssh broker-server "journalctl --user -u claude-peers-broker --since '2 hours ago' --no-pager | grep -i 'register\|edge-node'"

# Look for peer registrations from unexpected IPs
# The broker logs peer registration events
ssh broker-server "journalctl --user -u claude-peers-broker --since '2 hours ago' --no-pager | grep 'register'"
```

#### Check Syncthing for credential exposure

The `~/.config/claude-peers/` directory should NOT be synced via Syncthing. But verify:

```bash
# Check if the credentials directory is inside a synced folder
ssh edge-node "syncthing cli config folders list 2>/dev/null"
# Verify ~/.config/claude-peers/ is NOT under ~/projects/ or any synced path
```

---

## Recovery

### Step 1: Complete credential rotation

Follow the [Credential Rotation Procedure](#credential-rotation-procedure) above.

### Step 2: Verify all peers are legitimate

```bash
# List all peers with full detail
curl -s http://<broker-ip>:7899/peers \
  -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt)" | jq .

# Expected machines: workstation, broker-server, edge-node, workstation-2, laptop-1, iot-device
# Any other machine name = unauthorized peer. Investigate immediately.
```

### Step 3: Check NATS consumer state

```bash
ssh broker-server "nats consumer ls FLEET 2>/dev/null"

# Delete any consumers you don't recognize
# Known consumers: security-monitor, security-watch, response-daemon, wazuh-bridge, dream, gridwatch
ssh broker-server "nats consumer rm FLEET <suspicious-consumer>"
```

### Step 4: Verify fleet health

```bash
curl -s http://<broker-ip>:7899/machine-health \
  -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt)" | jq .

# All machines should be "healthy" with score 0 after rotation
```

### Step 5: Update fleet memory

If the attacker had `memory/read` access, they could read fleet memory. If they had `memory/write` (only fleet-write role, not peer-session), they could have modified it. Check:

```bash
curl -s http://<broker-ip>:7899/memory \
  -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt)"

# Review the content for anything unexpected
```

---

## Post-Incident

### Hardware-backed keys (future prevention)

The fundamental problem: Ed25519 private keys stored as files can be read by anyone with file access. The solution is hardware-backed keys that never leave a secure element.

**TPM 2.0 (Linux machines -- workstation, workstation-2, broker-server):**
- Store the Ed25519 key in TPM
- Sign operations go through the TPM API
- The private key never exists as a readable file
- Requires changes to `ucan_keys.go` to use `go-tpm` library

**Secure Enclave (macOS -- laptop-1, laptop-2):**
- Store key in the Secure Enclave
- Requires Keychain API access
- Keys are non-exportable by design

**For Raspberry Pi (edge-node, iot-device):**
- No TPM available
- Consider an external TPM module (e.g., Infineon SLB 9670)
- Or: restrict file permissions more aggressively and enable auditd

### File permission hardening

```bash
# On all machines, ensure credential files are locked down
chmod 600 ~/.config/claude-peers/identity.pem
chmod 600 ~/.config/claude-peers/token.jwt
chmod 700 ~/.config/claude-peers/

# Make the directory immutable (requires root, prevents even root from modifying without removing the flag)
sudo chattr +i ~/.config/claude-peers/identity.pem
# To modify later: sudo chattr -i ~/.config/claude-peers/identity.pem
```

### Enable auditd on all Linux machines

```bash
# Install and configure auditd to log all access to credential files
for host in edge-node workstation-2-workstation <workstation-ip> <broker-ip> <iot-device-ip>; do
  ssh $host "sudo auditctl -w ~/.config/claude-peers/identity.pem -p rwa -k claude-peers-cred"
  ssh $host "sudo auditctl -w ~/.config/claude-peers/token.jwt -p rwa -k claude-peers-cred"
done
```

This logs every read, write, and attribute change to the credential files. Check with:
```bash
ausearch -k claude-peers-cred --start recent
```

### Token TTL reduction

Current TTLs:
- Root token: 1 year
- Peer session tokens: 24 hours

Consider reducing:
- Peer session tokens to 4-8 hours (requires more frequent re-issue, but limits stolen token window)
- Implement automatic token refresh in the client

### Broker access logging

Add request logging to the broker to track which tokens are used from which IPs. Currently the broker does not log the source IP of authenticated requests. This would make stolen token detection much faster.

### Network-level token binding

Consider binding tokens to Tailscale IPs. A token issued to edge-node (100.x.x.x) should only be valid from that IP. This prevents a stolen token from being used off-network. Would require changes to `ucan_middleware.go`.

### Detection tuning

If credential theft was detected too late:
- Ensure `report_changes="yes"` is set on all machines' FIM config (currently only claude-peers directory has this)
- Enable realtime FIM on Arch machines (currently broken with DEB-extracted Wazuh -- needs AUR native install)
- Add inotify watch in the claude-peers binary itself as a backup detection

---

## Machine-Specific Notes

| Machine | Cred path | Key type | Wazuh FIM | Special |
|---------|-----------|----------|-----------|---------|
| workstation | ~/.config/claude-peers/ | Ed25519 file | Realtime (broken on DEB Wazuh, 5min scheduled) | Syncthing syncs ~/projects/ -- ensure creds NOT in synced path |
| broker-server | ~/.config/claude-peers/ | Ed25519 file (ROOT KEY) | Realtime | **BROKER. Root key here. Compromise = total fleet compromise.** |
| edge-node | ~/.config/claude-peers/ | Ed25519 file | Realtime | Pi 5. SD card physical access risk. |
| workstation-2 | ~/.config/claude-peers/ | Ed25519 file | Realtime | May be offline. Token may expire while offline. |
| laptop-1 | ~/.config/claude-peers/ | Ed25519 file | Realtime | macOS. Could use Secure Enclave in future. |
| iot-device | /root/.config/claude-peers/ | Ed25519 file | AIDE + auditd | **Runs as root.** Pi Zero 2W. Physical access risk. 512MB RAM. |
| laptop-2 | N/A | N/A | None | No claude-peers installed. Should never have credentials. |

---

## Quick Reference Card

```
CREDENTIAL THEFT DETECTED (FIM on identity.pem / token.jwt)
    |
    +-- Was it a READ or WRITE?
    |
    +-- WRITE (modified/deleted):
    |     Attacker replaced your key.
    |     Machine identity is destroyed.
    |     Machine will stop working.
    |     --> Generate new keypair + reissue token
    |
    +-- READ (access time changed):
    |     Attacker copied your credentials.
    |     Machine still works (attacker is stealthy).
    |     Attacker can impersonate from anywhere.
    |     --> Rotate immediately. Check for duplicate peers.
    |
    +-- Is it broker-server? (ROOT KEY)
    |
    +-- YES: FULL PKI ROTATION REQUIRED
    |         See "Root Key Compromise" section.
    |         All fleet machines must re-enroll.
    |
    +-- NO: Single machine rotation.
    |        1. Generate new keypair on machine
    |        2. Issue new token from broker
    |        3. Save token on machine
    |        4. Unquarantine
    |        5. Verify reconnection
    |
    +-- Was the token quarantine-blocked?
    |
    +-- Check if token has machine_name claim.
    |   If yes: quarantine blocks stolen token too.
    |   If no: token usable from any IP until expiry.
    |
    +-- Investigate HOW credentials were accessed.
        (SSH compromise? Physical access? Backup leak?)
        See Investigation section.
```

---

## Appendix: UCAN Token Structure

For reference, here is what a decoded peer-session token looks like:

```json
{
  "iss": "<base64url-encoded-ed25519-public-key-of-signer>",
  "aud": ["<base64url-encoded-ed25519-public-key-of-audience>"],
  "sub": "claude-peers",
  "iat": 1711612800,
  "exp": 1711699200,
  "cap": [
    {"resource": "peer/register"},
    {"resource": "peer/heartbeat"},
    {"resource": "peer/unregister"},
    {"resource": "peer/set-summary"},
    {"resource": "peer/list"},
    {"resource": "msg/send"},
    {"resource": "msg/poll"},
    {"resource": "msg/ack"},
    {"resource": "events/read"},
    {"resource": "memory/read"}
  ],
  "prf": "<sha256-hash-of-parent-token>",
  "machine_name": "edge-node"
}
```

The `prf` (proof) field links this token to its parent in the delegation chain. The root token has an empty `prf`. The `iss` (issuer) field contains the signer's public key, which is verified against the root public key for root tokens, or against the parent token's audience for delegated tokens.
