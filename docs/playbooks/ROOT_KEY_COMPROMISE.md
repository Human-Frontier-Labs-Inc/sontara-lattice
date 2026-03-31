# UCAN Root Key Compromise Incident Response Playbook

**System:** Sontara Lattice (claude-peers) fleet
**Last updated:** 2026-03-28
**Audience:** the operator (fleet operator)
**Severity tier:** MAXIMUM -- this is the single most critical secret in the entire fleet

---

## Table of Contents

1. [What the Root Key Is](#what-the-root-key-is)
2. [Impact Assessment](#impact-assessment)
3. [Detection](#detection)
4. [Immediate Triage (0-5 minutes)](#immediate-triage)
5. [Containment](#containment)
6. [Full PKI Rotation Procedure](#full-pki-rotation-procedure)
7. [Investigation](#investigation)
8. [Recovery Verification](#recovery-verification)
9. [Post-Incident Hardening](#post-incident-hardening)
10. [Monitoring Gaps](#monitoring-gaps)

---

## What the Root Key Is

The Ed25519 root private key lives at:

```
broker-server:~/.config/claude-peers/identity.pem
```

This single file is the trust anchor for the entire Sontara Lattice fleet. It is a PKCS8-encoded Ed25519 private key (PEM format), file permissions 0600, owned by the `user` user.

The root key:
- Signs the root token (`token.jwt` on broker-server, 1 year TTL, all capabilities)
- Is the issuer (`iss` claim) that the `TokenValidator` checks for root tokens (tokens with empty `prf` field)
- Can mint tokens with ANY capability (`peer/*`, `msg/*`, `events/read`, `memory/*`, `nats/subscribe`) for ANY audience
- Is the only key that can create delegation chains -- all other tokens trace back to it

The corresponding public key exists in two places:
- `broker-server:~/.config/claude-peers/identity.pub` (broker's own copy)
- `<every-machine>:~/.config/claude-peers/root.pub` (distributed to all fleet machines for chain validation)

---

## Impact Assessment

If the root private key is compromised, the attacker can:

### Total Fleet Control
- **Mint tokens with ALL capabilities** -- `peer/register`, `msg/send`, `memory/write`, `events/read`, everything
- **Impersonate any machine** -- create a token with any `machine_name` claim
- **Create fake delegation chains** -- mint a parent token, then delegate child tokens that pass the broker's chain validation
- **Read and write fleet memory** -- exfiltrate operational data, inject malicious instructions
- **Send messages as any peer** -- social engineering between Claude Code instances
- **Register fake peers** -- create phantom machines that appear legitimate
- **Subscribe to all NATS events** (if they also have the NATS token, which is in `config.json` on the same machine)

### What They Cannot Do (with just the root key)
- **SSH into fleet machines** -- SSH keys are separate from UCAN keys
- **Access the Anthropic API directly** -- separate credential
- **Modify Wazuh rules** -- separate system (but they CAN suppress alerts by quarantining the broker via crafted events)
- **Access NATS without the NATS token** -- NATS auth is a separate shared secret (but it is in `config.json` on the same machine, so if they have shell access, they have both)

### The Compound Threat

The root key lives on broker-server, which also hosts:
- The NATS server (token in `config.json`)
- The Wazuh manager (password in `~/docker/wazuh/.env`)
- The Anthropic API key (in environment)
- The LiteLLM proxy key (in environment or `config.json`)
- The broker database (`~/.claude-peers.db`)

If an attacker has shell access to broker-server sufficient to read `identity.pem`, they likely also have access to ALL other secrets on that machine. Assume a root key compromise means FULL broker-server compromise and treat accordingly.

---

## Detection

### What Fires Automatically

| Layer | Signal | What It Detects | Limitation |
|-------|--------|----------------|------------|
| **Wazuh FIM** | Rule 100100, level 12 (critical) | MODIFICATION of `identity.pem` (write, not read) | Does NOT detect read-only access (file copy without modification) |
| **wazuh-bridge** | `fleet.security.fim` event | Publishes SecurityEvent for the FIM alert | Only fires if Wazuh detects the change |
| **Broker health** | Score +10 (critical) | Machine enters quarantined state | Quarantines broker-server itself, which IS the broker |
| **security-watch** | `checkCredentialTheft()` | Correlates FIM on credential files + peer registration within 5 min | Only if the attacker registers a peer (they might not) |
| **response-daemon** | `IncidentCredentialTheft` (Tier 3) | Captures forensics, sends email | broker-server forensics = forensics on the compromised machine itself |

### Critical Detection Gap: Read Without Modify

**The most dangerous scenario is a silent read of `identity.pem`.** If the attacker copies the file content without modifying it:
- Wazuh FIM will NOT fire (FIM monitors checksums, not access)
- `auditd` WOULD catch it -- but only if `auditd` is configured to watch the file
- The attacker walks away with the root key and you have no idea

**Current state of `auditd` on broker-server:** NOT CONFIGURED for claude-peers credential files.

This is the single largest detection gap in the entire fleet.

### How You Might Notice Without Automated Detection

- Unknown peers appearing in `claude-peers status` that you did not enroll
- Fleet memory modified with content you did not write
- Messages appearing between peers that neither side sent
- NATS consumer list showing unknown consumers
- Broker logs showing token validation for tokens you did not issue

---

## Immediate Triage (0-5 minutes)

### Step 1: Confirm the compromise

Was the root key actually accessed, or is this a false alarm?

```bash
# Check if identity.pem was modified (FIM alert)
ssh broker-server "stat ~/.config/claude-peers/identity.pem"
# Check mtime, ctime, atime

# If auditd is running, check access logs
ssh broker-server "ausearch -f ~/.config/claude-peers/identity.pem --start today 2>/dev/null"

# Check for unexpected processes that might have read the key
ssh broker-server "lsof ~/.config/claude-peers/identity.pem 2>/dev/null"

# Check recent logins to broker-server
ssh broker-server "last -20"
ssh broker-server "who"

# Check if the key file content matches what you expect (compare checksum)
ssh broker-server "sha256sum ~/.config/claude-peers/identity.pem"
```

### Step 2: Check for unauthorized token usage

```bash
# List all registered peers -- look for unknown machines
curl -s http://<broker-ip>:7899/list-peers \
  -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt)" \
  -H "Content-Type: application/json" \
  -d '{"scope":"all","cwd":"/"}' | jq '.[].machine'

# Expected machines: workstation, broker-server, edge-node, workstation-2, laptop-1, iot-device
# ANYTHING ELSE = unauthorized peer

# Check recent events for unknown registrations
curl -s http://<broker-ip>:7899/events?limit=50 \
  -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt)" | jq '.[] | select(.type == "peer_joined")'

# Check NATS consumers for unknowns
ssh broker-server "nats consumer ls FLEET 2>/dev/null"
# Known consumers: security-monitor, security-watch, response-daemon, wazuh-bridge, dream, gridwatch
```

### Step 3: Assess the scope

If broker-server was compromised, check what else was accessed:

```bash
# Check all sensitive files
ssh broker-server "stat ~/.config/claude-peers/config.json"  # Contains NATS token, LLM key
ssh broker-server "stat ~/docker/wazuh/.env"                 # Contains Wazuh password
ssh broker-server "env | grep -i 'anthropic\|api_key\|token' | head -20"  # Environment secrets

# Check bash history for credential access
ssh broker-server "cat ~/.bash_history | grep -E '(identity|token|\.pem|\.jwt|config\.json|\.env|cat |cp |scp |curl )' | tail -30"

# Check for data exfiltration
ssh broker-server "ss -tnp | grep ESTAB"
```

---

## Containment

### Stop the bleeding (do this BEFORE rotation)

**If the compromise is confirmed or strongly suspected, shut everything down first.**

```bash
# Step 1: Stop the broker to prevent any further authenticated requests
ssh broker-server "systemctl --user stop claude-peers-broker"

# Step 2: Stop all fleet services on broker-server
ssh broker-server "systemctl --user stop claude-peers-dream claude-peers-supervisor claude-peers-wazuh-bridge claude-peers-security-watch claude-peers-response-daemon"

# Step 3: Block external access to the broker port (if not already Tailscale-only)
ssh broker-server "sudo iptables -A INPUT -p tcp --dport 7899 ! -i tailscale0 -j DROP"
ssh broker-server "sudo iptables -A INPUT -p tcp --dport 4222 ! -i tailscale0 -j DROP"

# Step 4: Kill any suspicious processes
ssh broker-server "ps auxf | grep -v grep | grep -E '(claude-peers|nats|curl|wget|nc |socat)'"
# Kill anything that should not be running
```

At this point the fleet is DOWN. No broker, no NATS publishing, no security monitoring. This is intentional -- a compromised trust root is worse than no trust at all.

---

## Full PKI Rotation Procedure

This is the nuclear option. It replaces the root key, root token, all machine tokens, and all delegated tokens. Every machine must re-enroll.

**Estimated time:** 10-15 minutes if scripted, 20-30 minutes manual.
**Fleet downtime:** Full -- from when you stop the broker until all machines re-enroll.

### Step 1: Back up the compromised key (for forensics)

```bash
ssh broker-server "cd ~/.config/claude-peers && \
  cp identity.pem identity.pem.compromised.$(date +%s) && \
  cp identity.pub identity.pub.compromised.$(date +%s) && \
  cp root.pub root.pub.compromised.$(date +%s) && \
  cp token.jwt token.jwt.compromised.$(date +%s)"
```

### Step 2: Generate new root keypair and root token

```bash
ssh broker-server "claude-peers init broker"
```

This generates:
- New `identity.pem` (root private key, PKCS8 PEM, 0600)
- New `identity.pub` (root public key, PKIX PEM, 0644)
- New `root.pub` (copy of the public key for distribution)
- New `token.jwt` (root token, 1 year TTL, all capabilities)
- Overwrites `config.json` with `role: broker`

Verify the new key was generated:

```bash
ssh broker-server "ls -la ~/.config/claude-peers/identity.pem ~/.config/claude-peers/token.jwt"
ssh broker-server "openssl pkey -in ~/.config/claude-peers/identity.pem -text -noout 2>/dev/null | head -3"
```

### Step 3: Distribute the new root.pub to all fleet machines

Every machine needs the new `root.pub` to validate tokens signed by the new root key.

```bash
# Define fleet SSH targets
declare -A FLEET=(
  [workstation]="<workstation-ip>"
  [edge-node]="edge-node"
  [workstation-2]="<workstation-2-ip>"
  [laptop-1]="<user>@<laptop-1-ip><laptop-1-ip>"
  [iot-device]="<iot-device-ip>"
)

# Copy new root.pub to each machine
for machine in "${!FLEET[@]}"; do
  HOST="${FLEET[$machine]}"
  echo "=== Distributing root.pub to $machine ==="
  scp broker-server:~/.config/claude-peers/root.pub ${HOST}:~/.config/claude-peers/root.pub
  echo "  done"
done
```

### Step 4: Re-enroll every machine (new keypair + new token)

Each machine gets a fresh keypair and a new token signed by the new root key.

```bash
declare -A FLEET=(
  [workstation]="<workstation-ip>"
  [edge-node]="edge-node"
  [workstation-2]="<workstation-2-ip>"
  [laptop-1]="<user>@<laptop-1-ip><laptop-1-ip>"
  [iot-device]="<iot-device-ip>"
)

for machine in "${!FLEET[@]}"; do
  HOST="${FLEET[$machine]}"
  echo "=== Re-enrolling $machine ==="

  # Backup old credentials
  ssh $HOST "cd ~/.config/claude-peers && \
    cp identity.pem identity.pem.rotated.\$(date +%s) 2>/dev/null; \
    cp token.jwt token.jwt.rotated.\$(date +%s) 2>/dev/null"

  # Generate new machine keypair
  ssh $HOST "claude-peers init client http://<broker-ip>:7899"

  # Copy the new public key to broker for token issuance
  scp ${HOST}:~/.config/claude-peers/identity.pub /tmp/${machine}-new.pub

  # Issue new token from the broker (on broker-server)
  NEW_TOKEN=$(ssh broker-server "claude-peers issue-token /tmp/${machine}-new.pub peer-session" 2>&1 | tail -1)

  # First copy the machine pub key to the broker
  scp /tmp/${machine}-new.pub broker-server:/tmp/${machine}-new.pub
  NEW_TOKEN=$(ssh broker-server "claude-peers issue-token /tmp/${machine}-new.pub peer-session" 2>&1 | tail -1)

  # Save the token on the machine
  ssh $HOST "claude-peers save-token '$NEW_TOKEN'"

  echo "  $machine re-enrolled"
done
```

### Step 5: If NATS token was also compromised, rotate it now

If the attacker had shell access to broker-server, they had access to `config.json` which contains the NATS token. Rotate it per the procedure in API_KEY_LEAK.md.

```bash
# Generate new NATS token
NEW_NATS_TOKEN="nats-$(openssl rand -hex 16)"

# Update NATS server config
ssh broker-server "# Edit nats-server.conf with $NEW_NATS_TOKEN"

# Update config.json on every machine (including broker-server)
for machine in broker-server "${!FLEET[@]}"; do
  # ... (see API_KEY_LEAK.md for full procedure)
  :
done
```

### Step 6: Restart the broker and all services

```bash
# Restart the broker
ssh broker-server "systemctl --user start claude-peers-broker"

# Wait for broker to be ready
sleep 3
curl -s http://<broker-ip>:7899/health | jq .

# Start all other services
ssh broker-server "systemctl --user start claude-peers-dream claude-peers-supervisor claude-peers-wazuh-bridge claude-peers-security-watch claude-peers-response-daemon"
```

### Step 7: Issue service tokens (fleet-write, fleet-read, CLI)

The broker also needs to re-issue tokens for services that use non-peer-session roles:

```bash
# Dream daemon needs fleet-write capabilities
ssh broker-server "claude-peers issue-token ~/.config/claude-peers/identity.pub fleet-write"
# Save this as the dream service token

# Gridwatch needs fleet-read
# CLI tools need cli role
# Adjust per your service layout
```

---

## Investigation

After rotation is complete and the fleet is back up, investigate how the compromise happened.

### Check broker-server access logs

```bash
# SSH access history
ssh broker-server "last -50"
ssh broker-server "lastb -20 2>/dev/null"  # failed logins

# Auth logs
ssh broker-server "journalctl -u sshd --since '24 hours ago' --no-pager | grep -E 'Accepted|Failed|Invalid'"

# Check for unauthorized SSH keys
ssh broker-server "cat ~/.ssh/authorized_keys"
```

### Check for persistence mechanisms

```bash
# Crontabs
ssh broker-server "crontab -l"
ssh broker-server "ls /etc/cron.d/ /etc/cron.daily/"

# Systemd services
ssh broker-server "systemctl --user list-unit-files --state=enabled"
ssh broker-server "ls /etc/systemd/system/*.service ~/.config/systemd/user/*.service 2>/dev/null"

# Shell startup files
ssh broker-server "stat ~/.bashrc ~/.profile ~/.bash_profile 2>/dev/null"

# Check for processes that survive the shutdown
ssh broker-server "ps auxf | grep -v -E '(sshd|systemd|bash|ps|grep)'"
```

### Check if stolen tokens were used

```bash
# Broker logs showing token validation
ssh broker-server "journalctl --user -u claude-peers-broker --since '24 hours ago' --no-pager | grep -E 'register|auth|401|403'"

# NATS consumer activity
ssh broker-server "nats consumer ls FLEET 2>/dev/null"
ssh broker-server "nats consumer info FLEET security-monitor 2>/dev/null"
```

### Check for data exfiltration

```bash
# Was fleet memory read or modified?
curl -s http://<broker-ip>:7899/fleet-memory \
  -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt)"
# Review content for unexpected changes

# Were messages sent?
curl -s http://<broker-ip>:7899/events?limit=100 \
  -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt)" | jq '.[] | select(.type == "message_sent")'
```

---

## Recovery Verification

After rotation, verify the fleet is healthy:

```bash
# 1. Broker is up and accepting requests
curl -s http://<broker-ip>:7899/health | jq .

# 2. All machines can register
# Wait 2 minutes for automatic peer registration
sleep 120
curl -s http://<broker-ip>:7899/list-peers \
  -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt)" \
  -H "Content-Type: application/json" \
  -d '{"scope":"all","cwd":"/"}' | jq '.[].machine'
# Should see: workstation, broker-server, edge-node, workstation-2, laptop-1, iot-device

# 3. Machine health is clean
curl -s http://<broker-ip>:7899/machine-health \
  -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt)" | jq .

# 4. NATS is flowing
ssh broker-server "journalctl --user -u claude-peers-broker --since '2 min ago' --no-pager | grep nats"

# 5. Wazuh bridge is publishing
ssh broker-server "journalctl --user -u claude-peers-wazuh-bridge --since '2 min ago' --no-pager | tail -5"

# 6. Security watch is correlating
ssh broker-server "journalctl --user -u claude-peers-security-watch --since '2 min ago' --no-pager | tail -5"

# 7. Old tokens no longer work
# Try using a backed-up old token -- should get 401
curl -s http://<broker-ip>:7899/events \
  -H "Authorization: Bearer <old-token-from-backup>" | jq .
# Should return: {"error":"...","code":"INVALID_TOKEN"}
```

---

## Post-Incident Hardening

### Enable auditd on broker-server (CRITICAL)

This is the highest priority post-incident action. The root key read gap must be closed.

```bash
ssh broker-server "sudo apt install -y auditd"

# Watch all access (read, write, attribute change) to credential files
ssh broker-server "sudo auditctl -w ~/.config/claude-peers/identity.pem -p rwa -k root-key-access"
ssh broker-server "sudo auditctl -w ~/.config/claude-peers/token.jwt -p rwa -k root-token-access"
ssh broker-server "sudo auditctl -w ~/.config/claude-peers/config.json -p rwa -k claude-peers-config"

# Make the rules persistent
ssh broker-server "sudo bash -c 'cat >> /etc/audit/rules.d/claude-peers.rules << EOF
-w ~/.config/claude-peers/identity.pem -p rwa -k root-key-access
-w ~/.config/claude-peers/token.jwt -p rwa -k root-token-access
-w ~/.config/claude-peers/config.json -p rwa -k claude-peers-config
EOF'"

# Verify
ssh broker-server "sudo auditctl -l | grep claude-peers"

# Test: read the file and check audit log
ssh broker-server "cat ~/.config/claude-peers/identity.pem > /dev/null"
ssh broker-server "sudo ausearch -k root-key-access --start recent"
```

### Hardware-backed key storage (future)

The fundamental problem: the root key is a file on disk that any process with the `user` user's permissions can read.

**TPM 2.0 on broker-server:**
- Store the Ed25519 private key in the TPM
- Signing operations go through `go-tpm` or `tpm2-tools`
- The key never exists as a readable file
- Requires modifying `ucan_keys.go` to use TPM for signing
- broker-server likely has a TPM 2.0 chip -- verify with `ls /dev/tpm*`

**Alternative: Encrypted filesystem**
- Store `~/.config/claude-peers/` on an encrypted LUKS partition
- Requires manual unlock after reboot (or systemd-cryptenroll with TPM)
- Protects against offline attacks but not against a running process with user permissions

**Alternative: Separate signing service**
- Run a minimal key-signing microservice that holds the root key
- The broker delegates signing to this service via localhost RPC
- The service runs as a different user with restricted file access
- Even if the broker process is compromised, the key is in a different process space

### Restrict broker-server access

```bash
# SSH: Tailscale only
ssh broker-server "sudo iptables -A INPUT -p tcp --dport 22 ! -i tailscale0 -j DROP"

# Broker: Tailscale only
ssh broker-server "sudo iptables -A INPUT -p tcp --dport 7899 ! -i tailscale0 -j DROP"

# NATS: Tailscale only
ssh broker-server "sudo iptables -A INPUT -p tcp --dport 4222 ! -i tailscale0 -j DROP"

# Wazuh: localhost only
ssh broker-server "sudo iptables -A INPUT -p tcp --dport 55000 ! -i lo -j DROP"

# Make iptables rules persistent
ssh broker-server "sudo apt install -y iptables-persistent && sudo netfilter-persistent save"
```

### Implement root key access monitoring in the broker itself

Add a self-monitoring check to the broker that periodically verifies the root key file has not been accessed unexpectedly:

```bash
# Watch for inotify on identity.pem (access events)
# This would be a code change to broker.go -- adding an inotify watcher
# that logs and alerts on any access to the key file outside of broker startup
```

---

## Monitoring Gaps

| Gap | Risk | Current State | Fix Priority |
|-----|------|--------------|-------------|
| **No auditd on broker-server for credential files** | Silent key read goes undetected | auditd not configured | **P0** -- fix immediately |
| **FIM only detects write, not read** | Attacker copies key without modifying it | Wazuh FIM monitors checksums only | **P0** -- auditd fills this gap |
| **Root key is a plain file on disk** | Any process as user `user` can read it | File permissions 0600 | **P1** -- TPM or encrypted storage |
| **Broker and root key on same machine** | Compromising the broker = compromising the root key | Architectural decision | **P2** -- separate signing service |
| **No broker request source IP logging** | Cannot determine if stolen tokens were used from unexpected IPs | Broker logs do not include client IP | **P1** -- add to ucan_middleware.go |
| **No automatic token revocation API** | Cannot revoke a specific token without restarting broker | TokenValidator has no revocation method | **P1** -- add revocation endpoint |
| **All secrets co-located on broker-server** | One machine compromise = all secrets compromised | Architectural decision | **P2** -- distribute secrets |

---

## Quick Reference Card

```
ROOT KEY COMPROMISE DETECTED OR SUSPECTED
    |
    +-- STOP EVERYTHING
    |     systemctl --user stop claude-peers-broker
    |     systemctl --user stop claude-peers-{dream,supervisor,wazuh-bridge,security-watch,response-daemon}
    |
    +-- Confirm the compromise
    |     stat ~/.config/claude-peers/identity.pem
    |     ausearch -f identity.pem (if auditd running)
    |     last -20 (who logged in?)
    |     Check for unknown peers
    |
    +-- FULL PKI ROTATION
    |     1. claude-peers init broker (new root key)
    |     2. Distribute root.pub to all machines
    |     3. Generate new keypair on each machine
    |     4. Issue new token for each machine
    |     5. Rotate NATS token (same machine, likely compromised too)
    |     6. Restart broker and all services
    |     7. Verify all machines re-enroll
    |
    +-- INVESTIGATE
    |     How did attacker get shell access?
    |     What else did they access? (config.json, .env, env vars)
    |     Were stolen tokens used? Check broker logs.
    |     Any persistence mechanisms? (cron, systemd, authorized_keys)
    |
    +-- HARDEN
          Enable auditd on broker-server
          Restrict all ports to Tailscale
          Consider TPM for root key storage
          Add broker request IP logging
```
