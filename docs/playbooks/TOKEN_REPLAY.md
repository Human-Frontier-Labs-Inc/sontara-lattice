# Token Replay / Token Theft Incident Response Playbook

**System:** Sontara Lattice (claude-peers) fleet
**Last updated:** 2026-03-28
**Audience:** the operator (fleet operator)
**Severity tier:** Tier 2 (Contain) -- token-scoped damage, time-limited by TTL

---

## Table of Contents

1. [Attack Model](#attack-model)
2. [Token Theft Vectors](#token-theft-vectors)
3. [Detection](#detection)
4. [Immediate Triage (0-5 minutes)](#immediate-triage)
5. [Containment](#containment)
6. [Token Re-Issuance](#token-re-issuance)
7. [Investigation](#investigation)
8. [Post-Incident Hardening](#post-incident-hardening)
9. [Monitoring Gaps](#monitoring-gaps)

---

## Attack Model

### What a UCAN token is

A UCAN token is an Ed25519-signed JWT containing:
- `iss`: Signer's public key (base64url Ed25519)
- `aud`: Audience's public key (who the token was issued to)
- `sub`: Always `"claude-peers"` (prevents cross-system confusion)
- `cap`: Array of capabilities (`peer/register`, `msg/send`, `memory/read`, etc.)
- `prf`: SHA-256 hash of parent token (delegation proof chain)
- `exp`: Expiry timestamp
- `iat`: Issued-at timestamp
- `machine_name`: Machine name (used for quarantine checks)

### Token types and their TTLs

| Token Type | TTL | Capabilities | Stored At |
|-----------|-----|-------------|----------|
| Root token | 1 year | All (`peer/*`, `msg/*`, `events/read`, `memory/*`, `nats/subscribe`) | `broker-server:~/.config/claude-peers/token.jwt` |
| Peer-session | 24 hours | `peer/*`, `msg/*`, `events/read`, `memory/read` | `<machine>:~/.config/claude-peers/token.jwt` |
| Fleet-write | 24 hours | `peer/list`, `events/read`, `memory/read`, `memory/write` | Service configs on broker-server |
| Fleet-read | 24 hours | `peer/list`, `events/read`, `memory/read` | Gridwatch, monitoring tools |
| CLI | 24 hours | `peer/list`, `msg/send`, `events/read` | CLI tool configs |

### What an attacker can do with a stolen token

**From ANY IP address.** Tokens have no IP binding. The broker validates the cryptographic signature and capability set, not the source IP.

**Peer-session token (most common theft):**
- Register as the victim machine on the broker
- List all peers across the fleet (names, CWDs, summaries, machines)
- Send messages to any peer (impersonating the victim machine)
- Poll and read messages intended for the victim
- Read fleet events (security events, peer joins/leaves, summaries)
- Read fleet memory (operational data, coordination notes)
- Heartbeat to keep the registration alive

**Fleet-write token:**
- All of the above PLUS write to fleet memory
- Could inject malicious instructions into fleet memory that daemons read

**Root token (catastrophic):**
- Everything. See ROOT_KEY_COMPROMISE.md.

### What limits the damage

- **TTL:** Peer tokens expire in 24 hours. The attacker has a time-limited window.
- **Capabilities are scoped:** A peer-session token cannot write fleet memory or issue new tokens.
- **Quarantine blocks by machine_name:** If the machine_name is set in the token, quarantining that machine blocks the stolen token too.
- **Subject check:** Token must have `sub: "claude-peers"` -- prevents use against other JWT-based systems.

### What does NOT limit the damage

- **No IP binding:** Token works from any IP that can reach the broker (port 7899).
- **No request rate limiting:** Attacker can make unlimited requests.
- **No usage logging:** The broker does not log which token was used for which request.
- **No concurrent session detection:** Multiple registrations from the same token are allowed.
- **No token revocation API:** Cannot invalidate a specific token without restarting the broker.

---

## Token Theft Vectors

| Vector | How | Likelihood |
|--------|-----|------------|
| **Disk read** | Attacker has shell access, reads `~/.config/claude-peers/token.jwt` | High (follows SSH compromise) |
| **NATS traffic interception** | Attacker on the Tailscale network sniffs NATS traffic (unencrypted) | Low (requires Tailscale compromise) |
| **Process memory** | Attacker dumps the memory of a running claude-peers process | Low (requires root) |
| **Backup exposure** | Token file included in a backup or Syncthing sync | Medium (misconfiguration) |
| **Log exposure** | Token appears in an error log or debug output | Medium (HTTP client logging) |
| **config.json exposure** | config.json does not contain tokens, but it does contain the NATS token | Medium (separate concern, see API_KEY_LEAK.md) |
| **Physical access** | SD card from edge-node or iot-device mounted and token.jwt read | Low (targeted physical attack) |
| **Clipboard/terminal** | Token displayed on screen during `issue-token` and captured | Low (shoulder surfing) |

---

## Detection

### What We CAN Detect Today

| Signal | How | Automated? |
|--------|-----|------------|
| FIM on `token.jwt` modification | Wazuh rule 100100, level 12 | Yes |
| Duplicate peer registrations (same machine name) | Manual `list-peers` check | No |
| Unexpected peer registrations | Manual `list-peers` check | No |
| Machine quarantine (if machine_name is in token) | Broker auto-quarantines on security events | Yes |
| Broker logs show registration events | `journalctl --user -u claude-peers-broker` | Partial (logs exist, no alerting) |

### What We CANNOT Detect Today

| Gap | Risk | Priority |
|-----|------|----------|
| **No IP binding on tokens** | Stolen token usable from any IP | **P1** |
| **No request source IP logging in broker** | Cannot see where requests come from | **P0** |
| **No anomaly detection on token usage** | Cannot detect unusual access patterns | **P1** |
| **No concurrent session detection** | Multiple registrations from same token go unnoticed | **P1** |
| **No token usage audit trail** | No record of which token accessed which endpoint | **P1** |
| **NATS traffic is unencrypted on Tailscale** | Token could be sniffed from NATS connection (NATS token, not UCAN, but still) | **P2** |
| **No alerting on failed token validation** | Attacker probing with invalid tokens is not surfaced | **P2** |

---

## Immediate Triage (0-5 minutes)

### Step 1: Determine which token was stolen

```bash
# Decode the suspected stolen token (without validation)
echo '<stolen-token>' | cut -d. -f2 | base64 -d 2>/dev/null | jq .

# Key fields to check:
# - machine_name: which machine's token is this?
# - cap: what can the attacker do?
# - exp: when does it expire?
# - iss: who signed it? (root key = root token)
# - prf: empty = root token (VERY BAD), non-empty = delegated (scoped)
```

### Step 2: Check if the token is still valid

```bash
# Calculate remaining TTL
# exp field is Unix timestamp
EXP=$(echo '<stolen-token>' | cut -d. -f2 | base64 -d 2>/dev/null | jq -r '.exp')
NOW=$(date +%s)
REMAINING=$(( EXP - NOW ))
echo "Token expires in $REMAINING seconds ($(( REMAINING / 3600 )) hours)"

# If REMAINING <= 0: token is already expired. Lower urgency.
# If REMAINING > 0: token is live. Immediate action required.
```

### Step 3: Check for active exploitation

```bash
# List all registered peers -- look for duplicates or unknowns
curl -s http://<broker-ip>:7899/list-peers \
  -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt)" \
  -H "Content-Type: application/json" \
  -d '{"scope":"all","cwd":"/"}' | jq '.[] | {id, machine, cwd, last_seen, summary}'

# Look for:
# - Two peers with the same machine name but different IDs
# - Peers with unusual CWDs (not ~/projects/*)
# - Peers with generic or suspicious summaries
# - Peers with very recent last_seen from a machine that should be idle

# Check recent events
curl -s http://<broker-ip>:7899/events?limit=50 \
  -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt)" | jq '.[] | select(.type | test("peer|message"))'

# Check fleet memory for tampering (if fleet-write token stolen)
curl -s http://<broker-ip>:7899/fleet-memory \
  -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt)"
```

---

## Containment

### Option 1: Quarantine the machine (fast, non-disruptive)

If the stolen token has a `machine_name` claim, quarantining that machine blocks the token from any IP.

```bash
# Check if the token has machine_name
echo '<stolen-token>' | cut -d. -f2 | base64 -d 2>/dev/null | jq -r '.machine_name'

# If it has a machine_name, quarantine it:
# The broker's updateMachineHealth function sets status to "quarantined"
# The UCAN middleware returns 403 QUARANTINED for requests with that machine_name

# Manually set quarantine via a crafted security event on NATS:
ssh broker-server "nats pub fleet.security.quarantine '{\"type\":\"security.quarantine\",\"machine\":\"<machine-name>\",\"severity\":\"quarantine\",\"description\":\"manual quarantine: token theft\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}'"

# Verify quarantine
curl -s http://<broker-ip>:7899/machine-health \
  -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt)" | jq '.<machine-name>'
```

### Option 2: Restart the broker (disruptive, thorough)

Restarting the broker clears the `TokenValidator.knownTokens` map. This means ALL delegated tokens must re-validate by presenting themselves again. The stolen token still passes validation (it's cryptographically valid), but combining this with quarantine is effective.

```bash
ssh broker-server "systemctl --user restart claude-peers-broker"
```

**Side effect:** Every active peer drops and must re-register. This causes a brief disruption (peers auto-reconnect within their heartbeat interval).

### Option 3: Rotate the affected machine's credentials (definitive)

This is the only way to permanently invalidate the stolen token. See [Token Re-Issuance](#token-re-issuance).

### Option 4: Wait for expiry (if TTL is short enough)

If the token expires in less than 1-2 hours and no active exploitation is detected, you can simply monitor and wait. The token will become invalid when it expires (with 30 seconds of leeway per the `jwt.WithLeeway(30*time.Second)` in `ucan.go`).

---

## Token Re-Issuance

### For a single affected machine

```bash
MACHINE="edge-node"  # Replace with affected machine
HOST="edge-node"     # Replace with SSH target

# Step 1: Generate new keypair on the machine
ssh $HOST "cd ~/.config/claude-peers && \
  cp identity.pem identity.pem.rotated.\$(date +%s) && \
  cp token.jwt token.jwt.rotated.\$(date +%s) && \
  claude-peers init client http://<broker-ip>:7899"

# Step 2: Copy new public key to broker
scp ${HOST}:~/.config/claude-peers/identity.pub /tmp/${MACHINE}-new.pub
scp /tmp/${MACHINE}-new.pub broker-server:/tmp/${MACHINE}-new.pub

# Step 3: Issue new token from broker
NEW_TOKEN=$(ssh broker-server "claude-peers issue-token /tmp/${MACHINE}-new.pub peer-session" 2>&1 | tail -1)
echo "New token: $NEW_TOKEN"

# Step 4: Save token on the machine
ssh $HOST "claude-peers save-token '$NEW_TOKEN'"

# Step 5: Unquarantine if quarantined
curl -X POST http://<broker-ip>:7899/unquarantine \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt)" \
  -d "{\"machine\": \"$MACHINE\"}"

# Step 6: Verify reconnection
sleep 5
curl -s http://<broker-ip>:7899/list-peers \
  -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt)" \
  -H "Content-Type: application/json" \
  -d '{"scope":"all","cwd":"/"}' | jq ".[] | select(.machine == \"$MACHINE\")"
```

After rotation, the old token is still cryptographically valid until it expires, but:
- If the machine was quarantined, the old token's `machine_name` claim causes 403
- The old token's `aud` (audience) no longer matches the machine's new keypair (though the broker does not currently verify audience matching on incoming requests -- this is a gap)
- The old token will expire naturally within its TTL

---

## Investigation

### How was the token obtained?

```bash
# Check file access on the affected machine
ssh $HOST "stat ~/.config/claude-peers/token.jwt"

# If auditd is running:
ssh $HOST "ausearch -f token.jwt --start today 2>/dev/null"

# Check for SSH compromise (most likely entry point)
ssh $HOST "last -20"
ssh $HOST "who"
ssh $HOST "journalctl -u sshd --since '24 hours ago' --no-pager | grep -E 'Accepted|Failed' | tail -20"

# Check bash history for credential access
ssh $HOST "cat ~/.bash_history | grep -E '(token|jwt|cat |cp |scp |curl )' | tail -20"

# Check if token was in any logs
ssh $HOST "journalctl --user --since '24 hours ago' --no-pager | grep -i 'token\|jwt\|bearer' | head -20"

# Check if config directory permissions are correct
ssh $HOST "ls -la ~/.config/claude-peers/"
# Expected: directory 700, identity.pem 600, token.jwt 600
```

### Was the token actively used?

```bash
# Check broker logs for the affected machine's registrations
ssh broker-server "journalctl --user -u claude-peers-broker --since '24 hours ago' --no-pager | grep '$MACHINE'"

# Check events for suspicious activity
curl -s http://<broker-ip>:7899/events?limit=100 \
  -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt)" | \
  jq ".[] | select(.machine == \"$MACHINE\" or .peer_id != \"\")"

# Check NATS consumers
ssh broker-server "nats consumer ls FLEET 2>/dev/null"
# Known consumers: security-monitor, security-watch, response-daemon, wazuh-bridge, dream, gridwatch
# Unknown consumers may indicate attacker activity

# Check fleet memory for unauthorized modifications
curl -s http://<broker-ip>:7899/fleet-memory \
  -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt)"
# Review for content you did not write
```

---

## Post-Incident Hardening

### Reduce token TTL

Current peer-session TTL is 24 hours. Reducing it limits the window for replay attacks.

The TTL is set in the `issue-token` command which calls `MintToken()` with a duration parameter. To change the default:

```go
// In the issue-token CLI handler, change the TTL from 24h to a shorter duration
// File: main.go (where issue-token is handled)
// Look for: MintToken(..., 24*time.Hour, ...)
// Change to: MintToken(..., 4*time.Hour, ...)
```

**Trade-off:** Shorter TTL means more frequent manual re-issuance. Until automatic token refresh is implemented, keep it manageable (4-8 hours minimum).

### Add IP binding to tokens

Encode the client's Tailscale IP in the token and verify it in the middleware:

```go
// In ucan.go, add ClientIP to UCANClaims:
// ClientIP string `json:"client_ip,omitempty"`

// In ucan_middleware.go, after signature validation:
// if claims.ClientIP != "" && claims.ClientIP != extractTailscaleIP(r) {
//     writeAuthError(w, 403, "token bound to different IP", "IP_MISMATCH")
// }
```

This would make stolen tokens useless from any IP other than the machine they were issued to.

### Add broker request logging

Log the source IP and token hash for every authenticated request:

```go
// In ucan_middleware.go, after successful validation:
// log.Printf("[auth] %s %s from=%s token=%s machine=%s",
//     r.Method, r.URL.Path, r.RemoteAddr, TokenHash(tokenStr)[:8], claims.MachineName)
```

This creates an audit trail for detecting stolen token usage.

### Add concurrent session detection

Alert when the same machine_name registers from two different peer IDs simultaneously:

```go
// In broker.go register(), before inserting:
// Check if a peer with the same machine name already exists
// If so, and the registration is from a different source, emit a security event
```

### Add token revocation

Implement a revocation list in the `TokenValidator`:

```go
// Add to TokenValidator:
// revokedTokens map[string]bool  // token hash -> revoked

// In Validate(), after signature check:
// if v.revokedTokens[TokenHash(tokenStr)] { return nil, fmt.Errorf("token revoked") }

// Add a broker endpoint: POST /revoke-token
// Requires memory/write capability
```

### Enable NATS TLS

NATS traffic on the Tailscale network is currently unencrypted. While Tailscale provides WireGuard encryption, defense in depth suggests enabling NATS TLS:

```bash
# Generate NATS TLS certificates
# Update nats-server.conf with TLS config
# Update all fleet machines' NATS connection strings to use tls://
```

---

## Monitoring Gaps

| Gap | Impact | Fix |
|-----|--------|-----|
| **No IP binding on tokens** | Stolen token works from any IP | Add `client_ip` claim and middleware check |
| **No request source IP logging** | Cannot detect token use from unexpected IPs | Add logging to ucan_middleware.go |
| **No concurrent session detection** | Duplicate registrations from same machine go unnoticed | Add broker-side detection |
| **No token revocation API** | Cannot invalidate a specific token | Add revocation endpoint |
| **No failed auth alerting** | Attacker probing with stolen/invalid tokens not surfaced | Log and alert on 401/403 responses |
| **No token usage rate monitoring** | Attacker making rapid requests not detected | Add rate limiting per token hash |
| **No audience verification on requests** | Broker does not verify that the requester matches the token's `aud` claim | Add audience check in middleware |
| **NATS unencrypted (within Tailscale)** | Token could theoretically be sniffed from NATS auth handshake | Enable NATS TLS |
| **30-second clock leeway** | Attacker with clock skew can extend token validity by 30 seconds | Acceptable trade-off, but monitor NTP (see CLOCK_SKEW.md) |

---

## Quick Reference Card

```
TOKEN STOLEN / REPLAY DETECTED
    |
    +-- Identify the token
    |     Decode: echo '<token>' | cut -d. -f2 | base64 -d | jq .
    |     Check: machine_name, capabilities, expiry
    |
    +-- Is it expired?
    |     YES: Lower urgency. Rotate anyway. Investigate how it was stolen.
    |     NO:  Immediate action required.
    |
    +-- Is it a root token? (prf field empty)
    |     YES: See ROOT_KEY_COMPROMISE.md. Full PKI rotation.
    |     NO:  Continue below.
    |
    +-- Quarantine the machine (blocks token by machine_name)
    |     nats pub fleet.security.quarantine '{"machine":"<name>","severity":"quarantine",...}'
    |
    +-- Check for active exploitation
    |     list-peers: duplicate machine names?
    |     events: unexpected registrations?
    |     fleet-memory: unauthorized changes?
    |
    +-- Rotate the machine's credentials
    |     1. SSH to machine, generate new keypair
    |     2. Issue new token from broker
    |     3. Save token on machine
    |     4. Unquarantine
    |     5. Verify reconnection
    |
    +-- Investigate entry point
    |     How was the file read? SSH compromise? Physical access?
    |     Check: last, who, journalctl -u sshd, bash_history
    |
    +-- Harden
          Shorter TTL, IP binding, request logging, revocation API
```
