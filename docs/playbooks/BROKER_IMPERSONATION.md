# Playbook: Broker Impersonation / MITM

An attacker who can redirect broker traffic -- via ARP spoofing, DNS hijacking, or config tampering -- can run a fake broker that accepts all fleet traffic. Because claude-peers clients do NOT verify the broker's identity, they will happily authenticate to and communicate with any server at the `broker_url` address. The fake broker captures UCAN tokens, peer messages, fleet memory, and can inject arbitrary responses.

## The Core Vulnerability

The trust model is one-directional:

```
Client --> Broker: "Here is my UCAN token (signed with my Ed25519 key)"
Broker: validates token signature against root.pub
Broker --> Client: "OK, you're authenticated"

BUT:

Client --> ???: "Here is my UCAN token"
???: accepts token (root.pub is on every machine in the fleet)
Client trusts ???: because it answered at broker_url
```

**There is no mutual authentication.** The client proves its identity to the broker (via UCAN), but the broker does not prove its identity to the client. Any server at the expected IP:port is trusted.

### What the Fake Broker Gets

Every authenticated request from every client that connects:

| Endpoint | Data Captured |
|----------|--------------|
| `POST /register` | Machine name, PID, working directory, git root, project name, branch, summary |
| `POST /heartbeat` | Peer ID (confirms machine is still active) |
| `POST /set-summary` | What each Claude Code instance is working on |
| `POST /list-peers` | Client's scope request (which machines/directories it's querying) |
| `POST /send-message` | Full message text between peers (may contain code, instructions, secrets) |
| `POST /poll-messages` | Client requesting messages (fake broker can inject messages) |
| `GET /fleet-memory` | Fleet memory request (fake broker can serve poisoned memory) |
| `POST /fleet-memory` | Fleet memory updates from daemons |
| `GET /machine-health` | Security posture of every machine |
| `GET /events` | Recent fleet events |
| `Authorization: Bearer <JWT>` | **Every request includes the UCAN JWT token** |

### What the Fake Broker Can Inject

| Response | Impact |
|----------|--------|
| Fake peer list | Client sees phantom machines, misses real ones |
| Fake messages | Inject instructions into Claude Code instances ("run this command", "modify this file") |
| Fake fleet memory | Poison the knowledge base that daemons and peers read |
| Fake health data | Report all machines as "healthy" to suppress real alerts |
| `{"error": "machine quarantined"}` on every request | Lock any machine out of the fleet |
| Fake events | Rewrite fleet history |

## Attack Scenarios

### Scenario A: ARP Spoofing on Tailscale Interface

Tailscale typically uses WireGuard tunnels that make traditional ARP spoofing between Tailscale nodes impractical -- traffic goes through encrypted WireGuard tunnels, not local LAN ARP. However, if two fleet machines share a physical LAN segment AND use direct connections (Tailscale derp relay is bypassed), ARP spoofing at the LAN level could theoretically redirect Tailscale traffic before it enters the WireGuard tunnel.

**Realistically, this is LOW probability on a Tailscale mesh.** Tailscale's WireGuard tunnels make ARP spoofing between tailnet nodes non-viable in most configurations.

### Scenario B: DNS Hijacking to Redirect broker_url

If `broker_url` uses a hostname (not a raw IP), modifying DNS redirects all broker traffic. See the DNS_HIJACKING playbook for full details.

**Current mitigation: All configs use raw Tailscale IPs, not hostnames.** This makes DNS hijacking irrelevant for broker redirection -- unless an attacker also modifies `config.json` (detected by FIM rule 100113).

### Scenario C: Config Tamper + Fake Broker (Most Likely Attack)

The realistic attack path:

```
1. Attacker compromises a fleet machine (e.g., edge-node via physical access)
2. Attacker modifies ~/.config/claude-peers/config.json:
   broker_url: http://<iot-device-ip>:7899  (attacker's machine, or any tailnet IP they control)
3. Attacker runs a fake broker on that IP
4. The compromised machine's claude-peers connects to the fake broker
5. Attacker captures everything
```

This is detected by FIM rule 100113 (config.json modified). See CONFIG_TAMPER playbook.

### Scenario D: Rogue Tailscale Device Running Fake Broker

```
1. Attacker adds a rogue device to the tailnet (stolen auth key)
2. Rogue device gets IP 100.x.x.x
3. Attacker does NOT need to modify any config on fleet machines
4. Instead, attacker modifies /etc/hosts on a target machine:
     100.x.x.x  broker-server
5. If ANY config uses the hostname "broker-server", traffic redirects
6. Attacker runs fake broker on the rogue device at :7899
```

This combines the Tailscale compromise and DNS hijacking vectors.

### Scenario E: Compromised broker-server (Worst Case)

If the attacker compromises broker-server itself, they can:
- Replace the real broker binary with a modified version that logs all traffic
- Modify the broker code to exfiltrate tokens and messages
- Run a transparent proxy in front of the real broker

This is the hardest to detect because all traffic patterns look normal.

## Detection

### Check 1: Verify the broker is the real one

```bash
# From a trusted machine, verify the broker on broker-server
TOKEN=$(cat ~/.config/claude-peers/token.jwt)

# Health check -- does it respond correctly?
curl -s http://<broker-ip>:7899/health | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    print(f'Status: {data.get(\"status\")}')
    print(f'Machine: {data.get(\"machine\")}')
    print(f'Peers: {data.get(\"peers\")}')
    if data.get('machine') != 'broker-server':
        print('WARNING: broker machine name does not match expected \"broker-server\"')
except:
    print('ERROR: broker response is not valid JSON')
"

# Verify the process on broker-server
ssh broker-server "pgrep -fa 'claude-peers.*broker'"
ssh broker-server "ss -tlnp | grep 7899"

# Verify the binary hash
ssh broker-server "md5sum ~/.local/bin/claude-peers"
ssh broker-server "sha256sum ~/.local/bin/claude-peers"
# Compare against known-good hash from the last deployment
```

### Check 2: Verify each machine is talking to the real broker

```bash
# For each client machine: where is it actually connecting?
for target in <workstation-ip> edge-node workstation-2-workstation "<user>@<laptop-1-ip><laptop-1-ip>" <iot-device-ip>; do
  echo "=== $target ==="
  ssh -o ConnectTimeout=5 $target "
    # What's in config?
    python3 -c 'import json; cfg=json.load(open(\"/home/\$(whoami)/.config/claude-peers/config.json\")); print(\"broker_url:\", cfg.get(\"broker_url\", \"NOT SET\"))' 2>/dev/null

    # Can it reach the real broker?
    curl -s --connect-timeout 3 http://<broker-ip>:7899/health 2>/dev/null | python3 -c 'import json,sys; d=json.load(sys.stdin); print(\"broker_health:\", d.get(\"status\",\"error\"), \"machine:\", d.get(\"machine\",\"unknown\"))' 2>/dev/null || echo 'broker_health: UNREACHABLE'

    # Check active connections to broker port
    ss -tn 2>/dev/null | grep ':7899' || echo 'No active connections to :7899'
  " 2>/dev/null
  echo ""
done
```

### Check 3: Verify broker identity via TLS certificate (if using tailscale serve)

```bash
# If the broker is exposed via tailscale serve (HTTPS):
# Check the TLS certificate
ssh broker-server "tailscale serve status 2>/dev/null"

# From a client: verify the TLS certificate chain
curl -v https://broker-server:7899/health 2>&1 | grep -E 'subject|issuer|SSL'
```

### Check 4: Look for competing brokers on the tailnet

```bash
# Scan all known fleet IPs for anything listening on :7899
for ip in <workstation-ip> <broker-ip> <workstation-2-ip> <laptop-1-ip> <iot-device-ip> <laptop-2-ip>; do
  result=$(curl -s --connect-timeout 2 http://$ip:7899/health 2>/dev/null)
  if [ -n "$result" ]; then
    machine=$(echo "$result" | python3 -c "import json,sys; print(json.load(sys.stdin).get('machine','unknown'))" 2>/dev/null)
    echo "BROKER FOUND at $ip:7899 -- machine=$machine"
    if [ "$ip" != "<broker-ip>" ]; then
      echo "  *** ROGUE BROKER *** -- only <broker-ip> should run a broker"
    fi
  fi
done
```

### Check 5: ARP table inspection (local LAN only)

```bash
# On Linux machines sharing a LAN with broker-server
ssh <machine> "ip neigh show" | grep "<broker-ip>"
# The MAC address should be consistent and match broker-server's actual NIC

# On macOS
ssh <user>@<laptop-1-ip><laptop-1-ip> "arp -a" | grep "<broker-ip>"
```

Note: This is mostly irrelevant for Tailscale traffic (WireGuard tunnels), but relevant for machines on the same physical LAN.

## Immediate Triage

### Step 1: Verify the real broker is running

```bash
# Direct connection to broker-server by IP
ssh broker-server "
echo '--- Broker process ---'
pgrep -fa 'claude-peers.*broker'
echo ''
echo '--- Listening on 7899 ---'
ss -tlnp | grep 7899
echo ''
echo '--- Binary hash ---'
sha256sum ~/.local/bin/claude-peers
echo ''
echo '--- Health response ---'
curl -s http://127.0.0.1:7899/health
"
```

### Step 2: If a fake broker is suspected, stop all clients

```bash
# Kill claude-peers on ALL client machines to stop token exposure
for target in <workstation-ip> edge-node workstation-2-workstation "<user>@<laptop-1-ip><laptop-1-ip>" <iot-device-ip>; do
  echo "Stopping claude-peers on $target..."
  ssh -o ConnectTimeout=5 $target "pkill -f 'claude-peers' 2>/dev/null" &
done
wait
echo "All clients stopped"
```

### Step 3: Identify the fake broker

```bash
# Check what IP the clients were actually connecting to
# (from a stopped client machine, check recent connections)
ssh <machine> "ss -tn | grep 7899"
ssh <machine> "journalctl --user --since '1 hour ago' --no-pager 2>/dev/null | grep -i 'broker\|7899' | tail -10"
```

## Investigation

### Determine if UCAN tokens were captured

If clients connected to a fake broker, every request included the UCAN JWT in the `Authorization: Bearer` header. The fake broker now has every client's token.

```bash
# Check which machines were connecting during the suspected MITM window

# On broker-server: check broker logs for registered peers
ssh broker-server "journalctl --user -u sontara-lattice --since '24 hours ago' --no-pager | grep 'peer_joined\|register' | tail -20"

# Check if any machines stopped appearing (they switched to the fake broker)
TOKEN=$(cat ~/.config/claude-peers/token.jwt)
curl -s -H "Authorization: Bearer $TOKEN" -X POST http://<broker-ip>:7899/list-peers \
  -H 'Content-Type: application/json' \
  -d '{"scope":"all","cwd":"/"}' | python3 -c "
import json, sys
peers = json.load(sys.stdin)
print(f'Currently registered peers: {len(peers)}')
for p in peers:
    print(f'  {p[\"machine\"]:20s} id={p[\"id\"]} last_seen={p[\"last_seen\"]}')
"
```

### Check for injected messages

If the fake broker was active, it could have injected messages into clients:

```bash
# Check the real broker's message table for messages that DON'T match
ssh broker-server "sqlite3 ~/.claude-peers.db 'SELECT from_id, to_id, text, sent_at FROM messages ORDER BY sent_at DESC LIMIT 20'"

# If clients received messages that aren't in the real broker's DB,
# those messages were injected by the fake broker
```

### Check fleet memory integrity

```bash
# Get current fleet memory
TOKEN=$(cat ~/.config/claude-peers/token.jwt)
curl -s -H "Authorization: Bearer $TOKEN" http://<broker-ip>:7899/fleet-memory

# Compare with SQLite backup
ssh broker-server "sqlite3 ~/.claude-peers.db \"SELECT value FROM kv WHERE key='fleet_memory'\""
```

## Recovery

### Step 1: Rotate ALL UCAN tokens

Every token presented to the fake broker is compromised. The attacker can replay these tokens against the real broker.

```bash
# On broker-server:
cd ~/.config/claude-peers

# Generate a new root token (this invalidates all existing delegated tokens
# because the proof chain is broken when old root hash changes)
echo "Generating new root token..."
claude-peers issue-token identity.pub root
# Save the new root token
NEW_ROOT=$(cat token.jwt)

# Re-issue tokens for each machine
for machine_pub in /tmp/*-identity.pub; do
  machine=$(basename "$machine_pub" -identity.pub)
  echo "Issuing token for $machine..."
  NEW_TOKEN=$(claude-peers issue-token "$machine_pub" peer-session)
  echo "  Deploy: ssh $machine \"claude-peers save-token '$NEW_TOKEN'\""
done
```

Actually, the token validator uses a `knownTokens` map that is populated at runtime. Generating a new root token and registering it as the only known token effectively invalidates old delegated tokens because their proof hash no longer matches any registered parent. But this requires restarting the broker.

```bash
# Restart the broker with the new root token
ssh broker-server "
pkill -f 'claude-peers.*broker'
sleep 1
cd ~/projects/claude-peers && ./claude-peers broker &
"
```

### Step 2: Rotate NATS token

If the attacker captured the NATS token from config.json content in messages or from a compromised machine:

```bash
# See NATS_INJECTION playbook, "Rotate NATS token fleet-wide" section
```

### Step 3: Verify and restart all clients

```bash
# Verify each client's config points to the real broker
for target in <workstation-ip> edge-node workstation-2-workstation "<user>@<laptop-1-ip><laptop-1-ip>" <iot-device-ip>; do
  echo "=== $target ==="
  ssh -o ConnectTimeout=5 $target "
    python3 -c 'import json; cfg=json.load(open(\"/home/\$(whoami)/.config/claude-peers/config.json\")); url=cfg.get(\"broker_url\",\"\"); print(\"OK\" if url==\"http://<broker-ip>:7899\" else f\"WRONG: {url}\")'
  " 2>/dev/null
done

# After verification, restart clients
# (they will pick up new tokens from save-token above)
```

## Decision Tree

```
Broker impersonation suspected
|
+-- Is the real broker still running on broker-server?
|   +-- YES: check if clients are actually connecting to it
|   |   +-- Clients connecting to real broker: false alarm or intermittent MITM
|   |   +-- Clients NOT connecting: check their config.json and DNS resolution
|   |       +-- config.json tampered: follow CONFIG_TAMPER playbook
|   |       +-- DNS hijacked: follow DNS_HIJACKING playbook
|   |       +-- Neither: check for ARP spoofing or routing manipulation
|   |
|   +-- NO: broker-server broker is down
|       +-- Was it killed by an attacker?
|       +-- Is a rogue broker running on another IP?
|       +-- Restart the real broker, audit broker-server for compromise
|
+-- Is there a competing broker on the tailnet?
|   +-- YES: rogue broker found on another IP
|   |   +-- IMMEDIATE: stop all clients
|   |   +-- Block rogue IP on all machines
|   |   +-- Rotate all UCAN tokens
|   |   +-- Investigate how the rogue broker was deployed
|   |
|   +-- NO: no rogue broker, but clients may have been redirected temporarily
|       +-- Check broker logs for gaps in heartbeats
|       +-- Check client logs for connection errors
|       +-- If gaps found: determine exposure window, rotate tokens
|
+-- Was broker-server itself compromised?
    +-- Check binary hash against known-good
    +-- Check for modified broker code or transparent proxies
    +-- Check for additional listening processes on :7899
    +-- If compromised: full broker-server remediation required
```

## Monitoring Gaps Summary

| Gap | Severity | Status | Remediation |
|-----|----------|--------|-------------|
| No mutual TLS / broker identity verification | **CRITICAL** | NOT IMPLEMENTED | Clients trust any server at broker_url. TODO: Implement broker certificate pinning or mutual TLS. |
| No broker certificate pinning | **CRITICAL** | NOT IMPLEMENTED | TODO: Client should verify broker's public key on first connection and pin it. Alert if key changes. |
| No rogue broker detection | **HIGH** | NOT IMPLEMENTED | TODO: Periodic scan of all tailnet IPs on :7899 to detect competing brokers |
| Tailscale serve not enforced for broker | **HIGH** | PARTIAL | Using `tailscale serve` would add TLS with Tailscale-issued certificates, providing some broker identity verification. Not currently enforced. |
| No token replay protection | **HIGH** | NOT IMPLEMENTED | Captured UCAN tokens can be replayed against the real broker. TODO: Add nonce or timestamp binding to token presentation. |
| No client connection logging | **MEDIUM** | NOT IMPLEMENTED | The broker logs peer registrations but not individual HTTP request source IPs. TODO: Log client IP on every authenticated request. |
| ARP monitoring not implemented | **LOW** | NOT APPLICABLE | Tailscale WireGuard tunnels make ARP spoofing between tailnet nodes impractical. Low priority. |

## Hardening Recommendations (Priority Order)

1. **Use Tailscale HTTPS (tailscale serve) for the broker.** This adds TLS with Tailscale-issued certificates. Clients connecting via `https://broker-server:7899` get TLS certificate verification for free. The certificate is issued by Tailscale and tied to the machine's identity. This is the fastest path to broker identity verification.

   ```bash
   # On broker-server:
   tailscale serve --bg 7899
   # Then update all client configs to use https://broker-server:7899
   ```

2. **Implement broker public key pinning.** On first connection, the client retrieves the broker's Ed25519 public key (from a new `/broker-identity` endpoint) and pins it. On subsequent connections, the client verifies the broker's key matches the pin. If it doesn't match, refuse to connect and alert.

3. **Add client IP logging to the broker.** Every authenticated request should log the source IP. This creates an audit trail for detecting when a client was connecting from an unexpected IP (indicating the client itself was compromised and used from a different location).

4. **Add token replay protection.** Include a nonce or recent timestamp in each request that the broker validates. This prevents captured tokens from being replayed after the MITM window closes.

5. **Periodic rogue broker scan.** A cron job or daemon that scans all tailnet IPs on port 7899 and alerts if any non-broker-server IP responds. Could be integrated into fleet-scout.

6. **Broker binary integrity verification.** The broker should verify its own binary hash on startup and publish it in the `/health` response. Clients can verify this hash against a known-good value.
