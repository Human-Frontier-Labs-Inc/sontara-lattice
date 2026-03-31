# Lateral Movement Incident Response Playbook

Sontara Lattice fleet -- last updated 2026-03-28.

**Tier:** 3 (Approval Required) -- forensic capture on all affected machines, email with ACTION REQUIRED, human must approve further actions before execution.

**Detection source:** security-watch correlation engine, not a single Wazuh rule. Multiple signals combine to indicate an attacker pivoting between machines.

**Fleet machines:**
| Machine | IP | OS | Value | SSH Target |
|---------|----|----|-------|------------|
| broker-server | <broker-ip> | Ubuntu 24.04 | CRITICAL (broker, root key, NATS, all daemons) | `<broker-ip>` |
| workstation | <workstation-ip> | Arch | HIGH (daily driver, source code, SSH keys) | `<workstation-ip>` |
| workstation-2 | <workstation-2-ip> | Arch | HIGH (secondary dev, source code) | `workstation-2-workstation` |
| laptop-1 | <laptop-1-ip> | macOS | HIGH (HFL client work) | `<user>@<laptop-1-ip><laptop-1-ip>` |
| edge-node | tailscale | Debian Pi 5 | MEDIUM (kiosk, limited data) | `edge-node` |
| iot-device | <iot-device-ip> | Debian Pi Zero 2W | LOW (cyberdeck, portable) | `<iot-device-ip>` |
| laptop-2 | <laptop-2-ip> | macOS | EXTERNAL (not owned, LLM server) | N/A -- no SSH access |

---

## 1. Understanding the Threat Model

### How Tailscale mesh changes lateral movement

Traditional lateral movement exploits network boundaries -- the attacker moves from DMZ to internal network. On a Tailscale mesh, there are NO network boundaries. Every machine can reach every other machine directly. This means:

- If the attacker compromises ANY machine, they can attempt SSH to ALL other machines (all on `100.x.x.x` Tailscale IPs)
- There are no firewalls between fleet machines by default
- Tailscale ACLs are the only network-level segmentation
- The attacker does NOT need to be on Tailscale themselves if they have a shell on a fleet machine -- that machine IS on Tailscale

### What the attacker gains per machine

| If compromised | Attacker gains |
|----------------|---------------|
| iot-device | SSH keys (may reach other machines), UCAN token (peer-session scope), NATS visibility (fleet-wide token) |
| edge-node | Same as iot-device + gridwatch data |
| workstation | Source code for claude-peers, SSH keys to all machines, UCAN token, NATS token |
| workstation-2 | Source code, SSH keys, UCAN token, NATS token |
| laptop-1 | HFL client data, SSH keys, UCAN token, NATS token |
| broker-server | ROOT KEY (can forge any UCAN token), NATS server (full control), all fleet data, broker database, Wazuh manager |
| laptop-2 | LLM inference access, potentially API keys for AI services |

### The NATS problem

The NATS token is currently shared across the fleet. A single token in `CLAUDE_PEERS_TOKEN` env var or config connects any machine to `nats://<broker-ip>:4222` with full `fleet.>` access. If the attacker has a shell on any fleet machine, they can:

1. Read the NATS token from config or environment
2. Subscribe to `fleet.>` and see ALL fleet events (peer joins, messages, security alerts, daemon output)
3. Publish to any `fleet.*` subject -- inject fake security events, fake peer registrations, fake daemon commands
4. Subscribe to `fleet.security.>` and see your incident response in real-time

This is the single biggest risk in a lateral movement scenario.

---

## 2. Detection Signals

### Primary: security-watch correlation

The `checkDistributedAttack` function in security-watch fires when the same Wazuh rule ID appears on 3+ machines within 5 minutes. This catches:
- Automated scanning (same exploit tried on multiple machines)
- Worm-like propagation (same binary tamper on multiple machines)
- Coordinated credential stuffing (auth failures across fleet)

The `checkCredentialTheft` function fires when FIM detects changes to `identity.pem` or `token.jwt` followed by a peer registration from the same machine within 5 minutes. This catches:
- Attacker stealing UCAN credentials and using them to register as a peer
- Token extraction followed by impersonation

### Detection patterns to watch for

**Pattern 1: Stepping stone (classic lateral movement)**
1. Auth failures on machine A (brute force or credential stuffing)
2. Auth success on machine A
3. Shortly after: auth attempts from machine A's IP on machine B
4. Auth success on machine B

security-watch detects this via `checkBruteForce` (5+ auth failures in 10 min) and `checkDistributedAttack` (same rule on 3+ machines in 5 min).

**Pattern 2: NATS-based pivot**
1. Attacker compromises machine A
2. Reads NATS token from machine A's config
3. Subscribes to `fleet.>` from machine A
4. Learns about other machines, their IPs, their capabilities
5. Uses SSH keys from machine A to reach machine B

Detection: This is INVISIBLE to Wazuh. NATS subscriptions are not logged. The only signal is unexpected NATS messages (publishing from a machine that shouldn't be publishing).

**Pattern 3: Token theft + impersonation**
1. Attacker compromises machine A
2. Extracts UCAN token from `~/.config/claude-peers/token.jwt`
3. Uses the token to make broker API calls from a different network location

Detection: Wazuh FIM rule 100100 (L12) detects access to credential files. The broker logs include the machine name from the token -- if the IP doesn't match the expected Tailscale IP for that machine, it's impersonation.

**Pattern 4: SSH key reuse**
1. Attacker compromises machine A
2. Finds SSH private keys in `~/.ssh/`
3. Uses those keys to SSH into machine B, C, D

Detection: Wazuh rule 100102 (L10) detects changes to SSH keys. But if the attacker only READS the keys (doesn't modify them), there is no FIM alert. The only detection is auth success logs on the target machines.

### What you receive

- **Email:** `[fleet-security] ACTION REQUIRED on <machine1>, <machine2>: lateral_movement`
- **Gridwatch:** Multiple machines turn red simultaneously at `http://<broker-ip>:8888`
- **Forensics:** Snapshots captured on ALL affected machines, saved to `~/.config/claude-peers/forensics/`

---

## 3. Immediate Triage (First 5 Minutes)

This is the most serious incident type. Drop everything.

### Step 1: Identify all affected machines

```bash
# Check machine health across the fleet
curl -s -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt)" \
  http://<broker-ip>:7899/machine-health | python3 -m json.tool

# Check which machines are quarantined
curl -s -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt)" \
  http://<broker-ip>:7899/machine-health | python3 -c "
import sys, json
data = json.load(sys.stdin)
for m, h in data.items():
    if h.get('status') in ('quarantined', 'degraded'):
        print(f'{m}: {h[\"status\"]} (score={h[\"score\"]}, last={h.get(\"last_event_desc\", \"?\")})')
"
```

### Step 2: Build a timeline

```bash
# Check forensic snapshots (captured automatically by response-daemon)
ls -lt ~/.config/claude-peers/forensics/ | head -20

# For each affected machine, check the forensic snapshot
for snap in ~/.config/claude-peers/forensics/*; do
  echo "=== $(basename $snap) ==="
  python3 -c "import json; d=json.load(open('$snap')); print('Current users:', d.get('current_users','?')[:200]); print('Recent logins:', d.get('recent_logins','?')[:500])"
  echo
done
```

### Step 3: Determine the attack path

Key questions:
1. Which machine was compromised FIRST? (Look at timestamps in forensic snapshots)
2. Did the attacker move from low-value to high-value? (iot-device -> workstation -> broker-server)
3. Did the attacker reach broker-server (the broker)? If yes, assume total fleet compromise.

```bash
# Check auth logs on ALL machines (parallel)
for target in <workstation-ip> <broker-ip> edge-node workstation-2-workstation "<user>@<laptop-1-ip><laptop-1-ip>" <iot-device-ip>; do
  echo "=== $target ==="
  ssh -o ConnectTimeout=5 "$target" "last -20 2>/dev/null" &
done
wait

# Check SSH logs on ALL machines
for target in <workstation-ip> <broker-ip> edge-node workstation-2-workstation <iot-device-ip>; do
  echo "=== $target ==="
  ssh -o ConnectTimeout=5 "$target" "journalctl -u sshd --since '6 hours ago' --no-pager 2>/dev/null | grep -iE 'accepted|failed|invalid' | tail -20" &
done
wait

# macOS SSH logs
ssh -o ConnectTimeout=5 "<user>@<laptop-1-ip><laptop-1-ip>" \
  "log show --predicate 'process == \"sshd\"' --last 6h --style compact 2>/dev/null | grep -iE 'accepted|failed' | tail -20"
```

### Step 4: Assess if broker-server is compromised

This is the critical question. If the broker is compromised:
- The attacker has the root Ed25519 key and can forge ANY UCAN token
- The attacker controls NATS and can inject/intercept any fleet event
- The attacker can see all security alerts and response actions in real-time
- The attacker can unquarantine machines and suppress alerts

```bash
# Check broker logs for suspicious activity
ssh broker-server "journalctl --user -u claude-peers-broker --since '6 hours ago' --no-pager | tail -50"

# Check for unauthorized root key access
ssh broker-server "stat ~/.config/claude-peers/root.pem"
ssh broker-server "stat ~/.config/claude-peers/root.pub"

# Check for unexpected processes
ssh broker-server "ps auxf | grep -v '\[.*\]' | head -40"

# Check for unexpected NATS connections
ssh broker-server "ss -tnp | grep 4222"
```

### Decision matrix

| Finding | Severity | Action |
|---------|----------|--------|
| Lateral movement between low-value machines only (iot-device, edge-node) | HIGH | Quarantine affected machines, rotate their credentials, investigate |
| Attacker reached a dev machine (workstation, workstation-2, laptop-1) | CRITICAL | Quarantine all affected, rotate all credentials, assume source code exposed |
| Attacker reached broker-server | TOTAL COMPROMISE | Full fleet shutdown, rebuild broker, rotate everything |
| laptop-2 involved | EXTERNAL BREACH | Contact the device owner immediately, isolate laptop-2 from Tailscale, rotate all shared credentials |

---

## 4. Containment

### Quarantine ALL affected machines

The response-daemon already quarantines machines with high severity events. Verify and extend:

```bash
# Verify quarantine status
curl -s -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt)" \
  http://<broker-ip>:7899/machine-health | python3 -m json.tool

# Manually quarantine any machine not yet quarantined
# (This is done by publishing a quarantine event to NATS)
# If the attacker has NATS access, they can see this -- but quarantine
# is enforced at the broker level, which they can't bypass without the root key
```

### Consider quarantining the entire fleet

If the attacker has the NATS token (which they do if they compromised any machine), they are watching your response in real-time. Consider a full fleet pause:

```bash
# Option 1: Block NATS externally (fastest, least destructive)
ssh broker-server "sudo iptables -A INPUT -p tcp --dport 4222 ! -s 127.0.0.1 -j DROP"
# This kills ALL NATS connections from all machines. Fleet coordination stops.
# The broker still works (it connects to NATS on localhost).
# Re-enable when ready: sudo iptables -D INPUT -p tcp --dport 4222 ! -s 127.0.0.1 -j DROP

# Option 2: Stop NATS entirely
ssh broker-server "docker stop nats-server"  # If running in Docker
# or
ssh broker-server "systemctl --user stop nats-server"  # If running as service

# Option 3: Nuclear -- disconnect all machines from Tailscale except broker-server and your current machine
# WARNING: You lose SSH access to disconnected machines
for machine in edge-node workstation-2-workstation <iot-device-ip>; do
  ssh "$machine" "sudo tailscale down" &
done
wait
```

### Isolate the initial compromise machine

```bash
# Block all outbound connections except Tailscale (keeps SSH working for investigation)
ssh <compromised-machine> "sudo iptables -A OUTPUT -o tailscale0 -j ACCEPT && sudo iptables -A OUTPUT -o lo -j ACCEPT && sudo iptables -P OUTPUT DROP"
```

---

## 5. Investigation

### SSH key audit across the fleet

This is the most common lateral movement vector. Check every machine.

```bash
# Collect all authorized_keys from all machines
for target in <workstation-ip> <broker-ip> edge-node workstation-2-workstation "<user>@<laptop-1-ip><laptop-1-ip>" <iot-device-ip>; do
  echo "===== $target ====="
  ssh -o ConnectTimeout=5 "$target" "cat ~/.ssh/authorized_keys 2>/dev/null" &
done
wait

# Check for SSH agent forwarding (allows key reuse without copying keys)
for target in <workstation-ip> <broker-ip> edge-node workstation-2-workstation "<user>@<laptop-1-ip><laptop-1-ip>" <iot-device-ip>; do
  echo "===== $target ====="
  ssh -o ConnectTimeout=5 "$target" "grep -i 'ForwardAgent\|AllowAgentForwarding' /etc/ssh/sshd_config ~/.ssh/config 2>/dev/null" &
done
wait

# Check which SSH private keys exist on each machine
for target in <workstation-ip> <broker-ip> edge-node workstation-2-workstation "<user>@<laptop-1-ip><laptop-1-ip>" <iot-device-ip>; do
  echo "===== $target ====="
  ssh -o ConnectTimeout=5 "$target" "ls -la ~/.ssh/id_* 2>/dev/null" &
done
wait

# Check if the same key fingerprint appears on multiple machines
for target in <workstation-ip> <broker-ip> edge-node workstation-2-workstation "<user>@<laptop-1-ip><laptop-1-ip>" <iot-device-ip>; do
  echo "===== $target ====="
  ssh -o ConnectTimeout=5 "$target" "for key in ~/.ssh/id_*; do ssh-keygen -lf \"\$key\" 2>/dev/null; done" &
done
wait
```

**Key finding to look for:** If the same private key fingerprint appears on multiple machines, those keys were copied. The attacker who compromises one machine gets access to all machines that share that key.

### NATS exposure assessment

```bash
# Check what NATS token is configured on each machine
for target in <workstation-ip> <broker-ip> edge-node workstation-2-workstation "<user>@<laptop-1-ip><laptop-1-ip>" <iot-device-ip>; do
  echo "===== $target ====="
  ssh -o ConnectTimeout=5 "$target" "grep -i nats ~/.config/claude-peers/config.json 2>/dev/null | head -3" &
done
wait

# Check NATS server for active subscriptions (on broker-server)
# This requires the NATS CLI tool
ssh broker-server "nats server report connections 2>/dev/null || echo 'nats CLI not installed'"

# Check NATS connections directly
ssh broker-server "ss -tnp | grep 4222 | grep ESTAB"
# Each line is an active NATS connection. Count should match number of active fleet machines + broker services.
# Extra connections = potential attacker.
```

**What the attacker can do with NATS access:**
- `fleet.security.>` -- See all security alerts, including your investigation
- `fleet.peer.>` -- See all peer joins/leaves, machine inventory
- `fleet.message.>` -- Read inter-peer messages
- `fleet.daemon.>` -- See daemon outputs and potentially inject commands
- Publish fake events to any subject (there is NO per-subject authorization in NATS currently)

### Tailscale network audit

```bash
# Check Tailscale status on each machine
for target in <workstation-ip> <broker-ip> edge-node workstation-2-workstation "<user>@<laptop-1-ip><laptop-1-ip>" <iot-device-ip>; do
  echo "===== $target ====="
  ssh -o ConnectTimeout=5 "$target" "tailscale status 2>/dev/null" &
done
wait

# Check Tailscale admin console for unusual devices
# Open: https://login.tailscale.com/admin/machines
# Look for:
#   - Devices you don't recognize
#   - Devices connecting from unusual locations
#   - Devices with unexpected OS types
#   - Recently added devices

# Check if any device is using an ephemeral key (attacker may have generated one)
# In the Tailscale admin panel, ephemeral devices show as "ephemeral" in the key column
```

### Persistence check on all affected machines

```bash
for target in <workstation-ip> <broker-ip> edge-node workstation-2-workstation "<user>@<laptop-1-ip><laptop-1-ip>" <iot-device-ip>; do
  echo "========== $target =========="

  echo "--- Crontabs ---"
  ssh -o ConnectTimeout=5 "$target" "crontab -l 2>/dev/null; sudo crontab -l 2>/dev/null" &

  echo "--- User systemd units ---"
  ssh -o ConnectTimeout=5 "$target" "ls -la ~/.config/systemd/user/ 2>/dev/null" &

  echo "--- System systemd units (custom) ---"
  ssh -o ConnectTimeout=5 "$target" "ls -la /etc/systemd/system/*.service 2>/dev/null | grep -v '^$'" &

  echo "--- Suspicious authorized_keys ---"
  ssh -o ConnectTimeout=5 "$target" "wc -l ~/.ssh/authorized_keys 2>/dev/null" &

  wait
done
```

### Check for data exfiltration

```bash
# On compromised machines, check for outbound connections to unknown IPs
ssh <machine> "ss -tnp | grep -v '100\.' | grep ESTAB"

# Check DNS queries (if systemd-resolved is running)
ssh <machine> "resolvectl query --cache 2>/dev/null | head -30"

# Check for large recent file transfers
ssh <machine> "journalctl --since '6 hours ago' | grep -iE 'scp|rsync|curl|wget' | head -20"
```

---

## 6. NATS Exposure -- The Critical Gap

This section exists because NATS is the biggest lateral movement risk in the current architecture.

### Current state

- One NATS token for the entire fleet
- Token stored in config file or environment variable on every machine
- Any machine can subscribe to `fleet.>` (all events)
- Any machine can publish to any `fleet.*` subject
- No per-machine NATS authentication
- No per-subject NATS authorization

### What the attacker can do RIGHT NOW

If they compromise any single machine:

```bash
# Read the NATS token
cat ~/.config/claude-peers/config.json | grep nats
# or
echo $CLAUDE_PEERS_TOKEN

# Connect to NATS from the compromised machine
# (They don't even need to install anything -- the claude-peers binary has NATS built in)
# Subscribe to everything
nats sub "fleet.>" --server nats://<broker-ip>:4222 --creds <token>

# Inject fake events
nats pub "fleet.security.quarantine" '{"machine":"workstation","severity":"quarantine","description":"fake alert"}' --server nats://<broker-ip>:4222 --creds <token>

# The attacker could:
# 1. Quarantine your machines by injecting fake security events
# 2. See your incident response in real-time
# 3. Inject fake "unquarantine" events
# 4. Impersonate any daemon
```

### Emergency NATS lockdown

If lateral movement is confirmed and the attacker likely has the NATS token:

```bash
# Step 1: Kill all external NATS connections immediately
ssh broker-server "sudo iptables -A INPUT -p tcp --dport 4222 ! -s 127.0.0.1 -j DROP"

# Step 2: Only the broker (running on broker-server) needs NATS on localhost
# All fleet features that depend on NATS (security-watch, response-daemon, gridwatch, daemons) run on broker-server
# Remote machines lose: real-time events, fleet coordination
# Remote machines keep: broker API (HTTP on port 7899), peer messaging, basic functionality

# Step 3: After investigation, bring NATS back with per-machine NKey auth (see Post-Incident section)
```

---

## 7. Eradication

### Rotate ALL credentials

This is mandatory for any confirmed lateral movement, regardless of how many machines were affected.

#### UCAN tokens (every machine)

```bash
# On broker-server (the broker), re-issue tokens for each machine:
for machine in workstation edge-node workstation-2 laptop-1 iot-device; do
  echo "=== Issuing token for $machine ==="
  # The machine's public key should still be valid (unless their identity.pem was also compromised)
  claude-peers issue-token ~/.config/claude-peers/known-keys/${machine}.pub peer-session
  echo "Save this token on $machine"
done

# If a machine's identity.pem was compromised (FIM alert on that file), regenerate the keypair:
ssh <machine> "claude-peers init client http://<broker-ip>:7899"
# Then issue a new token for the new public key
```

#### NATS token

```bash
# Generate a new NATS token
# The method depends on how NATS auth is configured (currently a simple token)
# Update on the broker:
ssh broker-server "vim ~/.config/claude-peers/config.json"  # Change nats_token
# Restart broker and all services that use NATS:
ssh broker-server "systemctl --user restart claude-peers-broker sontara-wazuh-bridge"

# Update on every fleet machine:
for target in <workstation-ip> edge-node workstation-2-workstation "<user>@<laptop-1-ip><laptop-1-ip>" <iot-device-ip>; do
  ssh "$target" "vim ~/.config/claude-peers/config.json"  # Update nats_token
done
```

#### SSH keys

```bash
# Generate NEW SSH keys on each machine (do not reuse the old ones)
for target in <workstation-ip> <broker-ip> edge-node workstation-2-workstation "<user>@<laptop-1-ip><laptop-1-ip>" <iot-device-ip>; do
  echo "=== $target ==="
  ssh "$target" "ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_new -N '' && mv ~/.ssh/id_ed25519_new ~/.ssh/id_ed25519 && mv ~/.ssh/id_ed25519_new.pub ~/.ssh/id_ed25519.pub"
done

# Rebuild authorized_keys on each machine with ONLY the new keys
# This is manual -- collect the new .pub from each machine and distribute
```

#### Tailscale auth keys

```bash
# In the Tailscale admin panel (https://login.tailscale.com/admin/machines):
# 1. Remove any unknown/suspicious devices
# 2. Rotate the auth key if you use a pre-auth key for fleet onboarding
# 3. Disable key expiry override if it's enabled (force regular re-auth)
```

### Rebuild compromised machines

See the Binary Tamper playbook (BINARY_TAMPER.md) section 8 for per-machine rebuild instructions.

---

## 8. Recovery -- Phased Restart

Do NOT bring the fleet back all at once. Phased restart lets you verify each machine before it can communicate with others.

### Phase 1: Broker

```bash
# Verify broker-server is clean (rootkit check, process audit, credential rotation done)
ssh broker-server "rkhunter --check --skip-keypress 2>&1 | tail -5"
ssh broker-server "ps auxf | wc -l"  # Compare against known baseline
ssh broker-server "ss -tlnp"  # Only expected listeners

# Start broker with new credentials
ssh broker-server "systemctl --user start claude-peers-broker"

# Verify broker is healthy
curl -s http://<broker-ip>:7899/health
curl -s -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt)" \
  http://<broker-ip>:7899/machine-health | python3 -m json.tool
```

### Phase 2: NATS (with restricted access)

```bash
# Re-enable NATS but only for localhost initially
ssh broker-server "sudo iptables -D INPUT -p tcp --dport 4222 ! -s 127.0.0.1 -j DROP"
# Actually, keep the firewall rule. Let broker services use localhost NATS.
# Only open NATS to specific machines as they come online:

# Allow workstation
ssh broker-server "sudo iptables -A INPUT -p tcp --dport 4222 -s <workstation-ip> -j ACCEPT"
```

### Phase 3: Wazuh

```bash
# Restart Wazuh manager
ssh broker-server "docker compose -f ~/docker/wazuh/docker-compose.yml up -d"

# Verify agents are connecting
ssh broker-server "docker exec wazuh-manager /var/ossec/bin/agent_control -l"

# Restart wazuh-bridge
ssh broker-server "systemctl --user start sontara-wazuh-bridge"
```

### Phase 4: Fleet machines (one at a time)

For each machine, in order of value (low to high: iot-device, edge-node, workstation-2, laptop-1, workstation):

```bash
MACHINE=iot-device
TARGET=<iot-device-ip>

# 1. Verify machine is clean
ssh "$TARGET" "rkhunter --check --skip-keypress 2>&1 | tail -5"  # Linux only
ssh "$TARGET" "ps aux | wc -l"

# 2. Verify new credentials are in place
ssh "$TARGET" "sha256sum ~/.config/claude-peers/token.jwt"
ssh "$TARGET" "sha256sum ~/.config/claude-peers/identity.pem"

# 3. Open NATS access for this machine
ssh broker-server "sudo iptables -A INPUT -p tcp --dport 4222 -s <machine-tailscale-ip> -j ACCEPT"

# 4. Start claude-peers on the machine
ssh "$TARGET" "claude-peers status"

# 5. Verify on the broker
curl -s -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt)" \
  http://<broker-ip>:7899/machine-health | python3 -c "import sys,json; print(json.load(sys.stdin).get('$MACHINE', 'not found'))"

# 6. Wait 5 minutes, check for anomalies, then proceed to next machine
```

### Phase 5: Remove temporary firewall rules

Once all machines are verified clean:

```bash
# Remove per-machine NATS rules and the blanket block
ssh broker-server "sudo iptables -F"  # Flush all rules
# Re-apply only permanent rules if any
```

---

## 9. Post-Incident Improvements

### Per-machine NATS credentials (NKey auth)

Replace the single shared NATS token with per-machine NKey authentication. Each machine gets its own NATS keypair.

**How NKey auth works:**
- Each machine has an Ed25519 NKey seed (like a private key)
- The NATS server has an authorization config listing each NKey's public key and what subjects it can access
- Compromising one machine only gives access to that machine's NATS permissions
- Revoking one machine's access does not require rotating credentials on all machines

**Per-machine NATS permissions:**

| Machine | Publish | Subscribe |
|---------|---------|-----------|
| workstation | `fleet.peer.workstation.>`, `fleet.message.>` | `fleet.>` |
| broker-server | `fleet.>` (broker has full access) | `fleet.>` |
| edge-node | `fleet.peer.edge-node.>` | `fleet.peer.>`, `fleet.security.>` (gridwatch needs these) |
| iot-device | `fleet.peer.iot-device.>`, `fleet.message.>` | `fleet.peer.>`, `fleet.message.iot-device.>` |
| All machines | N/A | Deny `fleet.security.quarantine` publish (only security-watch should publish this) |

### Tailscale ACL tightening

Current state: all machines can reach all machines on all ports. Restrict to:

```jsonc
// Tailscale ACL policy (https://login.tailscale.com/admin/acls)
{
  "acls": [
    // All machines can SSH to each other (port 22)
    {"action": "accept", "src": ["tag:fleet"], "dst": ["tag:fleet:22"]},

    // Only broker-bound traffic on port 7899 (broker API)
    {"action": "accept", "src": ["tag:fleet"], "dst": ["tag:broker:7899"]},

    // Only broker-bound NATS on port 4222
    {"action": "accept", "src": ["tag:fleet"], "dst": ["tag:broker:4222"]},

    // Gridwatch dashboard (port 8888) -- only from machines that need it
    {"action": "accept", "src": ["tag:fleet"], "dst": ["tag:broker:8888"]},

    // Deny everything else between fleet machines (no random port scanning)
    // This is implicit -- Tailscale denies by default if not in ACLs
  ]
}
```

### SSH key isolation

**Rule: No shared private keys across machines.** Each machine gets its own SSH keypair. `authorized_keys` on each machine lists only the specific public keys that should have access.

```bash
# Audit script: verify no key fingerprints are shared across machines
declare -A key_locations
for target in <workstation-ip> <broker-ip> edge-node workstation-2-workstation "<user>@<laptop-1-ip><laptop-1-ip>" <iot-device-ip>; do
  fingerprints=$(ssh "$target" "for key in ~/.ssh/id_*; do ssh-keygen -lf \"\$key\" 2>/dev/null; done")
  echo "=== $target ==="
  echo "$fingerprints"
done
# If any fingerprint appears on more than one machine, those keys need to be regenerated
```

### Restrict SSH to Tailscale only

```bash
# On each Linux machine, add to /etc/ssh/sshd_config or sshd_config.d/:
# ListenAddress 100.x.x.x   (Tailscale IP only)
# OR use iptables:
ssh <machine> "sudo iptables -A INPUT -p tcp --dport 22 ! -i tailscale0 -j DROP"
```

### Network segmentation within Tailscale

Tag machines by security tier:

| Tag | Machines | Can reach |
|-----|----------|-----------|
| `tag:broker` | broker-server | Everything |
| `tag:dev` | workstation, workstation-2 | broker, each other |
| `tag:endpoint` | edge-node, iot-device, laptop-1 | broker only |
| `tag:external` | laptop-2 | broker API only (port 7899), nothing else |

### Monitoring improvements

1. **NATS connection monitoring:** Alert when a new NATS client connects. Compare against expected client list.
2. **SSH session monitoring:** Alert on SSH sessions between machines that don't normally communicate.
3. **Tailscale device monitoring:** Alert on new Tailscale device registrations.
4. **Broker API anomaly detection:** Alert when a machine makes API calls it doesn't normally make (e.g., iot-device suddenly calling memory/write endpoints).

---

## 10. Testing This Playbook

```bash
# Simulate lateral movement (requires two targets)
claude-peers sim-attack lateral-movement --target=edge-node,iot-device --dry-run

# Live test
claude-peers sim-attack lateral-movement --target=edge-node,iot-device

# Verify detection chain
# 1. Check email for ACTION REQUIRED alert
# 2. Check gridwatch for multiple red machines
# 3. Check forensic snapshots captured for both machines
curl -s -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt)" \
  http://<broker-ip>:7899/machine-health | python3 -m json.tool

# Cleanup (sim-attack handles this automatically)
claude-peers unquarantine edge-node
claude-peers unquarantine iot-device
```

**NEVER test lateral movement scenarios involving broker-server** without explicit confirmation.
