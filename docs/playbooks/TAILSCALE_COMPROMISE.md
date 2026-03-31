# Playbook: Tailscale Device Compromise

Tailscale is the network boundary for the Sontara Lattice fleet. Every service -- broker, NATS, LiteLLM, Wazuh, NATS monitoring -- binds to Tailscale IPs with no additional network-level firewall. If an attacker compromises a Tailscale auth key, adds a rogue device to the tailnet, or takes over an existing fleet device, they are immediately "inside" with direct access to every port on every machine.

## Fleet Topology

| Machine | Tailscale IP | OS | Role | Critical Services |
|---------|-------------|-----|------|-------------------|
| workstation | <workstation-ip> | Arch | Daily driver, dev | claude-peers client, MCP server |
| broker-server | <broker-ip> | Ubuntu 24.04 | Broker, infrastructure | Trust Broker (:7899), NATS (:4222), NATS Monitor (:8222), LiteLLM (:4000), Wazuh Manager, Gridwatch |
| edge-node | Pi 5 IP | Debian | Kiosk | Gridwatch dashboard, claude-peers client |
| workstation-2 | <workstation-2-ip> | Arch | Secondary dev | claude-peers client |
| laptop-1 | <laptop-1-ip> | macOS | HFL work | claude-peers client |
| iot-device | <iot-device-ip> | Pi Zero 2W | Cyberdeck | sontara-lite agent, claude-peers client |
| laptop-2 | <laptop-2-ip> | macOS | LLM server | LLM inference (external owner) |

### What is Exposed to the Tailnet

Every machine on the tailnet can reach:
- **http://<broker-ip>:7899** -- Trust Broker (accepts UCAN tokens, returns fleet data)
- **nats://<broker-ip>:4222** -- NATS JetStream (shared token auth, full fleet event bus)
- **http://<broker-ip>:8222** -- NATS monitoring (no auth, full connection and stream details)
- **http://<broker-ip>:4000** -- LiteLLM proxy (API key auth, routes to cloud LLM providers)
- **SSH on all machines** -- Tailscale SSH or standard SSH
- **Any other service** listening on 0.0.0.0 on any fleet machine

There is NO per-service network segmentation within the tailnet. The Tailscale ACL is the only boundary.

## Attack Scenarios

### Scenario A: Stolen Tailscale Auth Key

Tailscale auth keys (reusable or single-use) allow adding new devices to the tailnet. If an attacker obtains one:

```
1. Attacker creates a new device with the auth key
2. Device joins the tailnet with full mesh connectivity
3. Attacker can immediately:
   - Reach the broker at <broker-ip>:7899
   - Connect to NATS at <broker-ip>:4222
   - Query NATS monitoring at <broker-ip>:8222
   - Probe all machines on all ports
   - If they have a NATS token: subscribe to all fleet events
   - If they have a UCAN token: register as a peer, send messages
```

### Scenario B: Compromised Fleet Device

If an attacker gains shell access to any fleet device (e.g., through a vulnerable service, stolen SSH key, physical access to edge-node/iot-device):

```
1. Attacker has shell on fleet machine
2. Machine already has:
   - UCAN token (~/.config/claude-peers/token.jwt)
   - Ed25519 keypair (~/.config/claude-peers/identity.pem)
   - NATS token (in config.json or environment)
   - root.pub (can validate tokens from other machines)
   - SSH keys for other fleet machines (if key-based auth is configured)
3. Attacker can:
   - Impersonate this machine on the broker
   - Publish/subscribe to all NATS events
   - Read all peer messages
   - Read/write fleet memory
   - Pivot to other machines via SSH
   - Access LiteLLM and exfiltrate through LLM prompts
```

### Scenario C: Rogue Tailscale Device (Insider Threat)

Someone with Tailscale admin access adds a device intentionally. This device appears legitimate in `tailscale status` but is controlled by an adversary.

## Detection

### Audit tailscale status on every machine

```bash
# Run from any fleet machine
tailscale status

# Expected output: exactly 7 machines
# workstation, broker-server, edge-node, workstation-2, laptop-1, iot-device, laptop-2
# Plus any phone devices (e.g., "user-iphone")
```

### Automated fleet-wide tailscale audit

```bash
# Run from workstation or broker-server
echo "=== Tailscale Device Audit ==="
echo "Expected devices: workstation, broker-server, edge-node, workstation-2, laptop-1, iot-device, laptop-2"
echo ""

tailscale status --json | python3 -c "
import json, sys
data = json.load(sys.stdin)
peers = data.get('Peer', {})
self_node = data.get('Self', {})

known_devices = {
    'workstation': '<workstation-ip>',
    'broker-server': '<broker-ip>',
    'edge-node': None,  # IP may vary
    'workstation-2': '<workstation-2-ip>',
    'laptop-1': '<laptop-1-ip>',
    'iot-device': '<iot-device-ip>',
    'laptop-2': '<laptop-2-ip>',
}

# Known non-fleet devices (phones, etc.)
known_other = {'user-iphone', 'user-pixel'}

all_devices = {}

# Self
hostname = self_node.get('HostName', 'unknown')
ips = self_node.get('TailscaleIPs', [])
ip = ips[0] if ips else 'no-ip'
all_devices[hostname] = ip
print(f'  SELF: {hostname:20s} {ip}')

# Peers
for key, peer in peers.items():
    hostname = peer.get('HostName', 'unknown')
    ips = peer.get('TailscaleIPs', [])
    ip = ips[0] if ips else 'no-ip'
    online = peer.get('Online', False)
    last_seen = peer.get('LastSeen', 'never')
    all_devices[hostname] = ip

    status = 'ONLINE' if online else 'offline'

    if hostname in known_devices:
        expected_ip = known_devices[hostname]
        if expected_ip and ip != expected_ip:
            print(f'  WARNING: {hostname:20s} {ip} (expected {expected_ip}) [{status}]')
        else:
            print(f'  OK:      {hostname:20s} {ip} [{status}]')
    elif hostname.lower().replace('-', '') in {k.lower().replace('-', '') for k in known_other}:
        print(f'  KNOWN:   {hostname:20s} {ip} (non-fleet device) [{status}]')
    else:
        print(f'  ROGUE:   {hostname:20s} {ip} [{status}] *** UNKNOWN DEVICE ***')

# Check for missing devices
for name in known_devices:
    if name not in all_devices and name != self_node.get('HostName'):
        found = False
        for dev_name in all_devices:
            if dev_name.lower().startswith(name.lower()):
                found = True
                break
        if not found:
            print(f'  MISSING: {name:20s} -- expected but not seen on tailnet')
"
```

### Check Tailscale admin panel

```bash
# Open Tailscale admin console
echo "https://login.tailscale.com/admin/machines"

# Or via CLI (requires admin access)
tailscale status --json | python3 -c "
import json, sys
data = json.load(sys.stdin)
peers = data.get('Peer', {})
print(f'Total peers: {len(peers)}')
for key, peer in peers.items():
    hostname = peer.get('HostName', 'unknown')
    os_info = peer.get('OS', 'unknown')
    online = peer.get('Online', False)
    created = peer.get('Created', 'unknown')
    last_seen = peer.get('LastSeen', 'unknown')
    print(f'  {hostname:20s} os={os_info:10s} online={online} created={created[:10]} last_seen={last_seen[:19]}')
"
```

### Monitor for new device joins

There is currently no automated alerting for new Tailscale devices joining the network.

**GAP: No Tailscale device join monitoring.** When a new device joins the tailnet, there is no alert. An attacker could add a rogue device and operate undetected until the next manual audit.

### Cross-reference NATS connections with Tailscale devices

```bash
# Get list of IPs connected to NATS
NATS_IPS=$(curl -s http://<broker-ip>:8222/connz | python3 -c "
import json, sys
data = json.load(sys.stdin)
ips = set()
for conn in data.get('connections', []):
    ip = conn.get('ip', '')
    if ip and ip != '127.0.0.1':
        ips.add(ip)
for ip in sorted(ips):
    print(ip)
")

# Get list of Tailscale IPs
TS_IPS=$(tailscale status --json | python3 -c "
import json, sys
data = json.load(sys.stdin)
ips = set()
self_ips = data.get('Self', {}).get('TailscaleIPs', [])
for ip in self_ips:
    if ':' not in ip:  # Skip IPv6
        ips.add(ip)
for peer in data.get('Peer', {}).values():
    for ip in peer.get('TailscaleIPs', []):
        if ':' not in ip:
            ips.add(ip)
for ip in sorted(ips):
    print(ip)
")

# Find NATS connections from IPs not on the tailnet
echo "=== NATS connections from non-Tailscale IPs ==="
for ip in $NATS_IPS; do
    if ! echo "$TS_IPS" | grep -q "^${ip}$"; then
        echo "  SUSPICIOUS: $ip connected to NATS but not a known Tailscale IP"
    fi
done
```

### Check broker connections

```bash
# The broker logs all registrations
ssh broker-server "journalctl --user -u sontara-lattice --since '24 hours ago' --no-pager | grep 'peer_joined\|register' | tail -20"
```

## Immediate Response: Rogue Device Detected

### Step 1: Identify the rogue device

```bash
# Get full details
tailscale status --json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for key, peer in data.get('Peer', {}).items():
    hostname = peer.get('HostName', '')
    # Replace ROGUE_HOSTNAME with the actual suspicious hostname
    if hostname == 'ROGUE_HOSTNAME':
        print(json.dumps(peer, indent=2))
"
```

### Step 2: Block the rogue device immediately

**Option A: Remove from Tailscale admin panel (preferred)**
```bash
# Via Tailscale admin UI:
# https://login.tailscale.com/admin/machines
# Find the rogue device -> "..." menu -> "Remove"

# Or if you have admin CLI access:
# tailscale admin remove <device-id>
```

**Option B: Block at the network level on critical machines (fast, while waiting for admin removal)**
```bash
ROGUE_IP="100.x.x.x"  # Replace with the rogue device's Tailscale IP

# Block on broker-server (protects broker, NATS, LiteLLM)
ssh broker-server "sudo iptables -A INPUT -s $ROGUE_IP -j DROP"

# Block on all other machines
for target in <workstation-ip> edge-node workstation-2-workstation "<user>@<laptop-1-ip><laptop-1-ip>" <iot-device-ip>; do
  ssh -o ConnectTimeout=5 $target "sudo iptables -A INPUT -s $ROGUE_IP -j DROP 2>/dev/null || true" &
done
wait
echo "Blocked $ROGUE_IP on all reachable machines"
```

### Step 3: Force re-authentication for all devices

If you suspect the Tailscale auth key itself was compromised:

```bash
# 1. Disable ALL reusable auth keys in Tailscale admin
# https://login.tailscale.com/admin/settings/keys
# Delete or disable every reusable key

# 2. Expire all device keys (forces re-authentication)
# In Tailscale admin: each device -> "..." -> "Expire key"
# This requires each device to re-authenticate within the key expiry window

# 3. Enable Tailscale key expiry if not already set
# Settings -> Keys -> Set key expiry (e.g., 90 days)
```

### Step 4: Rotate all shared secrets

If the rogue device was on the network long enough to exfiltrate credentials:

```bash
# 1. Rotate NATS token (the rogue device could have connected to NATS)
# See NATS_INJECTION playbook, "Rotate NATS token fleet-wide" section

# 2. Check if the rogue device obtained UCAN tokens
# The rogue device would need a token.jwt to authenticate with the broker
# If it didn't have one, broker access was limited to /health (unauthenticated)

# 3. Check NATS monitoring to see if the rogue device connected
curl -s http://<broker-ip>:8222/connz | python3 -c "
import json, sys
data = json.load(sys.stdin)
ROGUE_IP = 'REPLACE_ME'
for conn in data.get('connections', []):
    if conn.get('ip') == ROGUE_IP:
        print(f'ROGUE DEVICE WAS CONNECTED TO NATS')
        print(f'  Name: {conn.get(\"name\")}')
        print(f'  Messages in: {conn.get(\"in_msgs\")}')
        print(f'  Messages out: {conn.get(\"out_msgs\")}')
        print(f'  Subscriptions: {conn.get(\"num_subscriptions\")}')
"

# 4. If rogue device connected to NATS: full NATS token rotation required
# 5. If rogue device reached LiteLLM: rotate LLM API keys
```

## Immediate Response: Fleet Device Compromised

When an existing fleet device is compromised (not a rogue device, but an attacker gaining access to a legitimate machine).

### Step 1: Assess the scope

```bash
COMPROMISED="edge-node"  # Replace with actual machine name

# What credentials does this machine have?
echo "=== Credentials on $COMPROMISED ==="
ssh $COMPROMISED "
echo 'UCAN token:'; ls -la ~/.config/claude-peers/token.jwt 2>/dev/null
echo 'Identity key:'; ls -la ~/.config/claude-peers/identity.pem 2>/dev/null
echo 'Root pub:'; ls -la ~/.config/claude-peers/root.pub 2>/dev/null
echo 'Config (contains NATS token):'; cat ~/.config/claude-peers/config.json 2>/dev/null | python3 -c 'import json,sys; cfg=json.load(sys.stdin); print(\"nats_token present:\", bool(cfg.get(\"nats_token\")))' 2>/dev/null
echo 'SSH keys:'; ls -la ~/.ssh/ 2>/dev/null
echo 'Known hosts:'; cat ~/.ssh/known_hosts 2>/dev/null | wc -l
echo 'Authorized keys:'; cat ~/.ssh/authorized_keys 2>/dev/null | wc -l
"
```

### Step 2: Quarantine the machine via the broker

```bash
TOKEN=$(cat ~/.config/claude-peers/token.jwt)

# The attacker may also try to unquarantine -- this is a race condition.
# Consider also blocking the machine's NATS access.

# Publish quarantine event via NATS
nats pub fleet.security.quarantine "{
  \"type\": \"security.quarantine\",
  \"machine\": \"$COMPROMISED\",
  \"summary\": \"Manual quarantine: suspected device compromise\",
  \"data\": \"{\\\"machine\\\":\\\"$COMPROMISED\\\",\\\"reason\\\":\\\"device compromise confirmed\\\",\\\"timestamp\\\":\\\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\\\"}\",
  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
}"
```

### Step 3: Block the machine from NATS

```bash
# Get the machine's Tailscale IP from the fleet reference table above
COMPROMISED_IP="100.x.x.x"  # Replace

# Block on broker-server
ssh broker-server "sudo iptables -A INPUT -s $COMPROMISED_IP -p tcp --dport 4222 -j DROP"
ssh broker-server "sudo iptables -A INPUT -s $COMPROMISED_IP -p tcp --dport 7899 -j DROP"
ssh broker-server "sudo iptables -A INPUT -s $COMPROMISED_IP -p tcp --dport 4000 -j DROP"
echo "Blocked $COMPROMISED_IP from broker, NATS, and LiteLLM"
```

### Step 4: Capture forensics BEFORE remediation

```bash
# The response daemon may have already captured forensics automatically.
# Check:
ssh broker-server "ls -la ~/.config/claude-peers/forensics/ | grep $COMPROMISED"

# If not, capture manually:
ssh $COMPROMISED "ps auxf" > /tmp/$COMPROMISED-processes.txt 2>/dev/null
ssh $COMPROMISED "ss -tlnp" > /tmp/$COMPROMISED-listeners.txt 2>/dev/null
ssh $COMPROMISED "last -20" > /tmp/$COMPROMISED-logins.txt 2>/dev/null
ssh $COMPROMISED "who" > /tmp/$COMPROMISED-users.txt 2>/dev/null
ssh $COMPROMISED "cat /etc/hosts" > /tmp/$COMPROMISED-hosts.txt 2>/dev/null
ssh $COMPROMISED "cat ~/.config/claude-peers/config.json" > /tmp/$COMPROMISED-config.txt 2>/dev/null
ssh $COMPROMISED "journalctl --since '24 hours ago' --no-pager 2>/dev/null | tail -200" > /tmp/$COMPROMISED-journal.txt 2>/dev/null
echo "Forensics saved to /tmp/$COMPROMISED-*.txt"
```

### Step 5: Rotate credentials

```bash
# 1. Revoke the compromised machine's UCAN token
# There is no revocation list in the current UCAN implementation.
# The token will remain valid until expiry (365 days from issuance).
# GAP: No UCAN token revocation mechanism.

# Workaround: Issue a new root token and re-issue all machine tokens
# This invalidates the old token chain.

# On broker-server:
cd ~/.config/claude-peers
# Back up existing
cp token.jwt token.jwt.compromised.$(date +%Y%m%d%H%M%S)

# Generate new root token (requires the broker's private key)
claude-peers issue-token identity.pub root  # New root token

# Re-issue tokens for each clean machine
for machine in workstation edge-node workstation-2 laptop-1 iot-device; do
  echo "Issuing new token for $machine..."
  # Get their public key
  scp ${machine}:~/.config/claude-peers/identity.pub /tmp/${machine}-identity.pub 2>/dev/null || \
    ssh ${machine} "cat ~/.config/claude-peers/identity.pub" > /tmp/${machine}-identity.pub 2>/dev/null
  # Issue new token
  NEW_TOKEN=$(claude-peers issue-token /tmp/${machine}-identity.pub peer-session)
  echo "  Token: ${NEW_TOKEN:0:20}..."
  # Deploy
  ssh ${machine} "claude-peers save-token '$NEW_TOKEN'" 2>/dev/null
done

# 2. Rotate NATS token (see NATS_INJECTION playbook)

# 3. Rotate LLM API key if exposed
# Check if the compromised machine had llm_api_key in config.json
ssh broker-server "cat ~/.config/claude-peers/config.json | python3 -c 'import json,sys; cfg=json.load(sys.stdin); print(\"llm_api_key:\", \"present\" if cfg.get(\"llm_api_key\") else \"not set\")'"
```

### Step 6: Remediate the compromised machine

```bash
# Option A: Re-image the machine (strongest)
# For Pi devices: re-flash the SD card
# For Arch machines: reinstall

# Option B: Clean and re-credential (if full re-image is not feasible)
ssh $COMPROMISED "
# Remove all claude-peers credentials
rm -f ~/.config/claude-peers/token.jwt
rm -f ~/.config/claude-peers/identity.pem
rm -f ~/.config/claude-peers/identity.pub

# Kill all claude-peers processes
pkill -f claude-peers

# Check for persistence mechanisms
crontab -l 2>/dev/null
cat ~/.bashrc | tail -5
cat ~/.profile | tail -5
ls ~/.config/systemd/user/*.service 2>/dev/null
"

# After cleanup: re-initialize
ssh $COMPROMISED "claude-peers init client http://<broker-ip>:7899"
# Then issue a new token from the broker and deploy it
```

## Decision Tree

```
Tailscale compromise suspected
|
+-- Is there a ROGUE device on the tailnet?
|   +-- YES (unknown hostname in tailscale status)
|   |   +-- IMMEDIATE: Remove from Tailscale admin panel
|   |   +-- Block IP on broker-server (iptables)
|   |   +-- Check NATS connz: did it connect?
|   |   |   +-- YES: Full NATS token rotation, check for injected events
|   |   |   +-- NO: Damage limited to network reconnaissance
|   |   +-- Disable all reusable auth keys
|   |   +-- Investigate how the auth key was obtained
|   |
|   +-- NO: Is a LEGITIMATE device compromised?
|       +-- YES (attacker has shell on fleet machine)
|       |   +-- Block machine from broker/NATS/LiteLLM (iptables on broker-server)
|       |   +-- Capture forensics
|       |   +-- Quarantine via broker
|       |   +-- Rotate: UCAN tokens, NATS token, LLM keys
|       |   +-- Remediate or re-image the machine
|       |   +-- Re-credential and bring back online
|       |
|       +-- UNKNOWN: Suspicious activity but no confirmed compromise
|           +-- Run fleet-wide tailscale audit (script above)
|           +-- Check NATS connz for unexpected IPs
|           +-- Check broker logs for unexpected registrations
|           +-- Run forensic snapshot on suspect machine
```

## Emergency: Lock Down the Entire Tailnet

Use this when you believe multiple devices may be compromised or the Tailscale admin account itself is compromised.

```bash
echo "=== EMERGENCY TAILNET LOCKDOWN ==="

# 1. Block ALL external access to critical services on broker-server
ssh broker-server "
# Allow only localhost
sudo iptables -A INPUT -p tcp --dport 4222 -s 127.0.0.1 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 4222 -j DROP
sudo iptables -A INPUT -p tcp --dport 7899 -s 127.0.0.1 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 7899 -j DROP
sudo iptables -A INPUT -p tcp --dport 4000 -s 127.0.0.1 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 4000 -j DROP
sudo iptables -A INPUT -p tcp --dport 8222 -s 127.0.0.1 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 8222 -j DROP
echo 'All fleet services locked to localhost only'
"

# 2. Stop claude-peers on all machines
for target in <workstation-ip> edge-node workstation-2-workstation "<user>@<laptop-1-ip><laptop-1-ip>" <iot-device-ip>; do
  echo "Stopping claude-peers on $target..."
  ssh -o ConnectTimeout=5 $target "pkill -f claude-peers 2>/dev/null" &
done
wait

# 3. Disable Tailscale on compromised machines (nuclear option)
# ssh $COMPROMISED "sudo tailscale down"

echo ""
echo "Fleet is in lockdown mode."
echo "Only broker-server localhost services are running."
echo "To restore: remove iptables rules and restart claude-peers on each machine."
echo ""
echo "Restore commands:"
echo "  ssh broker-server 'sudo iptables -F INPUT'"
echo "  Then restart claude-peers on each machine"
```

## Monitoring Gaps Summary

| Gap | Severity | Status | Remediation |
|-----|----------|--------|-------------|
| No Tailscale device join alerting | **CRITICAL** | NOT IMPLEMENTED | TODO: Poll Tailscale API periodically, alert on new devices. Could be a daemon or cron job. |
| No UCAN token revocation | **CRITICAL** | NOT IMPLEMENTED | TODO: Add a token revocation list checked by the broker's TokenValidator. Currently tokens are valid for 365 days with no way to revoke. |
| No per-service network ACLs | **HIGH** | NOT IMPLEMENTED | TODO: Use Tailscale ACLs to restrict which devices can reach which ports (e.g., only certain machines should reach :4222) |
| NATS monitoring endpoint has no auth | **HIGH** | KNOWN | http://<broker-ip>:8222 exposes connection details, stream info, consumer state to anyone on the tailnet |
| LiteLLM proxy reachable from entire tailnet | **HIGH** | KNOWN | Any tailnet device can proxy LLM requests through <broker-ip>:4000 |
| No automated tailscale status auditing | **MEDIUM** | NOT IMPLEMENTED | TODO: Periodic `tailscale status` comparison against known device list |
| laptop-2 has no SSH access for incident response | **MEDIUM** | KNOWN | External machine -- cannot run forensics, cannot kill processes, cannot rotate credentials |
| No periodic reusable auth key audit | **MEDIUM** | NOT IMPLEMENTED | TODO: Alert if reusable auth keys exist and are not disabled |

## Hardening Recommendations

1. **Implement Tailscale ACLs.** Restrict which devices can reach which ports. Example policy:
   - Only workstation, workstation-2, laptop-1 can SSH to broker-server
   - Only fleet machines can reach :7899 (broker), :4222 (NATS)
   - :8222 (NATS monitor) only accessible from broker-server itself
   - :4000 (LiteLLM) only accessible from broker-server and machines running daemons

2. **Enable Tailscale device approval.** Require admin approval for new devices joining the tailnet. This prevents stolen auth keys from being immediately useful.

3. **Disable reusable auth keys.** Use single-use, pre-approved keys only. Delete any existing reusable keys.

4. **Set key expiry.** Force periodic re-authentication (e.g., every 90 days). This limits the window of a compromised device.

5. **Add NATS monitoring auth.** The NATS monitoring endpoint at :8222 should require authentication. Currently it exposes the full connection list to anyone on the tailnet.

6. **Implement a device inventory daemon.** A cron job or daemon that periodically runs `tailscale status --json`, compares against a known device list, and publishes an alert to `fleet.security.network` if unexpected devices are found.
