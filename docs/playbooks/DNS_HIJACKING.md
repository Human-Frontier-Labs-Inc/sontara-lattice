# Playbook: DNS Hijacking / /etc/hosts Manipulation

An attacker who modifies DNS resolution on any fleet machine can redirect broker traffic, NATS connections, and LLM API calls to attacker-controlled servers without ever touching `~/.config/claude-peers/config.json`. This bypasses the config.json FIM rule (100113) entirely because the config file itself is unchanged -- only the name resolution layer is poisoned.

## Fleet Reference

| Machine | Tailscale IP | OS | SSH Target | DNS Config Files |
|---------|-------------|-----|------------|-----------------|
| workstation | <workstation-ip> | Arch | `<workstation-ip>` | `/etc/hosts`, `/etc/resolv.conf`, `/etc/nsswitch.conf` |
| broker-server | <broker-ip> | Ubuntu 24.04 | `<broker-ip>` | `/etc/hosts`, `/etc/resolv.conf`, `/etc/nsswitch.conf`, `/etc/systemd/resolved.conf` |
| edge-node | Pi 5 | Debian | `edge-node` | `/etc/hosts`, `/etc/resolv.conf`, `/etc/nsswitch.conf` |
| workstation-2 | <workstation-2-ip> | Arch | `workstation-2-workstation` | `/etc/hosts`, `/etc/resolv.conf`, `/etc/nsswitch.conf` |
| laptop-1 | <laptop-1-ip> | macOS | `<user>@<laptop-1-ip><laptop-1-ip>` | `/etc/hosts`, `/etc/resolv.conf`, `/private/etc/hosts` |
| iot-device | <iot-device-ip> | Pi Zero 2W | `<iot-device-ip>` | `/etc/hosts`, `/etc/resolv.conf`, `/etc/nsswitch.conf` |
| laptop-2 | <laptop-2-ip> | macOS | N/A (no SSH access) | `/etc/hosts`, `/private/etc/hosts` |

## Attack Scenario

### Precondition

The fleet uses Tailscale IPs directly in `config.json` (e.g., `broker_url: http://<broker-ip>:7899`). Because these are raw IPs, standard DNS hijacking does NOT affect fleet traffic by default. The attack vector is relevant when:

1. **Config uses hostnames instead of IPs** -- if any machine has `broker_url: http://broker-server:7899` or similar hostname-based config, `/etc/hosts` manipulation redirects all broker traffic.
2. **Tailscale MagicDNS** -- Tailscale resolves `broker-server` via MagicDNS. If an attacker modifies `/etc/hosts` to override this resolution, the hostname resolves to an attacker IP before MagicDNS is consulted.
3. **System-level DNS poisoning** -- modifying `/etc/resolv.conf` to point to a rogue DNS server that returns malicious answers for Tailscale domain queries (e.g., `*.ts.net`).
4. **nsswitch.conf manipulation** -- changing the resolution order so that mDNS or a custom NSS module takes priority over Tailscale's resolver.

### Attack Flow

```
1. Attacker gains shell access to fleet machine (e.g., edge-node)
2. Attacker adds to /etc/hosts:
     100.200.200.200  broker-server
   OR modifies /etc/resolv.conf:
     nameserver 100.200.200.200
3. If config.json uses hostname "broker-server":
   - All broker HTTP traffic goes to 100.200.200.200
   - All NATS connections (derived from broker_url) go to 100.200.200.200
   - Attacker captures: peer registrations, messages, UCAN tokens, NATS events
4. Attacker runs fake broker at 100.200.200.200:7899 that accepts all UCAN tokens
   (root.pub is on every machine -- attacker can validate tokens)
5. Attacker runs fake NATS at 100.200.200.200:4222 that captures all fleet events
```

### What the Attacker Gets

- Every peer message sent from the compromised machine
- Every UCAN JWT presented to the fake broker (containing capabilities and machine identity)
- Every NATS event the machine publishes (daemon outputs, security alerts, health reports)
- Ability to inject fake responses: fake peer lists, fake messages, fake NATS events
- If LLM traffic also routes through DNS: all daemon prompts containing fleet state, security data, code

## CRITICAL GAP: No FIM on DNS Configuration Files

**Current monitoring does NOT cover DNS files.** The Wazuh local_rules.xml has no rules matching:
- `/etc/hosts`
- `/etc/resolv.conf`
- `/etc/nsswitch.conf`
- `/etc/systemd/resolved.conf`
- `/private/etc/hosts` (macOS)

**The Wazuh syscheck configuration must be updated to monitor these files.** Without this, an attacker can modify DNS resolution with ZERO alerts.

### Required Wazuh syscheck additions (broker-server ossec.conf)

```xml
<!-- DNS configuration monitoring - ADD to each agent's syscheck config -->
<syscheck>
  <!-- Existing directories... -->

  <!-- DNS hijacking detection -->
  <directories check_all="yes" realtime="yes">/etc/hosts</directories>
  <directories check_all="yes" realtime="yes">/etc/resolv.conf</directories>
  <directories check_all="yes" realtime="yes">/etc/nsswitch.conf</directories>

  <!-- Ubuntu-specific -->
  <directories check_all="yes" realtime="yes">/etc/systemd/resolved.conf</directories>
  <directories check_all="yes" realtime="yes">/etc/systemd/resolved.conf.d</directories>

  <!-- macOS agents -->
  <directories check_all="yes" realtime="yes">/private/etc/hosts</directories>
</syscheck>
```

### Required Wazuh local_rules.xml addition

```xml
<!-- DNS configuration tampered (hijacking/MITM vector) -->
<rule id="100115" level="13">
  <if_group>syscheck</if_group>
  <match type="pcre2">/etc/(hosts|resolv\.conf|nsswitch\.conf)|/systemd/resolved\.conf|/private/etc/hosts</match>
  <description>DNS configuration modified (possible DNS hijacking): $(file)</description>
  <group>fim,dns_hijack,</group>
</rule>

<!-- QUARANTINE: DNS config + credential change on same host -->
<rule id="100202" level="15" frequency="2" timeframe="300">
  <if_matched_group>dns_hijack</if_matched_group>
  <same_source_ip />
  <description>QUARANTINE: DNS hijacking + credential change on same host</description>
  <group>quarantine,</group>
</rule>
```

### TODO: Add these rules to `wazuh/local_rules.xml` and deploy to all agents

## Detection (With Current Capabilities)

Even without FIM on DNS files, you can detect the EFFECTS of DNS hijacking:

| Signal | Source | Detection Method |
|--------|--------|-----------------|
| Machine goes silent | Broker heartbeat timeout (300s) | If DNS redirects broker traffic, the real broker stops seeing heartbeats |
| NATS connection from unexpected IP | NATS monitoring endpoint | `curl http://<broker-ip>:8222/connz` -- check client IPs |
| Broker connection from unexpected IP | Broker logs | The real broker never sees the compromised machine connect |
| Failed DNS resolution | Machine-level check | `dig broker-server` returns wrong IP |
| /etc/hosts mismatch | Manual audit | Compare against known-good |

## Immediate Triage (First 2 Minutes)

### Step 1: Check DNS resolution on the suspected machine

```bash
# For Linux machines
ssh <machine> "getent hosts broker-server"
ssh <machine> "cat /etc/hosts | grep -v '^#' | grep -v '^$'"
ssh <machine> "cat /etc/resolv.conf"
ssh <machine> "cat /etc/nsswitch.conf"

# For macOS machines
ssh <user>@<laptop-1-ip><laptop-1-ip> "cat /etc/hosts | grep -v '^#' | grep -v '^$'"
ssh <user>@<laptop-1-ip><laptop-1-ip> "scutil --dns"
```

### Step 2: Verify broker_url resolves to expected Tailscale IP

```bash
# From the suspected machine -- does the broker URL resolve correctly?
ssh <machine> "python3 -c \"
import socket, json
cfg = json.load(open('$HOME/.config/claude-peers/config.json'))
url = cfg.get('broker_url', '')
# Extract host from URL
host = url.split('://')[1].split(':')[0] if '://' in url else url.split(':')[0]
try:
    ip = socket.gethostbyname(host)
    expected = '<broker-ip>'
    if ip == expected:
        print(f'OK: {host} resolves to {ip}')
    else:
        print(f'HIJACKED: {host} resolves to {ip} (expected {expected})')
except Exception as e:
    print(f'DNS FAILURE: {host}: {e}')
\""
```

### Step 3: Check if the machine can reach the REAL broker

```bash
# Direct IP test -- bypasses DNS entirely
TOKEN=$(ssh <machine> "cat ~/.config/claude-peers/token.jwt")
curl -s -H "Authorization: Bearer $TOKEN" http://<broker-ip>:7899/health
```

If this succeeds but the machine's claude-peers process is not connecting, DNS is being redirected.

### Step 4: Stop claude-peers on the affected machine

```bash
ssh <machine> "pkill -f 'claude-peers mcp-server' 2>/dev/null"
ssh <machine> "pkill -f 'claude-peers daemon' 2>/dev/null"
ssh <machine> "pgrep -fa claude-peers"
```

## Investigation

### Check /etc/hosts modification time and content

```bash
# Linux
ssh <machine> "stat /etc/hosts && echo '---' && cat /etc/hosts"
ssh <machine> "stat /etc/resolv.conf && echo '---' && cat /etc/resolv.conf"
ssh <machine> "stat /etc/nsswitch.conf && echo '---' && cat /etc/nsswitch.conf"

# macOS
ssh <user>@<laptop-1-ip><laptop-1-ip> "stat /etc/hosts && echo '---' && cat /etc/hosts"
```

### Check for recent modifications to DNS files

```bash
# Linux: check journal for NetworkManager or systemd-resolved changes
ssh <machine> "journalctl -u systemd-resolved --since '24 hours ago' --no-pager 2>/dev/null | tail -20"
ssh <machine> "journalctl -u NetworkManager --since '24 hours ago' --no-pager 2>/dev/null | tail -20"

# Check file modification via filesystem audit
ssh <machine> "ls -la /etc/hosts /etc/resolv.conf /etc/nsswitch.conf 2>/dev/null"
ssh <machine> "find /etc -name 'hosts' -o -name 'resolv.conf' -o -name 'nsswitch.conf' | xargs ls -la 2>/dev/null"
```

### Check for rogue DNS servers in resolv.conf

```bash
ssh <machine> "grep 'nameserver' /etc/resolv.conf"
```

Expected nameservers:
- `100.100.100.100` (Tailscale MagicDNS)
- `127.0.0.53` (systemd-resolved, which should forward to Tailscale)
- Router/ISP DNS (varies)

Any nameserver that is NOT in this list is suspicious. Tailscale network IPs (100.x.x.x) other than 100.100.100.100 are especially suspicious.

### Cross-check with all fleet machines

```bash
# Run on each machine to compare DNS state
for target in <workstation-ip> <broker-ip> edge-node workstation-2-workstation "<user>@<laptop-1-ip><laptop-1-ip>" <iot-device-ip>; do
  echo "=== $target ==="
  ssh -o ConnectTimeout=5 $target "echo 'hosts:'; cat /etc/hosts | grep -v '^#' | grep -v '^$'; echo 'resolv:'; cat /etc/resolv.conf | grep -v '^#' | grep -v '^$'" 2>/dev/null
  echo ""
done
```

### Check NATS connections for the suspected machine

```bash
# On broker-server: check NATS monitoring endpoint for unexpected connections
curl -s http://<broker-ip>:8222/connz | python3 -c "
import json, sys
data = json.load(sys.stdin)
known_ips = {
    '<workstation-ip>': 'workstation',
    '<broker-ip>': 'broker-server',
    '127.0.0.1': 'broker-server-local',
    '<workstation-2-ip>': 'workstation-2',
    '<laptop-1-ip>': 'laptop-1',
    '<iot-device-ip>': 'iot-device',
    '<laptop-2-ip>': 'laptop-2',
}
for conn in data.get('connections', []):
    ip = conn.get('ip', 'unknown')
    name = conn.get('name', 'unnamed')
    known = known_ips.get(ip, 'UNKNOWN')
    if known == 'UNKNOWN':
        print(f'SUSPICIOUS: {ip} ({name}) -- not a known fleet IP')
    else:
        print(f'OK: {ip} ({known}) -- {name}')
"
```

### Check if attacker exfiltrated data through fake broker

If DNS was hijacked, the machine was sending data to the wrong server. Determine the time window:

```bash
# When was /etc/hosts last modified?
ssh <machine> "stat -c '%Y %y' /etc/hosts 2>/dev/null || stat -f '%m %Sm' /etc/hosts"

# When did the machine last successfully heartbeat to the REAL broker?
ssh broker-server "journalctl --user -u sontara-lattice --since '24 hours ago' --no-pager | grep '<machine-name>' | tail -5"
```

The gap between the last real heartbeat and the DNS modification time is the exposure window.

## Recovery

### Step 1: Restore DNS configuration

```bash
# Linux: restore /etc/hosts
ssh <machine> "cat /etc/hosts"
# Remove any malicious entries -- keep only:
#   127.0.0.1 localhost
#   ::1 localhost
# and any legitimate entries

# If /etc/hosts was modified:
ssh <machine> "sudo cp /etc/hosts /etc/hosts.compromised.$(date +%Y%m%d%H%M%S)"
ssh <machine> "sudo tee /etc/hosts << 'EOF'
127.0.0.1 localhost
::1 localhost
EOF"

# Restore resolv.conf (if using systemd-resolved)
ssh <machine> "sudo systemctl restart systemd-resolved 2>/dev/null"

# Verify resolution works
ssh <machine> "getent hosts broker-server 2>/dev/null || echo 'No hostname resolution (expected if using IPs)'"
```

### Step 2: Verify config.json still uses raw IPs (not hostnames)

```bash
ssh <machine> "cat ~/.config/claude-peers/config.json" | python3 -c "
import json, sys
cfg = json.load(sys.stdin)
for key in ['broker_url', 'nats_url', 'llm_base_url']:
    val = cfg.get(key, '')
    if val and not any(c.isdigit() for c in val.split('://')[1].split(':')[0].split('.')[0]):
        print(f'WARNING: {key} uses hostname, not IP: {val}')
        print(f'  Change to raw Tailscale IP to prevent DNS hijacking')
    else:
        print(f'OK: {key} = {val}')
"
```

### Step 3: Rotate credentials if MITM occurred

If the machine was sending traffic to a fake broker during the exposure window:

```bash
# Rotate UCAN token (on broker-server)
# 1. Get the machine's public key
scp <machine>:~/.config/claude-peers/identity.pub /tmp/<machine>-identity.pub

# 2. Issue new token
cd ~/projects/claude-peers
./claude-peers issue-token /tmp/<machine>-identity.pub peer-session

# 3. Save new token on the affected machine
ssh <machine> "claude-peers save-token '<new-jwt>'"

# 4. Rotate NATS token if it was exposed
# The nats_token in config.json was sent to the fake NATS server
# Generate new NATS token on broker-server and distribute to ALL machines
```

### Step 4: Restart claude-peers

```bash
ssh <machine> "claude-peers mcp-server &"
```

### Step 5: Verify connectivity

```bash
TOKEN=$(ssh <machine> "cat ~/.config/claude-peers/token.jwt")
curl -s -H "Authorization: Bearer $TOKEN" http://<broker-ip>:7899/health
```

## Decision Tree

```
DNS hijacking suspected
|
+-- Is /etc/hosts modified?
|   +-- YES: Contains entries pointing fleet hostnames to non-fleet IPs
|   |   +-- Stop claude-peers immediately
|   |   +-- Save compromised file for forensics
|   |   +-- Restore /etc/hosts
|   |   +-- Determine exposure window
|   |   +-- Rotate UCAN token
|   |   +-- If NATS token was in config.json: rotate NATS token fleet-wide
|   |   +-- Restart and verify
|   +-- NO: Check /etc/resolv.conf
|
+-- Is /etc/resolv.conf modified?
|   +-- YES: Contains rogue nameserver IPs
|   |   +-- Stop claude-peers immediately
|   |   +-- Restart systemd-resolved or restore resolv.conf
|   |   +-- Same credential rotation as above
|   +-- NO: Check nsswitch.conf
|
+-- Is /etc/nsswitch.conf modified?
|   +-- YES: Resolution order changed (e.g., mDNS before dns)
|   |   +-- Restore nsswitch.conf
|   |   +-- Check for rogue mDNS/Avahi services
|   +-- NO: DNS hijacking not confirmed at OS level
|       +-- Check for ARP spoofing (see BROKER_IMPERSONATION playbook)
|       +-- Check for upstream DNS poisoning
```

## Hardening Recommendations

1. **Use raw Tailscale IPs in config.json, never hostnames.** This makes `/etc/hosts` manipulation irrelevant for fleet traffic. All current configs already use IPs -- enforce this.

2. **Add FIM monitoring for DNS files.** See the Wazuh syscheck additions above. This is the single biggest gap for this attack vector.

3. **Pin resolv.conf with immutable attribute (Linux):**
   ```bash
   # After verifying resolv.conf is correct:
   sudo chattr +i /etc/resolv.conf
   ```
   Note: This breaks legitimate DNS changes (e.g., switching networks). Only use on static machines like broker-server and edge-node.

4. **Monitor Tailscale MagicDNS resolution.** Add a periodic health check that verifies `broker-server` resolves to `<broker-ip>` via Tailscale:
   ```bash
   # Cron job on each machine
   */5 * * * * expected="<broker-ip>"; actual=$(getent hosts broker-server 2>/dev/null | awk '{print $1}'); if [ -n "$actual" ] && [ "$actual" != "$expected" ]; then logger -p auth.crit "DNS HIJACK: broker-server resolves to $actual (expected $expected)"; fi
   ```

5. **TODO: Implement broker identity verification.** Clients currently trust whoever is at `broker_url`. Even with correct DNS, a network-level attacker could redirect traffic. See BROKER_IMPERSONATION playbook.

## Monitoring Gaps Summary

| Gap | Severity | Status | Remediation |
|-----|----------|--------|-------------|
| No FIM on /etc/hosts | **CRITICAL** | NOT MONITORED | Add to Wazuh syscheck + local_rules.xml |
| No FIM on /etc/resolv.conf | **CRITICAL** | NOT MONITORED | Add to Wazuh syscheck + local_rules.xml |
| No FIM on /etc/nsswitch.conf | **HIGH** | NOT MONITORED | Add to Wazuh syscheck + local_rules.xml |
| No FIM on /etc/systemd/resolved.conf | **HIGH** | NOT MONITORED | Add to Wazuh syscheck (Ubuntu only) |
| No FIM on /private/etc/hosts | **HIGH** | NOT MONITORED | Add to Wazuh syscheck (macOS agents) |
| No periodic DNS resolution health check | **MEDIUM** | NOT IMPLEMENTED | Add cron-based resolution verification |
| Config allows hostnames (not enforced) | **LOW** | No enforcement | Add config validation to reject non-IP broker_url |
