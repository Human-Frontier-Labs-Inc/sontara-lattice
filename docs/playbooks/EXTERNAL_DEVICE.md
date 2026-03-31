# the external user's MacBook Pro (laptop-2) Compromise Incident Response Playbook

**System:** Sontara Lattice (claude-peers) fleet
**Last updated:** 2026-03-28
**Audience:** the operator (fleet operator)
**Severity tier:** Tier 2 (Investigate) -- external machine on the mesh with LLM access

---

## Table of Contents

1. [Attack Model](#attack-model)
2. [Detection](#detection)
3. [Immediate Triage (0-5 minutes)](#immediate-triage)
4. [Containment](#containment)
5. [Investigation](#investigation)
6. [Recovery](#recovery)
7. [Post-Incident Hardening](#post-incident-hardening)
8. [Monitoring Gaps](#monitoring-gaps)

---

## Attack Model

### What laptop-2 is

laptop-2 (<laptop-2-ip>) is a MacBook Pro owned by the other user, not the operator. It is on the Tailscale mesh and runs an LLM inference server used by the fleet's daemons. This machine is unique in the fleet because:

- **the operator does not control it.** No SSH access, no ability to audit, patch, or monitor.
- **It sees all daemon prompts.** Any daemon routed through this LLM server sends its full prompt and context to this machine.
- **It can inject responses.** A compromised LLM server can return manipulated responses that daemons trust and act on.
- **It is on the full Tailscale mesh.** It can reach every service: broker (:7899), NATS (:4222), NATS monitor (:8222), LiteLLM (:4000), SSH on all machines.

### Trust boundary problem

laptop-2 occupies an uncomfortable position: it is trusted with the fleet's most sensitive data (daemon prompts contain fleet state, security events, user context) but is outside the operator's administrative control. This is an inherent trust boundary violation.

### Attack scenarios

**Scenario A: the external user's machine is compromised by a third party**

```
1. Attacker gains access to laptop-2 (phishing, malware, physical access)
2. Attacker can read all LLM requests coming from the fleet
   - Daemon prompts contain: fleet state, security alerts, user behavior, API keys in context
3. Attacker can modify LLM responses
   - Tell fleet-sentinel "no threats detected" when there are active attacks
   - Tell fleet-scout "all services healthy" while services are down
   - Inject instructions into daemon responses that cause harmful actions
4. Attacker can pivot to other fleet machines via Tailscale
   - Probe all fleet services directly
   - If NATS token is discoverable on laptop-2: full event bus access
```

**Scenario B: the other user is the insider threat**

```
1. the other user (or someone with access to her machine) intentionally:
   - Reads all daemon prompts to learn about the operator's fleet activity
   - Modifies the LLM server to log or exfiltrate prompts
   - Swaps the LLM model for a fine-tuned version that produces subtly wrong outputs
   - Uses Tailscale access to probe fleet infrastructure
```

**Scenario C: LLM model swap or poisoning**

```
1. The model running on laptop-2 is replaced with:
   - A smaller model that produces lower-quality responses (subtle degradation)
   - A fine-tuned model with backdoor behaviors
   - A proxy that forwards to an external service (exfiltrating all prompts)
2. Fleet daemons continue operating with degraded or manipulated intelligence
```

---

## Detection

### LLM behavior anomalies

```bash
# Check LiteLLM routing -- which requests go to laptop-2?
ssh broker-server "
echo '=== LiteLLM routing config ==='
cat ~/.config/litellm/config.yaml 2>/dev/null | grep -A5 'external-device\|<laptop-2-ip>' || echo 'Check LiteLLM container config'
docker exec litellm cat /app/config.yaml 2>/dev/null | grep -A5 'external-device\|<laptop-2-ip>'
"

# Check LiteLLM logs for routing to laptop-2
ssh broker-server "docker logs litellm --since 24h 2>&1 | grep '<laptop-2-ip>' | tail -20"
```

### Latency anomalies

```bash
# Baseline LLM response time from laptop-2
# A sudden increase could indicate: model swap, proxy forwarding, or resource contention
ssh broker-server "
echo '=== LiteLLM latency to laptop-2 ==='
# Simple connectivity test
time curl -sf http://<laptop-2-ip>:11434/api/tags > /dev/null 2>&1 && echo 'Ollama endpoint: reachable' || echo 'Ollama endpoint: UNREACHABLE'

# Check if the expected model is loaded
curl -sf http://<laptop-2-ip>:11434/api/tags 2>/dev/null | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
    models = data.get(\"models\", [])
    for m in models:
        print(f\"  Model: {m.get(\"name\")} Size: {m.get(\"size\", 0) / 1e9:.1f}GB Modified: {m.get(\"modified_at\", \"unknown\")}\")
    if not models:
        print(\"  WARNING: No models loaded\")
except:
    print(\"  ERROR: Could not parse model list\")
'
"
```

### Network anomaly detection

```bash
# Check if laptop-2 is making unexpected connections to fleet services
# Via NATS monitoring
curl -sf http://<broker-ip>:8222/connz | python3 -c "
import json, sys
data = json.load(sys.stdin)
for conn in data.get('connections', []):
    if conn.get('ip') == '<laptop-2-ip>':
        print(f'laptop-2 CONNECTED TO NATS')
        print(f'  Name: {conn.get(\"name\")}')
        print(f'  Subscriptions: {conn.get(\"num_subscriptions\")}')
        print(f'  Messages in: {conn.get(\"in_msgs\")}')
        print(f'  Messages out: {conn.get(\"out_msgs\")}')
" 2>/dev/null || echo "NATS monitoring unreachable"

# Check broker for laptop-2 registration
ssh broker-server "journalctl --user -u sontara-lattice --since '7 days ago' --no-pager 2>/dev/null | grep -i 'external-device\|<laptop-2-ip>' | tail -10"
```

### Tailscale audit for laptop-2 activity

```bash
# Check if laptop-2 is online and its connection history
tailscale status --json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for key, peer in data.get('Peer', {}).items():
    if peer.get('HostName', '').lower().startswith('external-device'):
        print(f'Hostname: {peer.get(\"HostName\")}')
        print(f'IP: {peer.get(\"TailscaleIPs\", [\"unknown\"])}')
        print(f'Online: {peer.get(\"Online\")}')
        print(f'OS: {peer.get(\"OS\")}')
        print(f'Last seen: {peer.get(\"LastSeen\")}')
        print(f'Created: {peer.get(\"Created\")}')
"
```

---

## Immediate Triage (0-5 minutes)

### Step 1: Determine if laptop-2 is actively being used by the fleet

```bash
# Check current LiteLLM routing
ssh broker-server "docker logs litellm --since 1h 2>&1 | grep '<laptop-2-ip>' | wc -l"
# If count > 0, fleet is actively sending prompts to laptop-2 RIGHT NOW
```

### Step 2: Reroute LLM traffic away from laptop-2

```bash
# Option A: Reconfigure LiteLLM to stop routing to laptop-2
ssh broker-server "
# Edit LiteLLM config to remove or disable laptop-2 as a backend
docker exec litellm cat /app/config.yaml
"

# Option B: Block laptop-2 at the network level (faster)
ssh broker-server "sudo iptables -A INPUT -s <laptop-2-ip> -j DROP"
echo "Blocked all traffic from laptop-2 to broker-server"

# Option C: Block just outbound from LiteLLM to laptop-2
ssh broker-server "sudo iptables -A OUTPUT -d <laptop-2-ip> -j DROP"
echo "Blocked all traffic from broker-server to laptop-2"
```

### Step 3: Verify daemons are still functional

```bash
# After rerouting, ensure daemons fall back to cloud LLM providers
ssh broker-server "
journalctl --user -u sontara-lattice --since '5 minutes ago' --no-pager | grep -i 'error\|fail\|timeout' | tail -10
"
```

---

## Containment

### Full isolation of laptop-2 from the mesh

```bash
# Block on ALL fleet machines (not just broker-server)
EXTERNAL_IP="<laptop-2-ip>"

for target in "<workstation-ip>" "broker-server" "edge-node" "<workstation-2-ip>" "<user>@<laptop-1-ip><laptop-1-ip>" "<iot-device-ip>"; do
    ssh -o ConnectTimeout=5 $target "sudo iptables -A INPUT -s $EXTERNAL_IP -j DROP; sudo iptables -A OUTPUT -d $EXTERNAL_IP -j DROP" 2>/dev/null &
done
wait
echo "laptop-2 isolated from all fleet machines"

# Consider: remove from Tailscale entirely
# https://login.tailscale.com/admin/machines
# Find laptop-2 -> Remove
```

### Assess what laptop-2 has seen

```bash
# What data has been sent to laptop-2 via LLM requests?
ssh broker-server "
echo '=== LiteLLM request log analysis ==='
docker logs litellm 2>&1 | grep '<laptop-2-ip>' | head -5
echo '--- First request ---'
docker logs litellm 2>&1 | grep '<laptop-2-ip>' | tail -5
echo '--- Last request ---'
docker logs litellm 2>&1 | grep '<laptop-2-ip>' | wc -l
echo '--- Total requests ---'
"
```

---

## Investigation

### Determine if LLM responses have been manipulated

```bash
# Send a test prompt and compare responses from laptop-2 vs a known-good source
# This requires laptop-2 to still be reachable (do this before full isolation if safe)

# Test 1: Known-answer question
curl -sf http://<laptop-2-ip>:11434/api/generate -d '{
  "model": "llama3",
  "prompt": "What is 2+2? Reply with just the number.",
  "stream": false
}' 2>/dev/null | python3 -c "
import json, sys
data = json.load(sys.stdin)
print(f'Response: {data.get(\"response\", \"NO RESPONSE\")}')
print(f'Model: {data.get(\"model\", \"unknown\")}')
"

# Test 2: Check model fingerprint
curl -sf http://<laptop-2-ip>:11434/api/show -d '{"name": "llama3"}' 2>/dev/null | python3 -c "
import json, sys
data = json.load(sys.stdin)
print(f'Model: {data.get(\"modelfile\", \"unknown\")[:200]}')
print(f'Template: {data.get(\"template\", \"unknown\")[:200]}')
print(f'Parameters: {data.get(\"parameters\", \"unknown\")}')
"
```

### Check for prompt exfiltration

```bash
# Look for signs that prompts are being logged or forwarded
# This is limited since we don't have SSH access to laptop-2
# Best we can do: check network traffic patterns

# Monitor traffic volume to/from laptop-2
ssh broker-server "
echo 'GAP: Cannot audit laptop-2 processes or network activity without SSH access'
echo 'Can only observe traffic volume and patterns from our side'
# Check iptables counters if rules are in place
sudo iptables -L -v -n | grep '<laptop-2-ip>'
"
```

### Assess trust chain exposure

```bash
echo "=== laptop-2 Trust Chain Exposure ==="
echo "1. UCAN token: Unknown -- check if one was issued"
ssh broker-server "journalctl --user -u sontara-lattice --no-pager 2>/dev/null | grep -i 'external-device\|<laptop-2-ip>' | grep -i 'token\|register\|join' | tail -10"

echo "2. NATS token: Unknown -- check if it was shared"
echo "3. LLM prompts: ALL daemon prompts routed to this machine are exposed"
echo "4. Fleet state: Daemon prompts contain fleet health, security events, peer messages"
```

---

## Recovery

### Step 1: Migrate LLM inference off laptop-2

```bash
# Option A: Run LLM on broker-server (32GB RAM -- sufficient for smaller models)
ssh broker-server "
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh
# Pull the model
ollama pull llama3
# Verify
curl -sf http://localhost:11434/api/tags
"

# Option B: Use cloud LLM providers only (via LiteLLM)
# Reconfigure LiteLLM to route all traffic to cloud providers
# This costs more but eliminates the trust issue entirely
```

### Step 2: Update LiteLLM routing

```bash
ssh broker-server "
# Remove laptop-2 from LiteLLM config
# Replace with localhost Ollama or cloud-only routing
# Restart LiteLLM container
docker restart litellm
"
```

### Step 3: Decide on laptop-2's fleet membership

Three options:

1. **Remove from tailnet entirely.** Strongest isolation. laptop-2 has no further access.
2. **Keep on tailnet but restrict via ACLs.** Allow only specific traffic (e.g., only accept LLM requests from broker-server, block everything else).
3. **Keep as-is but add monitoring.** Accept the risk but add validation of LLM responses.

```bash
# Option 1: Remove from Tailscale admin
# https://login.tailscale.com/admin/machines -> laptop-2 -> Remove

# Option 2: Tailscale ACL restriction (in Tailscale admin -> ACLs)
# Allow broker-server -> laptop-2:11434 only
# Block laptop-2 -> everything else
```

---

## Post-Incident Hardening

### 1. Add LLM response validation

Daemons should validate LLM responses before acting on them:

- **Response sanity checking:** Does the response match the expected format? Is it within expected length bounds?
- **Cross-validation:** For high-stakes daemon actions (security responses, quarantine decisions), query a second LLM provider and compare.
- **Anomaly detection:** Track response latency, length, and format distributions. Alert on significant deviations.

### 2. Implement LLM request logging

```bash
# Log all requests and responses going through LiteLLM
# This creates an audit trail of what laptop-2 (or any LLM backend) has seen
ssh broker-server "
# Enable LiteLLM request logging
docker exec litellm cat /app/config.yaml | grep -i 'log'
"
```

### 3. Network segmentation for laptop-2

```bash
# Tailscale ACL to restrict laptop-2
# laptop-2 should ONLY be reachable on port 11434 from broker-server
# laptop-2 should NOT be able to reach any other fleet service

# In Tailscale admin ACL editor, add:
# {
#   "action": "accept",
#   "src": ["broker-server"],
#   "dst": ["laptop-2:11434"]
# }
# Block all other laptop-2 traffic by default
```

### 4. Model fingerprinting

```bash
# Record the expected model hash/fingerprint
# Compare periodically to detect model swaps
curl -sf http://<laptop-2-ip>:11434/api/show -d '{"name": "llama3"}' 2>/dev/null | \
    python3 -c "
import json, sys, hashlib
data = json.load(sys.stdin)
fingerprint = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
print(f'Model fingerprint: {fingerprint}')
print(f'Record this and compare on future checks')
" 2>/dev/null
```

---

## Monitoring Gaps

| Gap | Severity | Status | Remediation |
|-----|----------|--------|-------------|
| No SSH access to laptop-2 for auditing | **CRITICAL** | BY DESIGN | Cannot be fixed -- it's not the operator's machine. Mitigate by removing from mesh or restricting access. |
| No LLM response validation | **CRITICAL** | NOT IMPLEMENTED | Daemons trust LLM responses blindly. Add sanity checks and cross-validation. |
| No LLM request/response logging | **HIGH** | NOT CONFIRMED | Verify LiteLLM logging is enabled. All prompts sent to laptop-2 should be logged locally. |
| No model fingerprinting | **HIGH** | NOT IMPLEMENTED | Periodic model identity check to detect swaps. |
| No Tailscale ACLs restricting laptop-2 | **HIGH** | NOT IMPLEMENTED | laptop-2 can reach all fleet services. Should be restricted to inbound LLM requests only. |
| LLM prompts contain sensitive fleet state | **HIGH** | BY DESIGN | Daemon prompts include fleet health, security events, peer messages. Consider sanitizing prompts before sending to external LLM. |
| No alerting on laptop-2 connectivity changes | **MEDIUM** | NOT IMPLEMENTED | If laptop-2 goes offline or its IP changes, there is no alert. |
| Trust decision undocumented | **MEDIUM** | NOT IMPLEMENTED | No documented policy on whether external machines should be on the mesh. |
