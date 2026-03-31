# Playbook 7: Config Tamper (claude-peers Configuration)

The claude-peers config file at `~/.config/claude-peers/config.json` controls where every machine in the fleet connects. Tampering with this file can redirect all fleet traffic through a malicious proxy, capture LLM prompts, inject rogue events, or impersonate machines. This is a high-value target.

## Background: What an Attacker Can Do with Config Tampering

The config file contains these critical fields:

| Field | Normal Value | Attack If Tampered |
|-------|-------------|-------------------|
| `broker_url` | `http://<broker-ip>:7899` | **MITM all fleet traffic.** Attacker runs a fake broker, captures every peer message, credential exchange, and health report. Can inject fake responses. |
| `nats_url` | `nats://<broker-ip>:4222` | **Event injection.** Attacker runs a rogue NATS server, injects fake security events (false quarantines, fake all-clear), captures all daemon communications. |
| `nats_token` | Fleet auth token | **Unauthorized NATS access.** If exfiltrated, attacker can subscribe to all fleet events from anywhere on the Tailscale network. |
| `llm_base_url` | `http://127.0.0.1:4000/v1` | **Prompt capture + response injection.** Attacker proxies LLM requests, captures every daemon prompt (which contains fleet state, security data, conversation context), and can inject malicious responses that influence daemon decisions. |
| `llm_api_key` | API key for LLM endpoint | **Cost/abuse.** If exfiltrated, attacker uses your LLM credits. If LiteLLM routes to cloud APIs, attacker gets access to those too. |
| `machine_name` | Hostname (e.g., `workstation`) | **Impersonation.** Machine registers with the broker under a false name. Other peers believe messages come from a trusted machine. |
| `role` | `client` or `broker` | **Rogue broker.** Changing to `broker` on a non-broker machine creates a competing broker. If other machines are also tampered to point to it, the attacker controls the fleet. |

The most dangerous tampering is `broker_url` + `nats_url` together, because the attacker can then see everything AND inject anything, while the real broker loses visibility of the tampered machine.

## Detection Signals

| Signal | Source | Details |
|--------|--------|---------|
| Wazuh FIM | Realtime monitoring on `~/.config/claude-peers/` | All file changes in this directory trigger alerts. Credential files (identity.pem, token.jwt) trigger rule 100100 at level 12. Config.json changes trigger generic FIM at level 7. |
| NATS subject | `fleet.security.fim` | Alert published by wazuh-bridge. |
| Integrity checksum | Wazuh syscheck stores MD5/SHA1/SHA256 | FIM alert includes old and new checksums. |
| Machine goes silent | Broker stops receiving heartbeats | If `broker_url` was changed, the machine stops talking to the real broker. The broker will mark it stale after `stale_timeout` (300 seconds). |
| Gridwatch | Machine health score increases | FIM alert adds to health score. If credential files were also touched, score jumps significantly. |

**Detection gap**: If an attacker modifies config.json AND restarts the claude-peers process, the Wazuh alert fires but the machine immediately starts talking to the wrong broker. The 5-minute scan cycle on Arch machines (workstation, workstation-2) means there could be up to 5 minutes of unmonitored communication with a rogue broker before the alert fires. On broker-server and edge-node (realtime FIM), detection is near-instant.

## Immediate Triage (First 2 Minutes)

### Step 1: Stop the claude-peers process on the affected machine

Do this BEFORE investigating. If the config points to a malicious broker, every second the process runs is data leaking.

```bash
# Kill the MCP server process
ssh <machine> "pkill -f 'claude-peers mcp-server' 2>/dev/null"

# Kill any daemon processes
ssh <machine> "pkill -f 'claude-peers daemon' 2>/dev/null"

# Verify nothing is still running
ssh <machine> "pgrep -fa claude-peers"
```

### Step 2: Read the current config

```bash
ssh <machine> "cat ~/.config/claude-peers/config.json" | python3 -m json.tool
```

### Step 3: Diff against known-good values

These are the correct values for each machine:

**All client machines (workstation, edge-node, workstation-2, laptop-1, iot-device, laptop-2):**
```json
{
  "role": "client",
  "broker_url": "http://<broker-ip>:7899",
  "nats_url": "nats://<broker-ip>:4222",
  "llm_base_url": "http://127.0.0.1:4000/v1"
}
```

**Broker machine (broker-server):**
```json
{
  "role": "broker",
  "listen": "0.0.0.0:7899",
  "nats_url": "nats://127.0.0.1:4222",
  "llm_base_url": "http://127.0.0.1:4000/v1"
}
```

Check each field:

```bash
# Quick comparison (run from any trusted machine)
ssh <machine> "cat ~/.config/claude-peers/config.json" | python3 -c "
import json, sys
cfg = json.load(sys.stdin)
expected = {
    'broker_url': 'http://<broker-ip>:7899',
    'nats_url': 'nats://<broker-ip>:4222',
    'llm_base_url': 'http://127.0.0.1:4000/v1',
    'role': 'client'
}
for key, val in expected.items():
    actual = cfg.get(key, 'MISSING')
    if actual != val:
        print(f'TAMPERED: {key} = {actual} (expected {val})')
    else:
        print(f'OK: {key}')
for key in cfg:
    if key not in expected and key not in ('machine_name', 'stale_timeout', 'db_path', 'daemon_dir', 'agent_bin', 'llm_model', 'llm_api_key', 'nats_token', 'wazuh_alerts_path'):
        print(f'UNKNOWN FIELD: {key} = {cfg[key]}')
"
```

## Attack Scenarios and Response

### Scenario A: Malicious broker_url

**What happened**: `broker_url` changed from `http://<broker-ip>:7899` to an attacker-controlled endpoint.

**Impact**: The attacker captured:
- All peer registrations (machine name, instance ID, working directory, summary)
- All peer-to-peer messages (which may contain code, secrets, instructions)
- Health reports
- UCAN token presentations (the JWT itself, which contains capabilities)

**Response**:
1. Stop claude-peers (already done in triage).
2. Determine how long the machine was talking to the rogue broker:
   ```bash
   # Check when the config was modified
   ssh <machine> "stat ~/.config/claude-peers/config.json"

   # Check when the Wazuh alert fired (from forensics or bridge logs)
   ssh broker-server "journalctl --user -u sontara-wazuh-bridge --since '2 hours ago' | grep <machine>"
   ```
3. Rotate the machine's UCAN token. The JWT was exposed to the attacker:
   ```bash
   # On broker-server (broker)
   claude-peers issue-token /path/to/<machine>-identity.pub peer-session

   # On the affected machine
   ssh <machine> "claude-peers save-token <new-jwt>"
   ```
4. If the machine's private key (identity.pem) was NOT modified, the keypair is still safe. If identity.pem was ALSO changed, follow the full credential rotation in Playbook 2 (Credential File Tampering) in INCIDENT_RESPONSE.md.
5. Check if any messages sent to this machine during the tamper window contained sensitive data:
   ```bash
   # On broker-server, check broker logs for messages to this machine
   ssh broker-server "journalctl -u claude-peers-broker --since '<tamper-start-time>' | grep 'msg.*<machine>'"
   ```

### Scenario B: Malicious nats_url

**What happened**: `nats_url` changed to a rogue NATS server.

**Impact**: The attacker captured:
- All NATS events the machine published (daemon outputs, security events, health updates)
- All NATS events the machine subscribed to (fleet-wide security alerts, daemon triggers)
- The attacker could inject fake events: fake quarantine orders, fake all-clear signals, fake daemon triggers

**Response**:
1. Stop claude-peers (already done in triage).
2. Check if the NATS token was also changed or exfiltrated:
   ```bash
   ssh <machine> "cat ~/.config/claude-peers/config.json | python3 -c 'import json,sys; print(json.load(sys.stdin).get(\"nats_token\", \"NOT SET\"))'"
   ```
3. If the NATS token is the real fleet token, rotate it on ALL machines. The attacker now has a valid NATS credential:
   ```bash
   # Generate new NATS token on broker-server
   # Update nats-server.conf with new token
   # Restart NATS
   # Update config.json on every fleet machine with new nats_token
   ```
4. Check NATS server logs on broker-server for unauthorized connections:
   ```bash
   ssh broker-server "journalctl -u nats-server --since '2 hours ago' | grep -i 'connect\|auth\|error'"
   ```
5. Check if any injected events caused automated responses:
   ```bash
   # Check response daemon logs for actions taken during tamper window
   ssh broker-server "journalctl --user -u sontara-response --since '<tamper-start-time>' --until '<tamper-end-time>'"
   ```

### Scenario C: Malicious llm_base_url

**What happened**: `llm_base_url` changed to an attacker-controlled LLM proxy.

**Impact**: The attacker captured:
- Every LLM prompt from daemons on this machine (fleet-digest summaries, fleet-scout analysis, security watch correlation prompts)
- These prompts contain fleet state, machine names, IPs, security events, conversation context
- The attacker could inject malicious LLM responses that influence daemon decisions (e.g., make fleet-scout report "all clear" when there is an active threat)

**Response**:
1. Stop claude-peers (already done in triage).
2. If this is broker-server (where daemons run), this is critical. Check what daemons were active:
   ```bash
   ssh broker-server "journalctl --user -u sontara-daemons --since '<tamper-start-time>' --until '<tamper-end-time>'"
   ```
3. Review daemon outputs produced during the tamper window. They may contain attacker-influenced analysis:
   ```bash
   # Check NATS for daemon publications during tamper window
   # These outputs should be treated as potentially compromised
   ```
4. If `llm_api_key` was also in the config, the attacker has your LLM API credentials. Rotate immediately:
   ```bash
   # If using LiteLLM with cloud API keys, rotate those keys at the provider
   # Update LiteLLM config with new keys
   # Restart LiteLLM
   ```
5. Check LiteLLM logs for requests from unexpected sources:
   ```bash
   ssh broker-server "journalctl --user -u litellm --since '2 hours ago' | grep -v '127.0.0.1' | head -20"
   ```

### Scenario D: machine_name impersonation

**What happened**: `machine_name` changed to impersonate another fleet machine.

**Impact**: Messages sent "from" this machine appear to come from the impersonated machine. Other peers may trust instructions from a machine named `broker-server` that they would not trust from `workstation-2`.

**Response**:
1. Stop claude-peers (already done in triage).
2. Check the broker for duplicate registrations:
   ```bash
   curl -s -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt)" \
     http://<broker-ip>:7899/peers | python3 -m json.tool | grep -A5 '<impersonated-name>'
   ```
3. The UCAN token is bound to a specific identity. If the attacker only changed `machine_name` but not the keypair, the broker should still authenticate requests with the original identity. Check broker logs for auth anomalies.
4. Restore the correct machine_name and restart.

## Investigation: How Was the Config Modified?

After containment, determine the attack vector:

```bash
# Check who was logged in around the modification time
ssh <machine> "last | head -20"

# Check bash/zsh history for config editing commands
ssh <machine> "cat ~/.bash_history ~/.zsh_history 2>/dev/null | grep -i 'claude-peers\|config.json\|\.config/claude' | tail -20"

# Check if any running process could have written to it
ssh <machine> "lsof ~/.config/claude-peers/config.json 2>/dev/null"

# Check if auditd captured the modification (if auditd is running)
ssh <machine> "ausearch -f ~/.config/claude-peers/config.json 2>/dev/null"

# Check recent sudo usage
ssh <machine> "journalctl -u sudo --since '24 hours ago' 2>/dev/null | tail -20"

# Check if any Claude Code instance or daemon wrote to it
ssh <machine> "journalctl --user --since '24 hours ago' 2>/dev/null | grep -i 'config\|init\|save-token'"
```

## Recovery

### Step 1: Restore config from known-good source

```bash
# Write the correct config (adjust machine_name per machine)
ssh <machine> "cat > ~/.config/claude-peers/config.json << 'EOF'
{
  \"role\": \"client\",
  \"broker_url\": \"http://<broker-ip>:7899\",
  \"machine_name\": \"<correct-machine-name>\",
  \"nats_url\": \"nats://<broker-ip>:4222\",
  \"llm_base_url\": \"http://127.0.0.1:4000/v1\"
}
EOF"
```

Include `nats_token`, `llm_api_key`, and other fields as needed for the specific machine. Do NOT copy these values from this playbook -- retrieve them from a secure source (1Password, or from a known-good machine).

### Step 2: Verify config integrity

```bash
ssh <machine> "python3 -c \"import json; json.load(open('~/.config/claude-peers/config.json'))\" && echo 'valid JSON'"
ssh <machine> "cat ~/.config/claude-peers/config.json"
```

### Step 3: Verify file permissions

```bash
ssh <machine> "ls -la ~/.config/claude-peers/"
# Directory should be 700, config.json should be 600
ssh <machine> "chmod 700 ~/.config/claude-peers/ && chmod 600 ~/.config/claude-peers/config.json"
```

### Step 4: Restart claude-peers

```bash
# Restart the MCP server (if it was running as a service)
ssh <machine> "systemctl --user restart claude-peers-mcp 2>/dev/null"

# Verify connectivity to the real broker
ssh <machine> "claude-peers status"
```

### Step 5: Verify the machine is healthy

```bash
curl -s -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt)" \
  http://<broker-ip>:7899/machine-health | python3 -c "
import json, sys
health = json.load(sys.stdin)
for name, data in health.items():
    print(f'{name}: score={data.get(\"score\", \"?\")}, status={data.get(\"status\", \"?\")}')
"
```

### Step 6: Credential rotation (if warranted)

If any of the following were true during the tamper window, rotate credentials:

| Condition | Action |
|-----------|--------|
| `broker_url` was changed | Rotate the machine's UCAN token |
| `nats_token` was exposed | Rotate NATS auth token on ALL machines |
| `llm_api_key` was exposed | Rotate LLM API keys at provider |
| `identity.pem` was also modified | Full credential rotation (keypair + token) per INCIDENT_RESPONSE.md Scenario 2 |

## Hardening

1. **Set config.json immutable on stable machines**: Machines where the config rarely changes (edge-node, iot-device):
   ```bash
   sudo chattr +i ~/.config/claude-peers/config.json
   ```
   Remove immutable flag temporarily when deploying updates: `sudo chattr -i ...`

2. **Add a config integrity check to the heartbeat**: The claude-peers process could hash its config at startup and include the hash in heartbeats. The broker can compare against a known-good hash and flag mismatches.

3. **Add a Wazuh rule specifically for config.json** (currently only generic FIM at level 7):
   ```xml
   <!-- Add to wazuh/local_rules.xml -->
   <rule id="100135" level="10">
     <if_group>syscheck</if_group>
     <match type="pcre2">/\.config/claude-peers/config\.json$</match>
     <description>claude-peers config file modified (potential redirect attack): $(file)</description>
     <group>fim,config_tamper,</group>
   </rule>
   ```

4. **Pin expected config values in the broker**: The broker could store expected `broker_url` and `nats_url` values for each machine and flag heartbeats that do not match (i.e., the machine claims to be talking to the right broker but its config hash is wrong).

5. **Separate sensitive fields**: Move `nats_token` and `llm_api_key` out of config.json into separate files with 600 permissions, reducing the blast radius of a config.json read.
