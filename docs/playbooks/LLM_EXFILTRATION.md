# Playbook: LLM Prompt Exfiltration

The Sontara Lattice fleet routes all daemon LLM requests through LiteLLM proxy at `http://<broker-ip>:4000/v1` (or `http://127.0.0.1:4000/v1` on broker-server itself). If an attacker modifies `llm_base_url` in a machine's `config.json` to point to an attacker-controlled proxy, every LLM prompt from that machine flows through the attacker's server. The attacker sees everything the daemons think about.

## What Flows Through LLM Prompts

Every daemon sends rich contextual prompts to the LLM. Here is what an attacker captures:

| Daemon | What It Sends | Sensitivity |
|--------|--------------|-------------|
| fleet-scout | Machine health reports, Wazuh alert summaries, security posture analysis, open ports, running services | **CRITICAL** -- full security posture |
| fleet-digest | Peer lists (all machines, IPs, working directories), recent events, fleet activity summaries | **CRITICAL** -- complete fleet topology |
| librarian | Documentation content, file paths, project structures, code snippets | **HIGH** -- intellectual property |
| llm-watchdog | LiteLLM health data, model routing, error rates, API key usage patterns | **HIGH** -- infrastructure details |
| security-watch (if LLM-augmented) | Security event correlations, quarantine decisions, incident analysis | **CRITICAL** -- security decision-making |
| Any response-daemon LLM calls | Incident details, forensic snapshots, recommended actions | **CRITICAL** -- active incident data |

### Concrete Example: What fleet-scout Sends

```
You are fleet-scout, the security reconnaissance daemon for the Sontara Lattice.

Current fleet state:
- Trust Broker: http://<broker-ip>:7899 -- healthy, 5 peers
- Active peers: workstation (<workstation-ip>), broker-server, edge-node, workstation-2 (<workstation-2-ip>), laptop-1 (<laptop-1-ip>)
- Machine health: workstation=healthy(0), broker-server=healthy(0), edge-node=degraded(6)

Recent Wazuh alerts:
- edge-node: SSH key modified (rule 100102, level 10)
- workstation-2: Shell persistence (.bashrc modified, rule 100110, level 10)

Auth for broker: TOKEN=$(cat ~/.config/claude-peers/token.jwt); curl -H "Authorization: Bearer $TOKEN" http://<broker-ip>:7899/machine-health
```

The attacker now knows: every machine name, every IP, the broker URL, the authentication pattern, the UCAN token command, which machines have security issues, and the exact Wazuh rules in use.

## Attack Vector

### How It Happens

1. Attacker gains write access to `~/.config/claude-peers/config.json` on any machine running daemons
2. Attacker changes `llm_base_url` from `http://127.0.0.1:4000/v1` to `http://attacker-ip:4000/v1`
3. Attacker runs an OpenAI-compatible proxy at `attacker-ip:4000` that:
   - Logs all incoming prompts
   - Forwards requests to a real LLM (so responses still work and daemons don't error)
   - Optionally modifies responses to influence daemon decisions
4. The next daemon cycle sends prompts to the attacker's proxy

### Detection Timeline

| Event | Time | Detection |
|-------|------|-----------|
| Config modified | T+0 | Wazuh FIM fires rule 100113 (level 11 = critical) |
| FIM alert reaches NATS | T+0 to T+5min | Depends on FIM scan frequency. Realtime on broker-server/edge-node. Up to 5 min on Arch machines. |
| Next daemon cycle runs | T+0 to T+30min | Daemons run on intervals (typically 5-30 min). Prompts now go to attacker. |
| Attacker has first prompt | T+daemon_interval | Damage is done. |

**The critical gap: damage occurs before detection.** Even with realtime FIM, the config change is detected AFTER it happens. If a daemon fires its next cycle before the alert is investigated, prompts are already exfiltrated.

## Detection

### Primary: Wazuh FIM Rule 100113

```
Rule ID: 100113
Level: 11 (critical)
Match: /\.config/claude-peers/config\.json
Description: claude-peers config.json modified (possible MITM)
Groups: fim, config_tamper
```

This fires when config.json is modified. The alert propagates through:
1. Wazuh agent detects file change
2. Wazuh manager processes alert
3. wazuh-bridge publishes to `fleet.security.fim` on NATS
4. Broker updates machine health score (+10 for critical)
5. Security-watch correlates with other events
6. Email alert sent to your-email@example.com

### Secondary: LiteLLM Proxy Logs

```bash
# On broker-server: check LiteLLM proxy logs for unexpected client IPs
ssh broker-server "journalctl --user -u litellm --since '2 hours ago' --no-pager | grep -E 'client|request|connection' | tail -20"

# Or check the LiteLLM proxy directly
ssh broker-server "curl -s http://127.0.0.1:4000/health"
```

### Tertiary: Daemon Output Quality

If the attacker's proxy injects modified LLM responses, daemon outputs may contain:
- Unusual recommendations (e.g., "disable monitoring", "expose this port")
- Factual errors about the fleet
- Instructions to modify security configuration

## Immediate Triage (First 2 Minutes)

### Step 1: Stop all daemons on the affected machine

```bash
# Kill daemon processes -- prevents any more prompts from being sent
ssh <machine> "pkill -f 'claude-peers daemon' 2>/dev/null"
ssh <machine> "pkill -f 'claude-peers supervisor' 2>/dev/null"
ssh <machine> "pgrep -fa claude-peers"
```

### Step 2: Check the current llm_base_url

```bash
ssh <machine> "cat ~/.config/claude-peers/config.json" | python3 -c "
import json, sys
cfg = json.load(sys.stdin)
llm_url = cfg.get('llm_base_url', 'NOT SET')
expected = 'http://127.0.0.1:4000/v1'
if llm_url == expected:
    print(f'OK: llm_base_url = {llm_url}')
else:
    print(f'TAMPERED: llm_base_url = {llm_url} (expected {expected})')
"
```

### Step 3: Check environment variable override

The config can also be overridden by environment variables:

```bash
ssh <machine> "echo CLAUDE_PEERS_LLM_URL=\$CLAUDE_PEERS_LLM_URL"
ssh <machine> "grep -r 'CLAUDE_PEERS_LLM_URL' ~/.bashrc ~/.profile ~/.zshrc /etc/environment /etc/profile.d/ 2>/dev/null"
```

### Step 4: Verify the LiteLLM proxy is the REAL one

```bash
# From broker-server: verify LiteLLM is running and healthy
ssh broker-server "curl -s http://127.0.0.1:4000/health"
ssh broker-server "ss -tlnp | grep 4000"

# Check what process is listening on :4000
ssh broker-server "ss -tlnp | grep ':4000' | awk '{print \$6}'"
```

## Investigation

### Determine the exposure window

```bash
# When was config.json last modified?
ssh <machine> "stat ~/.config/claude-peers/config.json"

# When did the Wazuh alert fire?
ssh broker-server "journalctl --user -u sontara-wazuh-bridge --since '24 hours ago' --no-pager | grep 'config.json' | head -5"

# When did the last daemon run complete?
ssh <machine> "journalctl --user --since '24 hours ago' --no-pager 2>/dev/null | grep -E 'daemon|fleet-scout|fleet-digest|librarian' | tail -10"

# How many daemon cycles ran during the exposure window?
# Daemon intervals are typically:
#   fleet-scout: 15 minutes
#   fleet-digest: 30 minutes
#   librarian: on-demand
#   llm-watchdog: 10 minutes
```

### Determine what data was sent to the attacker

```bash
# Check daemon agent files to understand what prompts contain
cat ~/projects/claude-peers/daemons/fleet-scout/fleet-scout.agent
cat ~/projects/claude-peers/daemons/fleet-digest/fleet-digest.agent
cat ~/projects/claude-peers/daemons/librarian/librarian.agent
cat ~/projects/claude-peers/daemons/llm-watchdog/llm-watchdog.agent
```

### Check if the attacker's proxy is still reachable

```bash
# What was the malicious URL?
MALICIOUS_URL=$(ssh <machine> "cat ~/.config/claude-peers/config.json" | python3 -c "import json,sys; print(json.load(sys.stdin).get('llm_base_url',''))")

# Is it still responding?
curl -s --connect-timeout 5 "$MALICIOUS_URL/health" 2>/dev/null && echo "ATTACKER PROXY STILL ALIVE" || echo "Attacker proxy not responding"

# What IP does it resolve to?
echo "$MALICIOUS_URL" | python3 -c "
import sys, socket
from urllib.parse import urlparse
url = sys.stdin.read().strip()
parsed = urlparse(url)
host = parsed.hostname
try:
    ip = socket.gethostbyname(host)
    print(f'Attacker IP: {ip}')
except:
    print(f'Cannot resolve: {host}')
"
```

### Check LiteLLM proxy for unexpected connections

```bash
# On broker-server: check if the REAL LiteLLM saw fewer requests than expected
ssh broker-server "journalctl --user -u litellm --since '24 hours ago' --no-pager 2>/dev/null | grep -c 'POST\|request'"

# Compare with expected: if daemons usually make N requests per hour
# and the count is significantly lower, those requests went elsewhere
```

### Diff config against known-good

```bash
# Full config audit across all machines
for target in <workstation-ip> <broker-ip> edge-node workstation-2-workstation "<user>@<laptop-1-ip><laptop-1-ip>" <iot-device-ip>; do
  echo "=== $target ==="
  ssh -o ConnectTimeout=5 $target "cat ~/.config/claude-peers/config.json 2>/dev/null" | python3 -c "
import json, sys
try:
    cfg = json.load(sys.stdin)
    checks = {
        'broker_url': 'http://<broker-ip>:7899',
        'nats_url': 'nats://<broker-ip>:4222',
        'llm_base_url': 'http://127.0.0.1:4000/v1',
    }
    for key, expected in checks.items():
        actual = cfg.get(key, 'MISSING')
        if actual != expected:
            print(f'  TAMPERED: {key} = {actual} (expected {expected})')
        else:
            print(f'  OK: {key}')
except:
    print('  ERROR: cannot parse config')
" 2>/dev/null
done
```

## Recovery

### Step 1: Restore the config

```bash
# Back up the tampered config for forensics
ssh <machine> "cp ~/.config/claude-peers/config.json ~/.config/claude-peers/config.json.compromised.$(date +%Y%m%d%H%M%S)"

# Restore the correct llm_base_url
ssh <machine> "python3 -c \"
import json
with open('/home/\$(whoami)/.config/claude-peers/config.json') as f:
    cfg = json.load(f)
cfg['llm_base_url'] = 'http://127.0.0.1:4000/v1'
with open('/home/\$(whoami)/.config/claude-peers/config.json', 'w') as f:
    json.dump(cfg, f, indent=2)
print('Restored llm_base_url')
\""
```

### Step 2: Assess what secrets were in the prompts

The prompts sent during the exposure window may have contained:

| Secret | How It Appears in Prompts | Rotation Required? |
|--------|--------------------------|-------------------|
| Machine Tailscale IPs | Peer lists, health reports | LOW -- IPs are not secret to tailnet members, but attacker now knows topology |
| Broker URL | Daemon INPUT variables | LOW -- public within tailnet |
| UCAN token auth pattern | `TOKEN=$(cat ~/.config/claude-peers/token.jwt)` | The pattern is exposed but not the token itself |
| Wazuh rule IDs | Security alert summaries | **MEDIUM** -- attacker knows what is monitored and what is not |
| Machine health scores | Fleet-scout analysis | **MEDIUM** -- attacker knows which machines are degraded |
| File paths and project names | Librarian, fleet-digest summaries | **MEDIUM** -- reveals project structure |
| Active incidents | Response-daemon context | **HIGH** -- attacker knows what you're investigating |
| LLM API key | If passed in prompts or config | **HIGH** -- rotate immediately |

### Step 3: Rotate secrets based on exposure

```bash
# If llm_api_key was in the config that was sent to daemons:
# Rotate the LiteLLM API key
ssh broker-server "
# Check current LiteLLM config for API keys
cat /etc/litellm/config.yaml 2>/dev/null | grep -i 'api_key' | head -5
# Rotate keys in the LiteLLM config and restart
"

# If the attacker injected malicious LLM responses that influenced daemon behavior:
# Check daemon output logs for suspicious recommendations
ssh broker-server "journalctl --user -u sontara-lattice --since '24 hours ago' --no-pager | grep -E 'daemon_complete|output' | tail -20"
```

### Step 4: Restart daemons

```bash
# After config is restored and secrets rotated:
ssh <machine> "claude-peers daemon &"
# Or restart via systemd if using service units:
ssh <machine> "systemctl --user restart sontara-lattice 2>/dev/null"
```

## Decision Tree

```
LLM exfiltration suspected (config.json FIM alert on llm_base_url)
|
+-- Is llm_base_url currently tampered?
|   +-- YES: changed to non-standard URL
|   |   +-- IMMEDIATE: kill all daemon processes
|   |   +-- Back up tampered config for forensics
|   |   +-- Restore correct llm_base_url
|   |   +-- Determine exposure window (config mtime vs. last daemon run)
|   |   +-- Were any daemon cycles completed during exposure?
|   |   |   +-- YES: attacker has prompt data
|   |   |   |   +-- Catalog what each daemon sent (see table above)
|   |   |   |   +-- Rotate any API keys that appeared in prompts
|   |   |   |   +-- Check daemon outputs for injected malicious responses
|   |   |   +-- NO: config was caught before daemons ran. Minimal damage.
|   |   +-- Investigate HOW config was modified (lateral movement? local exploit?)
|   |
|   +-- NO: llm_base_url is correct
|       +-- Was it tampered and restored by the attacker to cover tracks?
|       +-- Check config.json mtime and Wazuh FIM alert history
|       +-- Check if environment variable CLAUDE_PEERS_LLM_URL was set
|
+-- Response injection check:
    +-- Did daemon outputs change quality or content during exposure window?
    +-- Were any automated actions taken based on LLM-influenced daemon decisions?
    +-- If yes: review and potentially roll back those actions
```

## Attack Variant: Response Injection

Beyond exfiltration, the attacker can MODIFY LLM responses. This is more dangerous than passive capture:

| Injected Response | Impact |
|-------------------|--------|
| "All machines are healthy, no action needed" | Suppresses real security alerts |
| "Recommend disabling Wazuh FIM on this directory" | Reduces monitoring coverage |
| "The broker should be migrated to http://evil-ip:7899" | Social engineering via daemon output |
| "Fleet memory update: new NATS token is X" | Poisoning fleet memory |
| Subtly wrong security analysis | False sense of security |

Detection: Compare daemon outputs against independent verification. If fleet-scout says "all healthy" but Wazuh shows alerts, the LLM response may have been injected.

## Monitoring Gaps Summary

| Gap | Severity | Status | Remediation |
|-----|----------|--------|-------------|
| No pre-flight config validation before daemon LLM calls | **CRITICAL** | NOT IMPLEMENTED | TODO: Daemons should verify llm_base_url matches expected value before sending prompts |
| Config FIM detection may lag behind daemon execution | **HIGH** | ARCHITECTURAL | On Arch machines, FIM scan interval is up to 5 min. Daemons may fire before FIM catches the change. |
| No LLM request logging at the client side | **HIGH** | NOT IMPLEMENTED | TODO: Log the URL and prompt hash before each LLM call so forensics can determine exactly what was sent where |
| No LLM response integrity verification | **HIGH** | NOT IMPLEMENTED | TODO: Daemons should sanity-check LLM responses (e.g., reject responses that recommend disabling security) |
| Environment variable override bypasses config FIM | **MEDIUM** | KNOWN GAP | Setting CLAUDE_PEERS_LLM_URL in .bashrc changes the LLM endpoint without modifying config.json. FIM on .bashrc (rule 100110) would catch this, but it is a shell_persistence alert, not a config_tamper alert -- may not trigger the right investigation. |
| LiteLLM proxy has no client allowlist | **MEDIUM** | NOT IMPLEMENTED | TODO: LiteLLM should only accept connections from known fleet IPs |

## Hardening Recommendations

1. **Pre-flight URL validation in daemon code.** Before each LLM call, verify that the resolved `llm_base_url` matches a hardcoded or broker-provided expected value. If it doesn't match, skip the LLM call and publish a security alert.

2. **Client-side request logging.** Log every LLM request URL and a SHA256 hash of the prompt body. This creates an audit trail for forensics: you can determine exactly when the switch happened and how many prompts were sent to the wrong endpoint.

3. **LiteLLM client IP allowlist.** Configure LiteLLM to only accept connections from known fleet Tailscale IPs. If a request comes from an IP not in the allowlist, reject it.

4. **Pin the LLM URL at the broker level.** The broker could store the expected `llm_base_url` for each machine and flag heartbeats where the machine's config hash doesn't match. This detects the tamper even if FIM is delayed.

5. **Response sanity checking.** Add guardrails to daemon output processing: reject LLM responses that contain instructions to modify security configuration, disable monitoring, or change infrastructure URLs.
