# API Key Leak Incident Response Playbook

**System:** Sontara Lattice (claude-peers) fleet
**Last updated:** 2026-03-28
**Audience:** the operator (fleet operator)
**Severity tier:** Varies per key (see impact table)

---

## Table of Contents

1. [Key Inventory](#key-inventory)
2. [Per-Key Impact Assessment](#per-key-impact-assessment)
3. [Leak Vectors](#leak-vectors)
4. [Detection](#detection)
5. [Response Per Key](#response-per-key)
6. [Prevention](#prevention)
7. [Monitoring Gaps](#monitoring-gaps)

---

## Key Inventory

Every secret in the Sontara Lattice fleet, where it lives, and what it protects.

| Secret | Value Pattern | Where Configured | Where Used | Rotation Difficulty |
|--------|--------------|------------------|------------|-------------------|
| **LiteLLM Proxy Key** | `sk-litellm-ai-town-proxy-2026` | broker-server LiteLLM config | Daemons via `CLAUDE_PEERS_LLM_API_KEY` env var in config.json | Low -- single service |
| **Anthropic API Key** | `sk-ant-*` | Environment on broker-server | LiteLLM proxy backend | Low -- single service |
| **NATS Token** | `<your-nats-token>` | `CLAUDE_PEERS_NATS_TOKEN` env var / config.json on every machine | Every NATS connection (broker, bridge, security-watch, dream, gridwatch) | **High** -- every machine and service |
| **Wazuh API Password** | `Fl33tW4tch.2026Xr` | `~/docker/wazuh/.env` on broker-server, Docker env `API_PASSWORD` | Wazuh REST API on port 55000 | Medium -- single container |
| **Resend Email API Key** | `re_*` | Environment on broker-server (`resend-email` CLI) | Email alerts from security-watch, response-daemon, fleet-digest | Low -- single CLI tool |
| **GitHub Tokens** | `ghp_*` or `github_pat_*` | `~/.config/gh/hosts.yml` or git credential store per machine | Git push, `gh` CLI | Medium -- per-machine |
| **UCAN Root Token** | JWT (1 year TTL) | `~/.config/claude-peers/token.jwt` on broker-server | Broker root auth, token issuance | **Critical** -- see ROOT_KEY_COMPROMISE.md |
| **UCAN Peer Tokens** | JWT (24h TTL) | `~/.config/claude-peers/token.jwt` on each machine | All broker API calls | Medium -- per-machine |
| **Tailscale Auth Keys** | `tskey-*` | Per-device enrollment, one-time use | Initial device registration only | N/A -- already consumed |

---

## Per-Key Impact Assessment

### LiteLLM Proxy Key (`sk-litellm-ai-town-proxy-2026`)

**What an attacker can do:**
- Send requests to the LiteLLM proxy as if they were a daemon
- Consume Anthropic/Vertex AI credits by routing model calls through the proxy
- Read model responses if they can also intercept traffic
- They CANNOT access the underlying Anthropic API key through LiteLLM

**Blast radius:** Financial (API credits), operational (rate limit exhaustion starves daemons)

**Severity:** Medium

### Anthropic API Key (`sk-ant-*`)

**What an attacker can do:**
- Make direct Anthropic API calls with your account
- Consume all available credits
- Access any model available on your account
- They do NOT get access to the fleet -- this key is for model inference only

**Blast radius:** Financial (potentially large -- Anthropic bills per token)

**Severity:** High

### NATS Token (`<your-nats-token>`)

**What an attacker can do:**
- Connect to the NATS server and subscribe to ALL fleet subjects (`fleet.>`)
- Read every security event, peer join/leave, heartbeat, message, fleet memory update
- Publish fake events to `fleet.security.*` -- could trigger false quarantines
- Publish to `fleet.peer.*` -- could inject fake peer registrations
- Disrupt NATS JetStream by creating rogue consumers

**Blast radius:** Full fleet observability compromise, potential for fleet disruption via false events

**Severity:** **Critical** -- the NATS token is a shared secret with no per-machine scoping. One leaked token = attacker sees everything.

### Wazuh API Password (`Fl33tW4tch.2026Xr`)

**What an attacker can do:**
- Authenticate to the Wazuh REST API on port 55000
- Suppress alerts by modifying rules or decoders
- Inject false alerts to trigger quarantine of legitimate machines
- Read agent data (system inventory, vulnerability scans, FIM baselines)
- Enumerate all monitored machines and their security posture
- Potentially pivot to agents via Wazuh active response (execute commands on agents)

**Blast radius:** Security monitoring blindness, false flag attacks, potential remote code execution via active response

**Severity:** **Critical**

### Resend Email API Key

**What an attacker can do:**
- Send emails from your Resend domain
- Phish the operator or partner using a trusted sender address
- Exhaust email sending quota (denial of service on alerting)

**Blast radius:** Social engineering, alert suppression

**Severity:** Medium

### GitHub Tokens

**What an attacker can do:**
- Push code to repositories (including claude-peers itself)
- Read private repositories
- Create releases with trojaned binaries
- Modify GitHub Actions workflows

**Blast radius:** Supply chain compromise -- a malicious push to claude-peers could deploy backdoored binaries fleet-wide via `deploy.sh`

**Severity:** High

---

## Leak Vectors

How a key might end up somewhere it should not be.

| Vector | Example | Likelihood |
|--------|---------|------------|
| **Git commit** | `config.json` with `nats_token` committed to claude-peers repo | Medium -- config.json has secrets inline |
| **Daemon output** | LLM daemon logs include the `LLM_API_KEY` in error messages | Medium -- Go HTTP client may log URLs with query params |
| **Fleet memory** | A daemon writes debug info to fleet memory that includes a key | Low -- daemons use structured data |
| **NATS event** | A FleetEvent `Data` field contains a config dump with secrets | Low -- events are typed |
| **Email digest** | Fleet digest includes environment variable dump | Low -- digest uses structured Go code |
| **PR body / issue** | Copy-pasting config.json into a GitHub issue | Medium -- human error |
| **Error log** | Stack trace or HTTP error includes auth header with bearer token | Medium -- Go HTTP errors may include request details |
| **Systemd unit file** | `Environment=CLAUDE_PEERS_NATS_TOKEN=...` in a unit file committed to dotfiles | **High** -- chezmoi auto-syncs dotfiles to GitHub |

---

## Detection

### What we CAN detect today

| Method | What it catches | Automated? |
|--------|----------------|------------|
| Wazuh FIM on `~/.config/claude-peers/` | Modification of config.json (which contains `nats_token`, `llm_api_key`) | Yes -- rule 100113, level 11 |
| Manual `git log` review | Secrets in commit history | No |
| API usage anomaly (manual check) | Unexpected LiteLLM/Anthropic usage spikes | No |
| Broker logs | Unexpected NATS connections or peer registrations | Partial -- logs exist but no alerting |

### What we CANNOT detect today

| Gap | Risk | Priority |
|-----|------|----------|
| **No git-secrets or pre-commit hooks** | Secrets can be committed to any repo on any machine | **P0** |
| **No automated secret scanning on GitHub** | Leaked secrets in push history go unnoticed | **P0** |
| **No API usage anomaly detection** | Attacker using LiteLLM/Anthropic keys is invisible until the bill arrives | **P1** |
| **No NATS connection monitoring** | Unknown clients connecting to NATS with the shared token are invisible | **P1** |
| **No Wazuh API access logging review** | Attacker using the Wazuh API password goes unnoticed | **P1** |
| **No Resend API usage monitoring** | Unauthorized emails from your domain go unnoticed | **P2** |
| **No automated chezmoi audit for secrets** | Dotfile sync may push secrets to GitHub | **P1** |

---

## Response Per Key

### LiteLLM Proxy Key Rotation

**Impact:** Daemons lose LLM access until reconfigured.

```bash
# Step 1: Generate a new key (any random string works for LiteLLM proxy)
NEW_KEY="sk-litellm-$(openssl rand -hex 16)"
echo "New LiteLLM key: $NEW_KEY"

# Step 2: Update LiteLLM proxy config on broker-server
ssh broker-server
# Edit the LiteLLM config (location depends on your LiteLLM deployment)
# Update the master_key or api_key field to $NEW_KEY
# Restart LiteLLM
sudo systemctl restart litellm  # or docker restart litellm

# Step 3: Update claude-peers config on broker-server (broker)
ssh broker-server "jq '.llm_api_key = \"$NEW_KEY\"' ~/.config/claude-peers/config.json > /tmp/cp-config.json && mv /tmp/cp-config.json ~/.config/claude-peers/config.json"

# Step 4: Update CLAUDE_PEERS_LLM_API_KEY in all systemd unit files that reference it
ssh broker-server "grep -rl 'sk-litellm' ~/.config/systemd/user/"
# Edit each file, replace the old key

# Step 5: Restart affected services
ssh broker-server "systemctl --user daemon-reload && systemctl --user restart claude-peers-supervisor claude-peers-dream"

# Step 6: Verify daemons can reach LLM
ssh broker-server "journalctl --user -u claude-peers-supervisor --since '1 min ago' --no-pager | tail -10"
```

### Anthropic API Key Rotation

**Impact:** LiteLLM proxy loses backend access until reconfigured.

```bash
# Step 1: Generate a new key at https://console.anthropic.com/settings/keys
# Revoke the old key immediately from the Anthropic console.

# Step 2: Update the Anthropic key in LiteLLM config on broker-server
ssh broker-server
# Edit LiteLLM config -- update the anthropic API key in the model list
# Restart LiteLLM
sudo systemctl restart litellm  # or docker restart litellm

# Step 3: Update any environment files that reference the old key
ssh broker-server "grep -rl 'sk-ant-' ~/.config/systemd/user/ /etc/environment ~/.bashrc ~/.profile 2>/dev/null"

# Step 4: Verify LiteLLM can still route to Anthropic
ssh broker-server "curl -s http://127.0.0.1:4000/v1/models -H 'Authorization: Bearer $LITELLM_KEY' | jq '.data[].id'"
```

### NATS Token Rotation

**Impact:** ALL NATS connections across the entire fleet drop simultaneously. Every service on every machine that uses NATS must be updated.

This is the most disruptive rotation. Plan for 5-10 minutes of fleet communication downtime.

```bash
# Step 1: Generate new token
NEW_NATS_TOKEN="nats-$(openssl rand -hex 16)"
echo "New NATS token: $NEW_NATS_TOKEN"

# Step 2: Update NATS server config on broker-server
ssh broker-server
# Edit the NATS server config (nats-server.conf or equivalent)
# Update the authorization token
# Example: authorization { token: "<NEW_NATS_TOKEN>" }
sudo systemctl restart nats-server  # or docker restart nats

# Step 3: Update config.json on EVERY fleet machine
MACHINES="broker-server workstation edge-node workstation-2 laptop-1 iot-device"
for machine in $MACHINES; do
  echo "=== Updating $machine ==="
  case $machine in
    broker-server) HOST="broker-server" ;;
    workstation)        HOST="<workstation-ip>" ;;
    edge-node)       HOST="edge-node" ;;
    workstation-2)      HOST="<workstation-2-ip>" ;;
    laptop-1)       HOST="<user>@<laptop-1-ip><laptop-1-ip>" ;;
    iot-device)        HOST="<iot-device-ip>" ;;
  esac

  ssh $HOST "jq '.nats_token = \"$NEW_NATS_TOKEN\"' ~/.config/claude-peers/config.json > /tmp/cp-config.json && mv /tmp/cp-config.json ~/.config/claude-peers/config.json"
  echo "  $machine config updated"
done

# Step 4: Update all systemd unit files that reference the old token
ssh broker-server "grep -rl 'NATS_TOKEN' ~/.config/systemd/user/"
# Edit each file with the new token

# Step 5: Restart ALL fleet services
ssh broker-server "systemctl --user daemon-reload && systemctl --user restart claude-peers-broker claude-peers-dream claude-peers-supervisor claude-peers-wazuh-bridge claude-peers-security-watch claude-peers-response-daemon"

# Step 6: Verify NATS connectivity from each machine
for machine in $MACHINES; do
  echo "=== $machine ==="
  # Trigger a peer registration or check broker logs
done

ssh broker-server "journalctl --user -u claude-peers-broker --since '1 min ago' --no-pager | grep nats"
```

### Wazuh API Password Rotation

**Impact:** Wazuh API access changes. Any scripts or dashboards using the API need updating.

```bash
# Step 1: Choose a new password
NEW_WAZUH_PASS="$(openssl rand -base64 24)"
echo "New Wazuh password: $NEW_WAZUH_PASS"

# Step 2: Update the .env file
ssh broker-server "cd ~/docker/wazuh && echo 'WAZUH_API_PASSWORD=$NEW_WAZUH_PASS' > .env"

# Step 3: Restart the Wazuh manager container
ssh broker-server "cd ~/docker/wazuh && docker compose down && docker compose up -d"

# Step 4: Wait for Wazuh to start (takes ~30 seconds)
sleep 30

# Step 5: Verify API access with new password
ssh broker-server "curl -s -k -u wazuh-api:$NEW_WAZUH_PASS https://127.0.0.1:55000/security/user/authenticate 2>/dev/null | head -c 100"

# Step 6: Update any scripts or configs that reference the old password
# Search for the old password in configs
ssh broker-server "grep -rl 'Fl33tW4tch' ~/projects/ ~/.config/ 2>/dev/null"

# Step 7: Verify agents reconnect
ssh broker-server "docker exec wazuh-manager /var/ossec/bin/agent_control -l"
```

### Resend Email API Key Rotation

**Impact:** Email alerting stops until the new key is configured.

```bash
# Step 1: Generate a new API key at https://resend.com/api-keys
# Revoke the old key.

# Step 2: Update the resend-email CLI config on broker-server
ssh broker-server
# Update wherever the resend-email CLI stores its API key
# This is typically an environment variable or config file
grep -r "RESEND" ~/.config/ ~/.bashrc ~/.profile /etc/environment 2>/dev/null

# Step 3: Test email sending
ssh broker-server "resend-email -m 'Test after key rotation' your-email@example.com 'Key rotation test'"

# Step 4: Verify security alerting still works
# Trigger a harmless FIM event
ssh broker-server "touch ~/.config/claude-peers/test-fim-rotation && rm ~/.config/claude-peers/test-fim-rotation"
# Check that the email arrives
```

### GitHub Token Rotation

**Impact:** Git push and `gh` CLI stop working on the affected machine until re-authenticated.

```bash
# Step 1: Revoke the token at https://github.com/settings/tokens
# If it's a fine-grained PAT, revoke that specific token.

# Step 2: Re-authenticate on the affected machine
ssh <machine> "gh auth login"
# Follow the interactive flow, or use:
ssh <machine> "gh auth login --with-token <<< '<new-token>'"

# Step 3: Verify
ssh <machine> "gh auth status"
ssh <machine> "git push --dry-run origin main 2>&1 | head -5"

# Step 4: If the token was in a git credential store:
ssh <machine> "git credential reject <<EOF
protocol=https
host=github.com
EOF"
```

---

## Prevention

### Immediate (do now)

**Install git-secrets pre-commit hooks on all machines:**

```bash
# On each development machine (workstation, broker-server, workstation-2, laptop-1)
# Install git-secrets
# Arch: yay -S git-secrets
# Ubuntu: sudo apt install git-secrets
# macOS: brew install git-secrets

# Register patterns for known secret formats
git secrets --register-aws  # catches AWS-style keys too
git secrets --add 'sk-litellm-.*'
git secrets --add 'sk-ant-.*'
git secrets --add 'nats-[a-f0-9]{32}'
git secrets --add 'Fl33tW4tch'
git secrets --add 'tskey-.*'
git secrets --add 're_[a-zA-Z0-9]+'
git secrets --add 'ghp_[a-zA-Z0-9]+'
git secrets --add 'github_pat_[a-zA-Z0-9]+'

# Install the hook in claude-peers repo
cd ~/projects/claude-peers
git secrets --install
```

**Add .gitignore entries:**

```bash
# In claude-peers repo root
echo "deploy.conf" >> .gitignore
echo "*.pem" >> .gitignore
echo "*.jwt" >> .gitignore
echo ".env" >> .gitignore
```

**Audit chezmoi for secrets:**

```bash
# Check what chezmoi is tracking
chezmoi managed | xargs grep -l 'sk-litellm\|sk-ant-\|nats-\|Fl33tW4tch\|NATS_TOKEN\|API_KEY' 2>/dev/null
```

### Short-term (this week)

- Enable GitHub secret scanning on the claude-peers repository (Settings > Code security)
- Move all secrets out of `config.json` and systemd unit files into a `.env` file with `0600` permissions
- Add `config.json` to the Wazuh FIM monitored paths (already done -- rule 100113)
- Set up NATS server monitoring endpoint to audit connections

### Medium-term (this month)

- Replace the shared NATS token with per-machine NATS credentials (NKey authentication)
- Restrict Wazuh API port 55000 to localhost only (no Tailscale exposure)
- Implement API usage alerting for Anthropic (billing alerts at minimum)
- Add a Claude Code hook that scans staged files for secrets before commit

### Long-term

- Use a secrets manager (HashiCorp Vault, sops, or age-encrypted files)
- Implement automatic NATS token rotation on a schedule
- Store LiteLLM and Anthropic keys in encrypted environment files decrypted at service start

---

## Monitoring Gaps

These are the gaps that exist today. Each is a blind spot where a key leak could go undetected.

| Gap | What Could Happen | Detection Today | Fix |
|-----|-------------------|-----------------|-----|
| **No pre-commit secret scanning** | Secret committed to git, pushed to GitHub, visible to anyone with repo access | None | Install git-secrets fleet-wide |
| **No GitHub secret scanning** | Leaked key in commit history stays discoverable indefinitely | None | Enable GitHub Advanced Security |
| **No NATS connection monitoring** | Attacker connects with stolen NATS token, reads all events, injects false ones | None | Enable NATS monitoring endpoint, alert on unknown client names |
| **No API usage anomaly detection** | Attacker burns through Anthropic credits or floods LiteLLM | None until the bill arrives | Set up billing alerts on Anthropic, rate limit on LiteLLM |
| **No Wazuh API audit logging** | Attacker uses Wazuh API to suppress alerts | Wazuh internal logs (not monitored) | Parse Wazuh API access logs, alert on rule modifications |
| **No chezmoi secret audit** | Systemd unit files with secrets auto-sync to GitHub | None | Add pre-sync hook to chezmoi that scans for secret patterns |
| **No email API usage monitoring** | Attacker sends phishing emails from your domain | None | Resend dashboard manual review |
| **Shared NATS token (no per-machine scoping)** | One leaked machine config exposes the token used by every machine | None -- all connections look the same | Migrate to NATS NKey per-machine auth |

---

## Quick Reference Card

```
API KEY LEAKED -- WHERE DID IT APPEAR?
    |
    +-- Git commit / PR body / GitHub?
    |     1. Revoke the key immediately (see per-key section)
    |     2. Rotate the key
    |     3. Force-push to remove from history (if private repo)
    |        git filter-branch or BFG Repo-Cleaner
    |     4. If public repo: assume fully compromised, rotate everything
    |
    +-- NATS event / fleet memory?
    |     1. Only visible to NATS subscribers (fleet-internal)
    |     2. Still rotate -- NATS stream retains 24h of events
    |     3. Purge the NATS stream: nats stream purge FLEET
    |
    +-- Error log / daemon output?
    |     1. Rotate the key
    |     2. Fix the logging code to redact secrets
    |     3. Purge old logs: journalctl --user --vacuum-time=1h
    |
    +-- Email digest?
    |     1. Rotate the key
    |     2. The email is in the operator's inbox -- low external risk
    |     3. Fix the digest code to not include secrets
    |
    +-- Unknown / public exposure?
          1. Assume worst case
          2. Rotate ALL related keys
          3. Check for unauthorized usage (API logs, billing)
          4. Monitor for 48 hours
```
