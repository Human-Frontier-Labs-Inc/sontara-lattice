# Social Engineering and Account Compromise Incident Response Playbook

**System:** Sontara Lattice (claude-peers) fleet
**Last updated:** 2026-03-28
**Audience:** the operator (fleet operator)
**Severity tier:** Tier 2 (Investigate) escalating to Tier 3 if admin account compromised

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

### the operator's critical online accounts

| Account | What it controls | Fleet impact if compromised |
|---------|-----------------|---------------------------|
| **GitHub** (personal) | sontara-lattice repo, claude-peers source code, all project repos | Attacker pushes malicious code to fleet source, backdoors binary builds, accesses private repos |
| **Google (Gmail)** | Fleet digest emails, account recovery for other services | Attacker reads fleet status emails, intercepts password resets, gains context for targeted attacks |
| **Tailscale admin** | Tailnet device management, ACLs, auth keys | Attacker adds rogue devices, modifies ACLs to allow access, creates reusable auth keys, removes legitimate devices |
| **Anthropic console** | Claude API keys, billing, usage data | Attacker steals API keys (fleet uses Claude via LiteLLM), racks up billing, accesses usage/prompt data |
| **1Password** | All shared credentials with HFL | Attacker accesses all client credentials, infrastructure secrets |
| **Cloudflare** | DNS for your-domain.example.com, tunnel config | Attacker redirects DNS, intercepts traffic to demo sites |
| **GCP** | V4/Cuatro infrastructure, cloud services | Attacker accesses cloud VMs, databases, billing |

### Attack scenarios

**Scenario A: GitHub account compromise**

```
1. Attacker gains access to the operator's GitHub (phishing, token leak, session hijack)
2. Pushes malicious commit to claude-peers repo
3. Syncthing syncs the repo change to workstation (if auto-pull is configured)
4. Or: the operator pulls the change thinking it's his own work
5. Next build includes attacker's code
6. Deployed to entire fleet via scp
7. Alternatively: attacker modifies GitHub Actions (if any) to inject into CI
```

**Scenario B: Google account compromise**

```
1. Attacker gains access to the operator's Gmail
2. Reads fleet digest emails to understand:
   - Fleet topology and machine names
   - Current security monitoring setup
   - Daemon behavior and schedules
3. Uses this intelligence to craft targeted attacks
4. Intercepts password reset emails for other services
5. Gains access to additional accounts
```

**Scenario C: Tailscale admin compromise**

```
1. Attacker gains access to Tailscale admin panel
2. Creates a reusable auth key
3. Adds a rogue device to the tailnet
4. Rogue device has full mesh access to all fleet services
5. Modifies ACLs to allow their device access to everything
6. Optionally: removes legitimate devices to cause denial of service
7. All of this happens silently -- there is no alerting on Tailscale admin actions
```

**Scenario D: Anthropic console compromise**

```
1. Attacker gains access to Anthropic console
2. Copies Claude API keys
3. Uses keys to:
   - Make API calls charged to the operator's account
   - Access any prompt/completion history (if stored)
   - Create new API keys for persistent access
4. If fleet daemons use these API keys via LiteLLM, attacker can:
   - Monitor daemon prompts by querying API usage
   - Exhaust API quota to deny service to fleet daemons
```

**Scenario E: Credential stuffing / password reuse**

```
1. the operator's email/password appears in a data breach
2. Attacker tries the same credentials across services
3. Any service without unique password + 2FA is compromised
```

---

## Detection

### GitHub audit log

```bash
# Check GitHub for suspicious activity
echo "=== GitHub Security Audit ==="
echo "1. Check: https://github.com/settings/security-log"
echo "2. Look for:"
echo "   - Unexpected repository access"
echo "   - New SSH keys or personal access tokens"
echo "   - Push events you didn't make"
echo "   - New collaborators added to repos"
echo ""
echo "3. Check deploy keys on claude-peers repo:"
echo "   https://github.com/YOUR_ORG/claude-peers/settings/keys"
echo ""
echo "4. Check active sessions:"
echo "   https://github.com/settings/sessions"

# If you have gh CLI configured:
gh auth status 2>/dev/null
gh api /user/keys 2>/dev/null | python3 -c "
import json, sys
keys = json.load(sys.stdin)
for k in keys:
    print(f'  SSH Key: {k.get(\"title\")} (created: {k.get(\"created_at\",\"?\")[:10]})')
" 2>/dev/null
```

### Google account activity

```bash
echo "=== Google Account Security ==="
echo "1. Recent activity: https://myaccount.google.com/notifications"
echo "2. Devices: https://myaccount.google.com/device-activity"
echo "3. Third-party access: https://myaccount.google.com/permissions"
echo "4. Security events: https://myaccount.google.com/security-checkup"
echo ""
echo "Check for:"
echo "   - Logins from unknown locations/devices"
echo "   - New app passwords created"
echo "   - Forwarding rules added to Gmail (Settings -> Forwarding)"
echo "   - Filter rules that auto-delete or hide emails"
```

### Tailscale admin audit

```bash
# Check current Tailscale state
echo "=== Tailscale Admin Audit ==="
tailscale status

echo ""
echo "Check Tailscale admin panel:"
echo "1. Devices: https://login.tailscale.com/admin/machines"
echo "   - Count should be exactly 7 fleet + known personal devices"
echo "   - Look for unknown devices"
echo ""
echo "2. Auth keys: https://login.tailscale.com/admin/settings/keys"
echo "   - Should have NO reusable auth keys"
echo "   - Delete any unused keys"
echo ""
echo "3. ACLs: https://login.tailscale.com/admin/acls"
echo "   - Review for unexpected allow rules"
echo ""
echo "4. Audit log: Check for recent admin actions"

# Fleet device audit
tailscale status --json | python3 -c "
import json, sys
data = json.load(sys.stdin)
known = {'workstation', 'broker-server', 'edge-node', 'workstation-2', 'laptop-1', 'iot-device', 'laptop-2'}
peers = data.get('Peer', {})
for key, peer in peers.items():
    hostname = peer.get('HostName', 'unknown')
    online = peer.get('Online', False)
    created = peer.get('Created', 'unknown')[:10]
    if hostname.lower().replace('-','') not in {k.lower().replace('-','') for k in known}:
        print(f'UNKNOWN DEVICE: {hostname} (created: {created}, online: {online})')
" 2>/dev/null
```

### Anthropic console check

```bash
echo "=== Anthropic Console Audit ==="
echo "1. Check: https://console.anthropic.com/settings/keys"
echo "   - Review all API keys -- delete any you don't recognize"
echo "   - Check creation dates"
echo ""
echo "2. Check usage: https://console.anthropic.com/settings/billing"
echo "   - Unexpected usage spikes indicate stolen API keys"
echo ""
echo "3. Check team members (if applicable):"
echo "   - https://console.anthropic.com/settings/members"
```

### Monitor for credential leaks

```bash
# Check if your email appears in known breaches
echo "=== Breach Check ==="
echo "Check: https://haveibeenpwned.com/"
echo "Enter your email addresses to check for known breaches"
echo ""
echo "Also check GitHub for accidentally committed secrets:"
echo "  https://github.com/YOUR_ORG/claude-peers/security/secret-scanning"
```

---

## Immediate Triage (0-5 minutes)

### Step 1: Identify which account is compromised

Determine the compromised account and immediately assess the blast radius using the table in the Attack Model section.

### Step 2: Change the password immediately

For whichever account is compromised:

```
1. Change the password from a KNOWN CLEAN device
2. If you suspect your primary machine is compromised, use a different device
3. Use 1Password to generate a new unique password
4. Enable 2FA if not already enabled
```

### Step 3: Revoke active sessions

```
GitHub:  https://github.com/settings/sessions -> "Revoke all"
Google:  https://myaccount.google.com/device-activity -> Sign out of all devices
Tailscale: https://login.tailscale.com/admin -> Expire all device keys
Anthropic: https://console.anthropic.com/settings/keys -> Regenerate all API keys
```

---

## Containment

### GitHub compromise containment

```bash
# 1. Revoke all personal access tokens
echo "https://github.com/settings/tokens -> Delete all tokens"

# 2. Remove all SSH keys you don't recognize
echo "https://github.com/settings/keys -> Remove unknown keys"

# 3. Check for malicious commits in claude-peers
cd ~/projects/claude-peers
git fetch origin
git log --oneline origin/main -20
# Look for commits you didn't make
# Check diff of recent commits:
git log --oneline --since="7 days ago" origin/main | while read hash msg; do
    echo "=== $hash: $msg ==="
    git diff "$hash^..$hash" --stat
done

# 4. If malicious code was pushed: force-push to remove it
# git reset --hard KNOWN_GOOD_COMMIT
# git push --force origin main
# WARNING: This is destructive -- only do if confirmed malicious
```

### Tailscale admin compromise containment

```bash
# This is the most critical -- attacker can add devices and access everything

# 1. Immediately remove any unknown devices
echo "https://login.tailscale.com/admin/machines"
echo "Remove ALL devices you don't recognize"

# 2. Disable ALL reusable auth keys
echo "https://login.tailscale.com/admin/settings/keys"
echo "Delete every auth key"

# 3. Expire all device keys (forces re-authentication)
echo "Expire key on each device in admin panel"

# 4. Review and restore ACLs to known-good state
echo "https://login.tailscale.com/admin/acls"

# 5. Run fleet device audit
tailscale status
```

### Anthropic console containment

```bash
# 1. Regenerate ALL API keys
echo "https://console.anthropic.com/settings/keys"
echo "Delete all existing keys and create new ones"

# 2. Update LiteLLM config with new API key
ssh broker-server "
# Update the Anthropic API key in LiteLLM config
# The exact location depends on how LiteLLM is configured
docker exec litellm cat /app/config.yaml | grep -i 'anthropic\|claude'
"

# 3. Restart LiteLLM with new key
ssh broker-server "docker restart litellm"
```

### Google account containment

```bash
echo "=== Google Account Lockdown ==="
echo "1. Change password: https://myaccount.google.com/signinoptions/password"
echo "2. Revoke app passwords: https://myaccount.google.com/apppasswords"
echo "3. Remove third-party access: https://myaccount.google.com/permissions"
echo "4. Check Gmail filters: Settings -> Filters and Blocked Addresses"
echo "   - Delete any forwarding rules you didn't create"
echo "   - Delete any filters that auto-archive or auto-delete"
echo "5. Check Gmail forwarding: Settings -> Forwarding and POP/IMAP"
echo "   - Disable any forwarding addresses you didn't add"
```

---

## Investigation

### Determine the attack vector

```bash
echo "=== Attack Vector Investigation ==="
echo ""
echo "1. Was it phishing?"
echo "   - Check Gmail sent folder and trash for phishing emails"
echo "   - Check browser history for fake login pages"
echo ""
echo "2. Was it a token/key leak?"
echo "   - Search repos for committed secrets:"
cd ~/projects/claude-peers
grep -r 'sk-\|ghp_\|gho_\|ANTHROPIC\|tailscale' . --include='*.go' --include='*.json' --include='*.yaml' --include='*.yml' --include='*.env' 2>/dev/null | grep -v 'node_modules\|vendor\|.git' | head -20
echo ""
echo "3. Was it credential reuse from a breach?"
echo "   - Check https://haveibeenpwned.com/"
echo ""
echo "4. Was it session hijack?"
echo "   - Check for malware on the machine used to log in"
echo "   - Check browser extensions for suspicious ones"
```

### Assess what the attacker accessed

```bash
# For GitHub: check audit log
echo "Check GitHub audit log for the compromised period:"
echo "https://github.com/settings/security-log"
echo ""
echo "Look for:"
echo "  - repo.clone events (what repos were cloned)"
echo "  - repo.push events (what code was pushed)"
echo "  - public_key.create (SSH keys added)"
echo "  - oauth_access.create (tokens created)"

# For Tailscale: check if new devices were added
echo ""
echo "Check Tailscale admin for devices added during the compromised period"
```

---

## Recovery

### Step 1: Verify all accounts are secured

```bash
echo "=== Account Security Verification ==="
echo ""
echo "For each account, verify:"
echo "  [ ] Password changed to unique value (via 1Password)"
echo "  [ ] 2FA enabled (preferably hardware key)"
echo "  [ ] Active sessions revoked"
echo "  [ ] Unknown SSH keys / tokens removed"
echo "  [ ] No unauthorized changes to settings"
echo ""
echo "Accounts to verify:"
echo "  [ ] GitHub"
echo "  [ ] Google (Gmail)"
echo "  [ ] Tailscale"
echo "  [ ] Anthropic"
echo "  [ ] 1Password"
echo "  [ ] Cloudflare"
echo "  [ ] GCP"
```

### Step 2: If malicious code was pushed to GitHub

```bash
cd ~/projects/claude-peers

# 1. Identify the malicious commits
git log --oneline --since="COMPROMISE_START_DATE" origin/main

# 2. Review each commit
# 3. Revert or force-push to remove malicious code
# 4. Rebuild the binary from clean source
# 5. Redeploy to all fleet machines (see UPGRADE_ATTACK playbook)
```

### Step 3: If Tailscale was compromised

Follow the TAILSCALE_COMPROMISE playbook for full recovery, including:
- Remove all rogue devices
- Rotate all fleet credentials (UCAN tokens, NATS token)
- Verify fleet integrity

### Step 4: If API keys were stolen

```bash
# Regenerate all API keys across all services
# Update all services that use those keys
# Monitor for unauthorized usage over the next 30 days
```

---

## Post-Incident Hardening

### 1. Hardware security keys (YubiKey) for all critical accounts

```
Priority order:
1. Google account (recovery anchor for other accounts)
2. GitHub (source code integrity)
3. Tailscale (network access control)
4. 1Password (credential vault)
5. Anthropic (API keys, billing)
6. Cloudflare (DNS, tunnels)

Setup: https://www.yubico.com/setup/
Each account should have TWO hardware keys (primary + backup)
```

### 2. Unique passwords for every account

```
Use 1Password to generate unique 20+ character passwords for every service.
NEVER reuse passwords across accounts.
```

### 3. Email alias strategy

```
Use unique email aliases for each service registration.
If an alias appears in a breach, you know exactly which service was compromised.
Example: user+github@gmail.com, user+tailscale@gmail.com
```

### 4. Regular account audit schedule

```
Monthly:
- Review GitHub security log and SSH keys
- Review Google connected apps and devices
- Audit Tailscale device list and auth keys
- Review Anthropic API keys and usage
- Check haveibeenpwned.com for new breaches

Quarterly:
- Rotate API keys (Anthropic, any others)
- Review and prune GitHub personal access tokens
- Review 1Password for weak or reused passwords
```

### 5. Phishing resistance

```
- NEVER click login links in emails -- always type the URL manually
- Use browser bookmarks for critical services
- Enable Gmail phishing alerts
- Use a browser extension that warns on lookalike domains
```

---

## Monitoring Gaps

| Gap | Severity | Status | Remediation |
|-----|----------|--------|-------------|
| No hardware security keys on critical accounts | **CRITICAL** | NOT IMPLEMENTED | Purchase and configure YubiKeys for all critical accounts |
| No alerting on Tailscale admin actions | **CRITICAL** | NOT IMPLEMENTED | No way to detect when someone adds a device or modifies ACLs |
| No alerting on GitHub push events to fleet repos | **HIGH** | NOT IMPLEMENTED | Set up GitHub webhook or notification for push events to claude-peers |
| No API key usage monitoring | **HIGH** | NOT IMPLEMENTED | Monitor Anthropic usage dashboard for unexpected spikes |
| No automated credential leak scanning | **HIGH** | NOT IMPLEMENTED | Use GitHub secret scanning, monitor haveibeenpwned API |
| No Gmail forwarding rule audit | **MEDIUM** | NOT IMPLEMENTED | Periodic check for unauthorized forwarding rules |
| No Tailscale auth key audit automation | **MEDIUM** | NOT IMPLEMENTED | Periodic check for reusable auth keys that should not exist |
| 2FA status unknown across all accounts | **MEDIUM** | NOT CONFIRMED | Verify 2FA is enabled on every critical account |
| No incident communication plan | **LOW** | NOT IMPLEMENTED | If the operator's accounts are compromised, how do clients/partners get notified? |
