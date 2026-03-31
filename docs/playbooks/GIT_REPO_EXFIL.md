# Playbook: Source Repository Exfiltration

**System:** Sontara Lattice (claude-peers) fleet
**Last updated:** 2026-03-28
**Audience:** the operator (fleet operator)
**Severity tier:** Tier 3 (Approval Required) -- security architecture documentation exposed

---

## Table of Contents

1. [Attack Model](#attack-model)
2. [What the Repository Contains](#what-the-repository-contains)
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

The Sontara Lattice source code lives in the private GitHub repository `your-github-org/sontara-lattice` and is checked out to `~/projects/claude-peers/` on workstation. Via Syncthing, it syncs to `~/projects/claude-peers/` on broker-server.

The repository is not just code -- it is a complete security operations manual. It documents every detection rule, every monitoring gap, every playbook procedure, every machine IP, and every architectural decision. An attacker with this repository knows exactly how to attack the fleet and exactly what will and will not be detected.

### Attack Vectors

**Vector 1: GitHub Repository Leak**
- Repository made public accidentally (settings change)
- GitHub account compromise (the operator or partner's account)
- Repository forked to a public repo
- GitHub API token with repo access leaked (in .env, CI config, etc.)

**Vector 2: Local Filesystem Copy**
- Attacker with SSH access to workstation or broker-server copies the git repo
- Syncthing exfiltration (see SYNCTHING_EXFIL playbook) -- `~/projects/` includes the repo
- Compromised Claude session reads repository files via Read/Bash tools

**Vector 3: Git History Mining**
- Even if sensitive content is removed from current files, it persists in git history
- `git log -p --all` reveals every change ever made
- Force pushes that "remove" commits don't remove them if the attacker already cloned

**Vector 4: CI/CD Exposure**
- If CI/CD pipelines have access to the repo, compromised CI systems expose it
- GitHub Actions artifacts may contain repo contents

---

## What the Repository Contains

### Security Architecture (Maximum Sensitivity)

| File/Directory | Content | Attacker Value |
|---------------|---------|---------------|
| `wazuh/local_rules.xml` | Every custom Wazuh rule, rule IDs, severity levels, trigger conditions | **CRITICAL** -- attacker knows exactly what is monitored and at what thresholds |
| `wazuh/shared_agent.conf` | All FIM monitored paths, ignore patterns, log sources | **CRITICAL** -- attacker knows the syscheck gaps (like `.db$` ignore) |
| `docs/playbooks/*.md` | Every incident response procedure, decision tree, known gaps | **CRITICAL** -- attacker knows exactly how you will respond and where your blind spots are |
| `docs/INCIDENT_RESPONSE.md` | Master runbook, alert tiers, response actions, emergency contacts | **CRITICAL** |
| `docs/WAZUH_SETUP.md` | Full Wazuh deployment guide, manager config, agent enrollment | **HIGH** -- attacker can understand and evade the monitoring system |
| `docs/UCAN_AUTH.md` | Authentication architecture, token format, capability model | **HIGH** -- attacker understands the auth system |

### Fleet Infrastructure

| File | Content | Attacker Value |
|------|---------|---------------|
| `config.go` | All config fields, defaults, env var names | **HIGH** -- reveals every configurable parameter and how to override them |
| `broker.go` | Full broker implementation, all API endpoints, SQLite schema | **HIGH** -- attacker can find vulnerabilities in the broker |
| `ucan.go`, `ucan_middleware.go` | Token validation logic, capability checking | **HIGH** -- attacker can find auth bypass vectors |
| `security_watch.go` | Alert correlation logic, escalation rules | **HIGH** -- attacker knows how alerts are correlated |
| `response_daemon.go`, `response_actions.go` | Auto-response actions, forensic capture procedures | **HIGH** -- attacker knows exactly what auto-responses will fire |
| `sim_attack.go` | Attack simulation code -- literally documents attack techniques | **HIGH** |
| `deploy.sh`, `deploy.conf.example` | Deployment procedure, target machines | **MEDIUM** |

### Network Information

| Information | Source | Attacker Value |
|------------|--------|---------------|
| Tailscale IPs (<workstation-ip>, <broker-ip>, etc.) | Config files, playbooks, CLAUDE.md | **MEDIUM** -- only useful if attacker gains Tailscale access |
| Service ports (7899, 4222, 4000, 8384, 8888) | Config defaults, docs | **MEDIUM** -- standard ports but confirms service layout |
| Machine roles (broker on broker-server, kiosk on edge-node) | Docs, config | **MEDIUM** -- fleet topology |
| SSH access patterns | Deploy script, playbooks | **MEDIUM** -- reveals which machines can reach which |

### Monitoring Gaps (Documented in Playbooks)

Every playbook contains a "Monitoring Gaps" section that explicitly lists what is NOT monitored. An attacker reading these knows:

| Documented Gap | Playbook | Attacker Exploitation |
|---------------|----------|----------------------|
| `.db` files ignored by FIM | DATABASE_EXFIL | Steal database without triggering alerts |
| No Syncthing config monitoring | SYNCTHING_EXFIL | Add rogue sync device without detection |
| No fleet memory content validation | FLEET_MEMORY_POISONING | Inject instructions into all Claude sessions |
| No message content monitoring | PEER_MESSAGE_EXFIL | Exfiltrate data via peer messages without detection |
| No input device monitoring | CLIPBOARD_KEYLOG | Install keylogger without detection |
| No outbound SSH monitoring | SSH_TUNNEL_EXFIL | Create tunnels without detection |

---

## Detection Signals

### Primary: GitHub Audit Log

```bash
# Check GitHub audit log for the organization
# Requires GitHub CLI with admin access
gh api /orgs/your-github-org/audit-log \
  --paginate \
  -q '.[] | select(.action | startswith("repo.")) | "\(.created_at) \(.action) \(.actor) \(.repo)"' \
  2>/dev/null | head -20

# Check for repo visibility changes
gh api /orgs/your-github-org/audit-log \
  --paginate \
  -q '.[] | select(.action == "repo.access" or .action == "repo.visibility_change") | "\(.created_at) \(.action) \(.actor)"' \
  2>/dev/null

# Check for forks
gh api repos/your-github-org/sontara-lattice/forks \
  -q '.[].full_name' 2>/dev/null
```

### Secondary: GitHub Repository Settings

```bash
# Check current repo visibility
gh repo view your-github-org/sontara-lattice --json visibility -q '.visibility'

# Check collaborators
gh api repos/your-github-org/sontara-lattice/collaborators \
  -q '.[].login' 2>/dev/null

# Check deploy keys
gh api repos/your-github-org/sontara-lattice/keys \
  -q '.[] | "\(.id) \(.title) \(.read_only) created=\(.created_at)"' 2>/dev/null

# Check webhooks
gh api repos/your-github-org/sontara-lattice/hooks \
  -q '.[] | "\(.id) \(.config.url) active=\(.active)"' 2>/dev/null
```

### Tertiary: Git Log Anomalies

```bash
# Check for force pushes (refs changed without merge)
cd ~/projects/claude-peers
git reflog --all --date=iso | head -20

# Check for unexpected branches
git branch -a

# Check remote URLs (should only point to the private repo)
git remote -v
```

---

## Immediate Triage (0-5 minutes)

### Step 1: Verify repository visibility

```bash
# Must be "private"
gh repo view your-github-org/sontara-lattice --json visibility -q '.visibility'
```

### Step 2: Check for unauthorized forks or clones

```bash
# Forks
gh api repos/your-github-org/sontara-lattice/forks -q 'length'

# Recent clone/fetch traffic
gh api repos/your-github-org/sontara-lattice/traffic/clones \
  -q '.clones[] | "\(.timestamp) unique=\(.uniques) total=\(.count)"' 2>/dev/null
```

### Step 3: Check organization audit log for suspicious actions

```bash
gh api "/orgs/your-github-org/audit-log?phrase=repo:your-github-org/sontara-lattice" \
  --paginate \
  -q '.[] | "\(.created_at) \(.action) actor=\(.actor) ip=\(.actor_ip)"' 2>/dev/null | head -30
```

### Step 4: If repo was made public, make it private immediately

```bash
gh repo edit your-github-org/sontara-lattice --visibility private
```

---

## Investigation

### Determine the scope of exposure

```bash
# How long was the repo public (if visibility was changed)?
gh api "/orgs/your-github-org/audit-log?phrase=repo:your-github-org/sontara-lattice+action:repo.access" \
  --paginate \
  -q '.[] | "\(.created_at) \(.action) \(.actor)"' 2>/dev/null

# Were there any clones during the exposure window?
gh api repos/your-github-org/sontara-lattice/traffic/clones 2>/dev/null

# Were there forks created during the exposure window?
gh api repos/your-github-org/sontara-lattice/forks \
  -q '.[] | "\(.created_at) \(.full_name) \(.owner.login)"' 2>/dev/null
```

### Check for leaked GitHub tokens

```bash
# Search for tokens in the repo history
cd ~/projects/claude-peers
git log -p --all -- '*.env' '*.env.*' '.env.*' 2>/dev/null | grep -iE 'token|key|secret|password' | head -20

# Check GitHub's secret scanning alerts
gh api repos/your-github-org/sontara-lattice/secret-scanning/alerts \
  -q '.[] | "\(.created_at) \(.secret_type) state=\(.state)"' 2>/dev/null
```

### Check for unauthorized access to the repo

```bash
# Check GitHub personal access tokens
# (requires going to github.com/settings/tokens -- no CLI equivalent)

# Check GitHub SSH keys
gh api /user/keys -q '.[] | "\(.id) \(.title) created=\(.created_at)"'

# Check GitHub OAuth apps with access
gh api /user/installations -q '.installations[] | "\(.id) \(.app_slug) permissions=\(.permissions | keys)"' 2>/dev/null
```

---

## Containment

### Step 1: Make repo private if it was changed to public

```bash
gh repo edit your-github-org/sontara-lattice --visibility private
```

### Step 2: Remove unauthorized collaborators

```bash
# List current collaborators
gh api repos/your-github-org/sontara-lattice/collaborators \
  -q '.[] | "\(.login) \(.permissions)"'

# Remove unauthorized collaborator
# gh api -X DELETE repos/your-github-org/sontara-lattice/collaborators/<username>
```

### Step 3: Delete unauthorized forks

```bash
# Forks owned by the org can be deleted. External forks cannot be deleted by repo owners.
# For external forks: contact GitHub support for DMCA takedown.
gh api repos/your-github-org/sontara-lattice/forks \
  -q '.[] | "\(.full_name) \(.owner.login)"'
```

### Step 4: Revoke compromised GitHub tokens

Go to:
- https://github.com/settings/tokens (personal access tokens)
- https://github.com/settings/applications (OAuth apps)
- https://github.com/settings/keys (SSH keys)

Revoke any tokens that may have been used to access the repo.

---

## Recovery

### Step 1: Rotate all secrets mentioned in the repository

The repository contains or references these secrets:

| Secret | Location in Repo | Rotation Method |
|--------|-----------------|-----------------|
| Tailscale IPs | Playbooks, CLAUDE.md, config defaults | Cannot rotate IPs. Tailscale ACLs provide network-level isolation. |
| Broker URL pattern | config.go defaults, docs | The port (7899) is well-known. Changing it requires fleet-wide config update. |
| Wazuh rule IDs | wazuh/local_rules.xml | Rule IDs themselves are not secrets, but the attacker now knows detection thresholds. Update rules to be less predictable. |
| NATS token pattern | config.go | Rotate NATS auth token on broker-server and all agents |
| LLM API key pattern | config.go | Rotate LiteLLM API keys |
| Machine hostnames | Throughout | Cannot change. Consider Tailscale ACL tightening. |

### Step 2: Address exposed monitoring gaps

The playbooks document specific gaps. If the attacker has the playbooks, they know these gaps. Prioritize closing them:

1. **Fix .db FIM ignore** (DATABASE_EXFIL gap)
2. **Add Syncthing config monitoring** (SYNCTHING_EXFIL gap)
3. **Add fleet memory content validation** (FLEET_MEMORY_POISONING gap)
4. **Add message content scanning** (PEER_MESSAGE_EXFIL gap)
5. **Add outbound SSH monitoring** (SSH_TUNNEL_EXFIL gap)
6. **Add input device monitoring** (CLIPBOARD_KEYLOG gap)

### Step 3: Consider changing detection thresholds

If the attacker knows your Wazuh rules fire at specific levels and frequencies, consider:
- Lowering thresholds for critical rules
- Adding new rules that the attacker doesn't know about
- Adding decoy rules that create noise for an attacker testing detection boundaries

### Step 4: Update the repository

After rotating secrets and closing gaps:
- Update playbooks to reflect new procedures
- Remove any hardcoded secrets from the repository
- Consider splitting security-sensitive documentation (Wazuh rules, monitoring gaps) into a separate, more restricted repository

---

## Decision Tree

```
Repository exfiltration suspected
|
+-- How was it detected?
|   +-- GitHub audit log shows visibility change
|   +-- Unauthorized fork detected
|   +-- Attacker demonstrates knowledge of fleet internals
|   +-- GitHub secret scanning alert
|   +-- Traffic spike on repo clone metrics
|
+-- Is the repo currently exposed?
|   +-- Public visibility: make private immediately
|   +-- Unauthorized collaborator: remove immediately
|   +-- Unauthorized fork: DMCA takedown request
|   +-- Leaked GitHub token: revoke immediately
|
+-- Was the repo cloned or just viewed?
|   +-- Cloned (full history): attacker has everything, including git history
|   |   +-- Rotate ALL secrets referenced in the repo
|   |   +-- Close ALL documented monitoring gaps ASAP
|   |   +-- Consider changing Wazuh rule thresholds
|   |
|   +-- Viewed (web only): attacker has current file content but not full history
|       +-- Same rotation requirements but lower urgency for historical secrets
|
+-- Was the leak via GitHub or local filesystem?
    +-- GitHub: fix access controls, revoke tokens, check audit log
    +-- Local (SSH, Syncthing): see SYNCTHING_EXFIL or LATERAL_MOVEMENT playbooks
    +-- Compromised Claude session: check what files were read via Bash/Read tools
```

---

## Monitoring Gaps

| Gap | Severity | Status | Remediation |
|-----|----------|--------|-------------|
| **No automated GitHub audit log monitoring** | **HIGH** | NOT IMPLEMENTED | Set up a scheduled check of the GitHub audit log for repo.access, repo.visibility_change, and fork events |
| **No GitHub clone traffic alerts** | **MEDIUM** | NOT IMPLEMENTED | Monitor the traffic/clones API endpoint for unusual activity |
| **No git remote URL verification** | **LOW** | NOT IMPLEMENTED | Periodic check that `git remote -v` on local checkouts points only to the expected GitHub URL |
| **Security docs co-located with code** | **MEDIUM** | ARCHITECTURAL | Monitoring gaps and Wazuh rules live in the same repo as the code. Consider separation. |

---

## Hardening Recommendations

1. **Enable GitHub audit log streaming.** Stream the org audit log to a monitoring system that alerts on repo visibility changes, new collaborators, new forks, and unusual clone activity.

2. **Restrict repo access.** Minimize the number of GitHub accounts with access. Use branch protection rules. Require code review for changes to `wazuh/` and `docs/playbooks/`.

3. **Separate security documentation.** Consider moving Wazuh rules, monitoring gap documentation, and detailed playbook procedures to a separate, more restricted repository. The main repo can reference them without containing them.

4. **Git secret scanning.** Enable GitHub secret scanning and push protection. This catches accidentally committed credentials before they enter the repository.

5. **Monitor git clone traffic.** Set up a scheduled job that checks `gh api repos/.../traffic/clones` and alerts on unexpected clone counts.

6. **Rotate secrets periodically.** Establish a rotation schedule for NATS tokens, LLM API keys, and UCAN tokens regardless of incidents. This limits the value of any stolen credentials.

7. **Consider threat model evolution.** Once an attacker has the repo, your detection rules are known. Build defense-in-depth: multiple independent detection mechanisms for the same attack, so that knowing one rule doesn't help evade the others.
