# Wazuh Manager Compromise Incident Response Playbook

**System:** Sontara Lattice (claude-peers) fleet
**Last updated:** 2026-03-28
**Audience:** the operator (fleet operator)
**Severity tier:** Tier 3 (Approval Required) -- security monitoring infrastructure compromise

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

### What the Wazuh Manager is

The Wazuh manager runs as a Docker container (`wazuh-manager`) on broker-server. It is the central security monitoring hub for the fleet:

- **Receives agent data** from all fleet machines via port 1514 (agent registration) and 1515 (enrollment)
- **Processes alerts** and writes to `/var/ossec/logs/alerts/alerts.json` (mounted at `~/docker/wazuh/logs/alerts/alerts.json` on the host)
- **Runs FIM** (file integrity monitoring) via agents on each machine
- **Applies custom rules** (`local_rules.xml`) that detect credential theft, binary tampering, persistence, etc.
- **Exposes a REST API** on port 55000 (username: `wazuh-api`, password: `Fl33tW4tch.2026Xr`)

### Current network exposure

| Port | Protocol | Purpose | Bound To | Accessible From |
|------|----------|---------|----------|----------------|
| 1514 | TCP | Agent communication | 0.0.0.0 (Docker) | Any Tailscale peer, any local process |
| 1515 | TCP | Agent enrollment | 0.0.0.0 (Docker) | Any Tailscale peer, any local process |
| 514 | UDP | Syslog | 0.0.0.0 (Docker) | Any Tailscale peer, any local process |
| 55000 | TCP | **REST API** | **0.0.0.0 (Docker)** | **Any Tailscale peer** -- should be localhost only |

The Wazuh API on port 55000 is currently exposed to the entire Tailscale mesh. Any device on the mesh can authenticate with `wazuh-api` / `Fl33tW4tch.2026Xr` and access the full API. This is a significant exposure that should be restricted.

### Attack scenarios

**Scenario 1: Attacker gains Wazuh API access**

The attacker knows or discovers the API credentials (hardcoded password, exposed in this doc, in docker-compose.yml `.env`).

With API access they can:
- **Suppress alerts**: Modify rules, disable specific rule IDs, change alert levels
- **Inject false alerts**: Create fake alerts that trigger quarantine of legitimate machines
- **Read agent data**: System inventory, vulnerability scans, FIM baselines, network listeners
- **Enumerate the fleet**: List all agents, their IPs, OS versions, registration status
- **Disable agents**: Deregister agents, stopping monitoring on specific machines
- **Trigger active response**: Execute commands on agents (if active response is configured)
- **Modify decoders**: Change how logs are parsed, creating blind spots

**Scenario 2: Attacker compromises the Docker container**

If the attacker gets shell access to the `wazuh-manager` container (via Docker socket access, container escape, or Wazuh vulnerability):
- Everything in Scenario 1, PLUS:
- **Direct file access**: Read/modify `/var/ossec/etc/rules/local_rules.xml` directly
- **Access agent keys**: Read shared keys in `/var/ossec/etc/client.keys` -- could impersonate any agent
- **Modify the alerts log**: Delete or alter historical alerts in `alerts.json`
- **Access the agent queue**: Read or inject messages in the agent communication queue
- **Pivot to host**: If the Docker socket is mounted or the container has host networking

**Scenario 3: Attacker compromises a Wazuh agent**

If an agent on a fleet machine is compromised:
- **Send false data**: Report fake FIM results, masking actual changes
- **Suppress local events**: Modify the local agent config to ignore specific paths
- **Consume agent resources**: Cause the agent to use excessive CPU/memory
- The agent CANNOT directly access the manager API or other agents (agent-to-manager communication is one-way)

### Impact on the Sontara Lattice security pipeline

```
Wazuh Agent (compromised) --> sends false/no data
    |
    v
Wazuh Manager (compromised) --> suppresses alerts, injects false ones
    |
    v
alerts.json (tampered) --> wazuh-bridge reads tampered data
    |
    v
NATS fleet.security.* --> false events published
    |
    v
Broker machine health --> legitimate machines quarantined, attackers invisible
    |
    v
Security Watch --> correlations based on false data
    |
    v
Response Daemon --> wrong machines get forensic captures, wrong IPs blocked
```

A compromised Wazuh manager means the entire security monitoring pipeline is untrustworthy. Every decision downstream is based on potentially false data.

---

## Detection

### What We CAN Detect Today

| Signal | Source | Automated? |
|--------|--------|------------|
| Docker container health check | Docker daemon | If configured (currently uncertain) |
| wazuh-bridge loses connection to alerts.json | Bridge logs | Yes -- bridge logs errors and retries |
| Wazuh agent disconnection alerts | Wazuh itself (if manager is up) | Yes -- but compromised manager could suppress this |
| FIM on local_rules.xml (if the file is on host) | Wazuh FIM on host | No -- rules file is inside the container, not on monitored host path |
| Gaps in alert flow (no alerts for extended period) | Manual observation | No |

### What We CANNOT Detect Today

| Gap | Risk | Priority |
|-----|------|----------|
| **Wazuh API access from Tailscale peers** | Any fleet machine can hit port 55000 | **P0** |
| **No monitoring of Wazuh API access logs** | Unauthorized API calls go unnoticed | **P0** |
| **No rule integrity checking** | Attacker modifies local_rules.xml inside container, no detection | **P1** |
| **No alert volume baseline** | Cannot detect "alert suppression" (fewer alerts than expected) | **P1** |
| **No Docker container integrity monitoring** | Container modified at runtime, no detection | **P1** |
| **No agent key integrity monitoring** | Agent shared keys in container could be copied | **P2** |
| **Active response not audited** | Commands executed via active response are not logged to NATS | **P1** |

---

## Immediate Triage (0-5 minutes)

### Step 1: Check container health

```bash
# Is the container running?
ssh broker-server "docker ps | grep wazuh"

# Container logs (last 50 lines)
ssh broker-server "docker logs wazuh-manager --tail 50"

# Resource usage
ssh broker-server "docker stats wazuh-manager --no-stream"
```

### Step 2: Check Wazuh API accessibility

```bash
# Test API access with known credentials
ssh broker-server "curl -sk -u wazuh-api:Fl33tW4tch.2026Xr https://127.0.0.1:55000/security/user/authenticate 2>/dev/null | head -c 200"

# Check if port 55000 is accessible from the Tailscale interface
# From workstation:
curl -sk -u wazuh-api:Fl33tW4tch.2026Xr https://<broker-ip>:55000/security/user/authenticate 2>/dev/null | head -c 200
# If this returns a JWT: the API is exposed to the mesh (CURRENT STATE -- this is the gap)
```

### Step 3: Check rule integrity

```bash
# Compare local_rules.xml inside the container against the git version
ssh broker-server "docker exec wazuh-manager cat /var/ossec/etc/rules/local_rules.xml" > /tmp/container-rules.xml
diff /tmp/container-rules.xml ~/projects/claude-peers/wazuh/local_rules.xml
# Any differences = investigate immediately
```

### Step 4: Check agent status

```bash
# List all connected agents
ssh broker-server "docker exec wazuh-manager /var/ossec/bin/agent_control -l"

# Expected agents:
# 001 - workstation
# 002 - edge-node
# 003 - workstation-2
# 004 - laptop-1
# (iot-device may not have an agent -- uses AIDE sentinel instead)

# Any unknown agents = unauthorized enrollment
# Any missing agents = possible agent suppression
```

### Step 5: Check alert flow

```bash
# Is the wazuh-bridge still publishing?
ssh broker-server "journalctl --user -u claude-peers-wazuh-bridge --since '10 min ago' --no-pager | tail -10"

# Are alerts still flowing?
ssh broker-server "tail -5 ~/docker/wazuh/logs/alerts/alerts.json | jq .timestamp"
# Check that timestamps are recent (within the last few minutes)

# If no recent alerts, check if Wazuh is processing:
ssh broker-server "docker exec wazuh-manager /var/ossec/bin/wazuh-control status"
```

---

## Containment

### Step 1: Isolate the Wazuh API

Immediately block API access from the network. The API should only be accessible from localhost.

```bash
# Block port 55000 from everything except localhost
ssh broker-server "sudo iptables -A INPUT -p tcp --dport 55000 ! -i lo -j DROP"

# Verify the block
curl -sk --connect-timeout 3 https://<broker-ip>:55000/ 2>&1
# Should timeout or refuse connection
```

### Step 2: If the container is actively compromised, stop it

```bash
# Stop the container
ssh broker-server "docker stop wazuh-manager"

# At this point, Wazuh monitoring is DOWN for all agents.
# Agents will buffer events and re-send when the manager comes back.
# The wazuh-bridge will log connection errors but will not crash.
```

### Step 3: Preserve the container state for forensics

```bash
# Create a snapshot of the container before destroying it
ssh broker-server "docker commit wazuh-manager wazuh-manager-forensic-$(date +%Y%m%d)"

# Save the alerts log
ssh broker-server "cp -r ~/docker/wazuh/logs ~/docker/wazuh/logs-forensic-$(date +%Y%m%d)"
```

### Step 4: Check if the attacker pivoted to the host

The Wazuh container has volume mounts. Check if the attacker modified host files through the mounts:

```bash
# The only host path mount is ./logs:/var/ossec/logs
# Check if anything unexpected was written there
ssh broker-server "find ~/docker/wazuh/logs -newer ~/docker/wazuh/logs/alerts/alerts.json -type f 2>/dev/null"

# Check if the Docker socket was mounted (it should NOT be)
ssh broker-server "docker inspect wazuh-manager | jq '.[0].Mounts[] | select(.Source | test(\"docker.sock\"))'"
# This should return nothing. If it returns a mount, the attacker could have escaped the container.
```

---

## Investigation

### Was the API accessed?

```bash
# Wazuh API access logs are inside the container
ssh broker-server "docker exec wazuh-manager cat /var/ossec/logs/api.log 2>/dev/null | tail -50"
# Or if the container is stopped, check the forensic snapshot

# Look for:
# - Requests from non-localhost IPs
# - PUT/POST requests to /rules, /decoders, /agents (modification attempts)
# - DELETE requests (agent deregistration, rule deletion)
# - Multiple authentication attempts (brute force on API)
```

### Were rules modified?

```bash
# Get the current rules from the container (or forensic snapshot)
ssh broker-server "docker exec wazuh-manager cat /var/ossec/etc/rules/local_rules.xml" > /tmp/current-rules.xml

# Compare against the canonical version in git
diff /tmp/current-rules.xml ~/projects/claude-peers/wazuh/local_rules.xml

# Check rule modification timestamps inside the container
ssh broker-server "docker exec wazuh-manager stat /var/ossec/etc/rules/local_rules.xml"

# Check if any default rules were also modified
ssh broker-server "docker exec wazuh-manager find /var/ossec/ruleset/rules/ -newer /var/ossec/etc/rules/local_rules.xml -type f 2>/dev/null"
```

### Were agents tampered with?

```bash
# Check agent registration keys
ssh broker-server "docker exec wazuh-manager cat /var/ossec/etc/client.keys"
# Verify each agent ID and name matches expected fleet machines

# Check for agents that were added without your knowledge
# Compare against your expected list:
# ID  Name          IP
# 001 workstation       <workstation-ip>
# 002 edge-node      (edge-node Tailscale IP)
# 003 workstation-2     <workstation-2-ip>
# 004 laptop-1      <laptop-1-ip>

# Check agent group assignments (should all be 'default')
ssh broker-server "docker exec wazuh-manager /var/ossec/bin/agent_groups -l"
```

### Was the alerts log tampered with?

```bash
# Check for gaps in the alert timeline
ssh broker-server "tail -100 ~/docker/wazuh/logs/alerts/alerts.json | jq -r '.timestamp' | head -20"
# Look for unexplained gaps (>5 minutes without any alert from any agent)

# Check alert file integrity
ssh broker-server "ls -la ~/docker/wazuh/logs/alerts/alerts.json"
# Check file size -- a sudden decrease suggests truncation

# Compare alert volume against baseline (if you have one)
ssh broker-server "wc -l ~/docker/wazuh/logs/alerts/alerts.json"
```

### Was active response used?

```bash
# Check if active response commands were executed
ssh broker-server "docker exec wazuh-manager cat /var/ossec/logs/active-responses.log 2>/dev/null"

# Check each agent for evidence of active response execution
for host in <workstation-ip> edge-node <workstation-2-ip> "<user>@<laptop-1-ip><laptop-1-ip>"; do
  echo "=== $host ==="
  ssh $host "cat /var/ossec/logs/active-responses.log 2>/dev/null || echo 'no active response log'"
done
```

---

## Recovery

### Step 1: Rebuild the Wazuh container from scratch

Do NOT restart the potentially compromised container. Rebuild from the known-good image.

```bash
ssh broker-server

# Remove the compromised container (forensic snapshot already saved)
cd ~/docker/wazuh
docker compose down

# Remove all Wazuh volumes (they may be tampered)
docker volume rm wazuh_api_configuration wazuh_etc wazuh_queue wazuh_var_multigroups wazuh_integrations wazuh_active_response wazuh_agentless wazuh_wodles 2>/dev/null

# Pull a fresh image
docker compose pull

# Start fresh
docker compose up -d

# Wait for startup
sleep 30

# Verify the manager is running
docker exec wazuh-manager /var/ossec/bin/wazuh-control status
```

### Step 2: Deploy known-good custom rules from git

```bash
ssh broker-server "docker cp ~/projects/claude-peers/wazuh/local_rules.xml wazuh-manager:/var/ossec/etc/rules/local_rules.xml"
ssh broker-server "docker exec wazuh-manager /var/ossec/bin/wazuh-control restart"
```

### Step 3: Deploy shared agent config

```bash
ssh broker-server "docker exec wazuh-manager bash -c 'cat > /var/ossec/etc/shared/default/agent.conf << AGENTEOF
<agent_config>
  <syscheck>
    <disabled>no</disabled>
    <frequency>300</frequency>
    <scan_on_start>yes</scan_on_start>
    <alert_new_files>yes</alert_new_files>
    <directories check_all=\"yes\" realtime=\"yes\" report_changes=\"yes\">~/.config/claude-peers</directories>
    <directories check_all=\"yes\" realtime=\"yes\">~/.ssh</directories>
    <directories check_all=\"yes\" realtime=\"yes\">~/.local/bin</directories>
    <directories check_all=\"yes\">/usr/local/bin</directories>
    <directories check_all=\"yes\">/etc/systemd/system</directories>
    <directories check_all=\"yes\">~/.config/systemd/user</directories>
    <ignore type=\"sregex\">.log$</ignore>
    <ignore type=\"sregex\">.db$</ignore>
    <ignore type=\"sregex\">.db-journal$</ignore>
  </syscheck>
</agent_config>
AGENTEOF'"
```

### Step 4: Rotate the Wazuh API password

```bash
NEW_WAZUH_PASS="$(openssl rand -base64 24)"
echo "New Wazuh password: $NEW_WAZUH_PASS"

# Update .env
ssh broker-server "cd ~/docker/wazuh && echo 'WAZUH_API_PASSWORD=$NEW_WAZUH_PASS' > .env"

# Restart to apply
ssh broker-server "cd ~/docker/wazuh && docker compose down && docker compose up -d"
sleep 30

# Verify new password works
ssh broker-server "curl -sk -u wazuh-api:$NEW_WAZUH_PASS https://127.0.0.1:55000/security/user/authenticate | head -c 100"
```

### Step 5: Re-enroll all agents

If agent keys were potentially compromised, re-enroll all agents:

```bash
# On each fleet machine, re-register the agent
# Ubuntu/Debian:
ssh edge-node "sudo /var/ossec/bin/agent-auth -m <broker-ip>"
ssh edge-node "sudo systemctl restart wazuh-agent"

# Arch:
ssh <workstation-ip> "sudo /var/ossec/bin/agent-auth -m <broker-ip>"
ssh <workstation-ip> "sudo systemctl restart wazuh-agent"

# macOS:
ssh <user>@<laptop-1-ip><laptop-1-ip> "sudo /Library/Ossec/bin/agent-auth -m <broker-ip>"
ssh <user>@<laptop-1-ip><laptop-1-ip> "sudo /Library/Ossec/bin/wazuh-control restart"

# Verify all agents are connected
ssh broker-server "docker exec wazuh-manager /var/ossec/bin/agent_control -l"
```

### Step 6: Fix log permissions

```bash
ssh broker-server "docker exec wazuh-manager chmod -R o+r /var/ossec/logs/alerts/"
ssh broker-server "docker exec wazuh-manager chmod o+x /var/ossec/logs /var/ossec/logs/alerts"
```

### Step 7: Restart the wazuh-bridge

```bash
ssh broker-server "systemctl --user restart claude-peers-wazuh-bridge"

# Verify bridge is tailing alerts
ssh broker-server "journalctl --user -u claude-peers-wazuh-bridge --since '1 min ago' --no-pager | tail -5"
```

### Step 8: Validate the full pipeline

```bash
# Create a test FIM event
ssh broker-server "touch ~/.config/claude-peers/test-wazuh-recovery"

# Wait for detection (30-60 seconds)
sleep 60

# Check bridge received it
ssh broker-server "journalctl --user -u claude-peers-wazuh-bridge --since '2 min ago' --no-pager | grep test-wazuh"

# Check machine health updated
curl -s http://<broker-ip>:7899/machine-health \
  -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt)" | jq .

# Clean up
ssh broker-server "rm ~/.config/claude-peers/test-wazuh-recovery"
```

---

## Post-Incident Hardening

### Restrict Wazuh API to localhost (CRITICAL -- do this now)

The API should never be accessible from the Tailscale mesh.

**Option 1: iptables (immediate)**

```bash
ssh broker-server "sudo iptables -A INPUT -p tcp --dport 55000 ! -i lo -j DROP"
ssh broker-server "sudo apt install -y iptables-persistent && sudo netfilter-persistent save"
```

**Option 2: Docker port binding (permanent)**

Modify the docker-compose.yml to only bind port 55000 to localhost:

```yaml
ports:
  - "1514:1514"
  - "1515:1515"
  - "514:514/udp"
  - "127.0.0.1:55000:55000"   # Changed from "55000:55000"
```

Then recreate:
```bash
ssh broker-server "cd ~/docker/wazuh && docker compose down && docker compose up -d"
```

### Monitor Wazuh API access logs

Add a cron job or systemd timer that checks the API log for unauthorized access:

```bash
# Simple monitoring script
ssh broker-server "cat > ~/.local/bin/check-wazuh-api-log.sh << 'SCRIPT'
#!/bin/bash
# Check for non-localhost API access
docker exec wazuh-manager cat /var/ossec/logs/api.log 2>/dev/null | \
  grep -v '127.0.0.1' | \
  grep -v 'localhost' | \
  tail -10
SCRIPT
chmod +x ~/.local/bin/check-wazuh-api-log.sh"
```

### Implement rule integrity checking

Periodically compare the in-container rules against the git source of truth:

```bash
# Add to a cron job or monitoring script
ssh broker-server "docker exec wazuh-manager cat /var/ossec/etc/rules/local_rules.xml | md5sum"
# Compare against: md5sum ~/projects/claude-peers/wazuh/local_rules.xml
# Alert if different
```

### Add alert volume monitoring

Establish a baseline of expected alert volume and alert when it drops significantly:

```bash
# Count alerts per hour -- if fewer than expected, Wazuh may be suppressed
ssh broker-server "wc -l ~/docker/wazuh/logs/alerts/alerts.json"
# Baseline this daily and alert on significant drops
```

### Docker security hardening

```bash
# Verify Docker socket is NOT mounted into the container
ssh broker-server "docker inspect wazuh-manager | jq '.[0].Mounts[].Source'"
# Should only show named volumes and ./logs, NOT /var/run/docker.sock

# Set container to read-only filesystem (where possible)
# Add to docker-compose.yml:
# read_only: true
# tmpfs:
#   - /tmp
#   - /var/ossec/queue

# Limit container capabilities
# Add to docker-compose.yml:
# cap_drop:
#   - ALL
# cap_add:
#   - NET_BIND_SERVICE
```

### Use a stronger API password

The current password (`Fl33tW4tch.2026Xr`) appears in documentation and may be in commit history. After rotation, use a randomly generated password and store it only in the `.env` file:

```bash
# Generate and store
NEW_PASS="$(openssl rand -base64 32)"
ssh broker-server "echo 'WAZUH_API_PASSWORD=$NEW_PASS' > ~/docker/wazuh/.env && chmod 600 ~/docker/wazuh/.env"
```

---

## Monitoring Gaps

| Gap | Impact | Current State | Fix Priority |
|-----|--------|--------------|-------------|
| **Wazuh API exposed on port 55000 to Tailscale mesh** | Any fleet machine can authenticate and modify rules | Port bound to 0.0.0.0 | **P0** -- bind to 127.0.0.1 |
| **No Wazuh API access log monitoring** | Unauthorized API access goes unnoticed | Logs exist in container but are not monitored | **P0** |
| **No rule integrity checking** | Attacker modifies rules to suppress alerts | No comparison against git source | **P1** |
| **No alert volume baseline** | Alert suppression (fewer alerts than expected) is invisible | No monitoring | **P1** |
| **No Docker container integrity monitoring** | Runtime modifications to container go undetected | No monitoring | **P1** |
| **Agent keys in container are not monitored** | Attacker could copy client.keys to impersonate agents | No FIM on container internals | **P2** |
| **Active response not audited** | Commands executed via Wazuh AR are not published to NATS | No monitoring | **P1** |
| **Wazuh API password in documentation/commits** | Password is discoverable in repo history | Password appears in multiple places | **P1** -- rotate and remove from docs |

---

## Quick Reference Card

```
WAZUH MANAGER COMPROMISE DETECTED OR SUSPECTED
    |
    +-- Is the container running?
    |     docker ps | grep wazuh
    |
    +-- Check API accessibility from mesh
    |     curl -sk https://<broker-ip>:55000/...
    |     If accessible: BLOCK PORT 55000 IMMEDIATELY
    |     iptables -A INPUT -p tcp --dport 55000 ! -i lo -j DROP
    |
    +-- Compare rules against git
    |     docker exec wazuh-manager cat local_rules.xml
    |     diff against ~/projects/claude-peers/wazuh/local_rules.xml
    |     Differences = rules tampered
    |
    +-- Check agent list
    |     docker exec wazuh-manager agent_control -l
    |     Unknown agents = unauthorized enrollment
    |
    +-- STOP the container (preserve first)
    |     docker commit wazuh-manager wazuh-manager-forensic-$(date +%Y%m%d)
    |     docker stop wazuh-manager
    |
    +-- REBUILD from scratch
    |     docker compose down
    |     Remove volumes
    |     docker compose up -d
    |     Redeploy rules from git
    |     Redeploy agent config
    |     Rotate API password
    |     Re-enroll all agents
    |
    +-- VALIDATE the pipeline
    |     Touch a test file in a monitored path
    |     Verify wazuh-bridge publishes the event
    |     Verify broker machine health updates
    |
    +-- HARDEN
          Bind port 55000 to 127.0.0.1
          Monitor API access logs
          Periodic rule integrity checks
          Alert volume baseline
```
