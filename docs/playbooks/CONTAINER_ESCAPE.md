# Container Escape Incident Response Playbook

Sontara Lattice fleet -- last updated 2026-03-28.

**Tier:** 3 (Approval) -- container escape gives root on broker-server, which hosts the broker, NATS, all daemons, and the Wazuh manager. This is a full infrastructure compromise.

**Current Detection: LIMITED** -- Docker service health is monitored via fleet-scout, but container security (capabilities, mounts, socket exposure, escape attempts) is NOT monitored. This is a critical gap.

**Affected machine:** broker-server (<broker-ip>) -- the only machine running Docker.

**Containers on broker-server:**
| Container | Image | Purpose | Risk Level |
|-----------|-------|---------|------------|
| wazuh-manager | wazuh/wazuh-manager | Wazuh alert processing, agent management | HIGH -- has host volume mounts |
| wazuh-indexer | wazuh/wazuh-indexer | Elasticsearch for Wazuh data | MEDIUM |
| wazuh-dashboard | wazuh/wazuh-dashboard | Wazuh web UI | LOW |
| litellm | LiteLLM proxy | LLM routing for all daemons | MEDIUM -- sees all prompts |

---

## Attack Surface

### Docker socket exposure

If the Docker socket (`/var/run/docker.sock`) is mounted into any container, that container can:
- Create new privileged containers
- Mount the host filesystem
- Execute commands on the host
- Effectively gain root on broker-server

```bash
# Check if any container has the Docker socket mounted
ssh broker-server "docker inspect --format '{{range .Mounts}}{{.Source}}:{{.Destination}} {{end}}' \$(docker ps -q)" 2>/dev/null
```

### Host volume mounts

The Wazuh manager container has host filesystem mounts for log access:
- `/opt/wazuh-data/logs/` -- Wazuh logs (read by wazuh-bridge)
- Potentially other mounts for agent configs, rules, etc.

If the container can write to host paths, an attacker inside the container can:
- Modify host files (crontabs, systemd units, shell profiles)
- Place malicious binaries on the host
- Modify the wazuh-bridge's alerts.json to inject fake alerts or suppress real ones

### Privileged containers

A container running with `--privileged` has:
- All Linux capabilities
- Access to all host devices
- No seccomp restrictions
- Can mount the host filesystem via `/dev/sda*`
- Can load kernel modules
- Can modify host network configuration

### Kernel exploits

Container isolation relies on Linux namespaces and cgroups. Kernel vulnerabilities can break this isolation:
- Dirty Pipe (CVE-2022-0847) -- write to arbitrary files from unprivileged container
- OverlayFS exploits -- escape via overlayfs on the host
- cgroup escape -- break out of cgroup namespace

broker-server runs Ubuntu 24.04. Check kernel version:
```bash
ssh broker-server "uname -r"
```

### Network-level escape

Containers on the default bridge network can:
- Access the host network on the docker0 interface
- Reach the NATS server (port 4222) on the host
- Reach the broker (port 7899) on the host
- Reach other containers' exposed ports

If a container is in `--network host` mode, it has full access to the host network stack including Tailscale.

---

## 1. Detection Signals

### Current detection capabilities

**fleet-scout health check:** The fleet-scout daemon checks Docker container status but does NOT audit container security. It would notice if a container is down, but not if it's been compromised.

**Wazuh on the host:** Wazuh agent on broker-server monitors host-level file changes but cannot see inside containers. FIM would trigger if the container escape results in host file modifications.

### Signals of container escape

- **Unexpected processes on the host:** A process running as root that doesn't belong to any known service
  ```bash
  ssh broker-server "ps auxf | grep -v '\[.*\]' | grep -viE 'docker|containerd|systemd|sshd|claude-peers|nats|ssh|cron|wazuh'"
  ```

- **Host filesystem access from container context:**
  ```bash
  ssh broker-server "docker logs wazuh-manager 2>&1 | grep -iE 'mount\|/host\|/proc/1\|nsenter'"
  ```

- **New Docker containers that shouldn't exist:**
  ```bash
  ssh broker-server "docker ps -a --format '{{.Names}}\t{{.Image}}\t{{.Status}}'"
  # Compare against expected: wazuh-manager, wazuh-indexer, wazuh-dashboard, litellm
  ```

- **Docker daemon audit logs:**
  ```bash
  ssh broker-server "journalctl -u docker --since '24 hours ago' --no-pager | grep -iE 'create\|exec\|privilege\|capability'"
  ```

- **Unexpected network connections from the host:**
  ```bash
  ssh broker-server "ss -tnp | grep -v '100\.\|127\.\|4222\|7899\|4000\|8888\|docker\|containerd'"
  ```

### What you receive (currently)

- **If the escape results in host file modifications:** Wazuh FIM may trigger, leading to broker alerts and email
- **If the escape is stealthy (memory-only, or modifying unmonitored paths):** Nothing

---

## 2. Immediate Triage (First 5 Minutes)

### Step 1: Check container status and configuration

```bash
# List all containers
ssh broker-server "docker ps -a --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'"

# Check for privileged containers
ssh broker-server "for c in \$(docker ps -q); do echo \"\$(docker inspect --format '{{.Name}} privileged={{.HostConfig.Privileged}}' \$c)\"; done"

# Check container capabilities
ssh broker-server "for c in \$(docker ps -q); do echo \"--- \$(docker inspect --format '{{.Name}}' \$c) ---\"; docker inspect --format '{{.HostConfig.CapAdd}}' \$c; done"

# Check volume mounts
ssh broker-server "for c in \$(docker ps -q); do echo \"--- \$(docker inspect --format '{{.Name}}' \$c) ---\"; docker inspect --format '{{range .Mounts}}{{.Type}}: {{.Source}} -> {{.Destination}} ({{.Mode}}){{println}}{{end}}' \$c; done"

# Check network mode
ssh broker-server "for c in \$(docker ps -q); do echo \"\$(docker inspect --format '{{.Name}} network={{.HostConfig.NetworkMode}}' \$c)\"; done"
```

### Step 2: Check for Docker socket exposure

```bash
ssh broker-server "for c in \$(docker ps -q); do docker inspect --format '{{.Name}} {{range .Mounts}}{{if eq .Destination \"/var/run/docker.sock\"}}DOCKER_SOCKET_MOUNTED{{end}}{{end}}' \$c; done"
```

If any container shows `DOCKER_SOCKET_MOUNTED`, that container can control the host. This is a critical finding.

### Step 3: Check for escape indicators

```bash
# Processes running outside containers but started recently
ssh broker-server "ps auxf --sort=-start_time | head -30"

# Check for nsenter usage (common escape technique)
ssh broker-server "journalctl --since '24 hours ago' --no-pager | grep nsenter"

# Check for unexpected Docker exec calls
ssh broker-server "journalctl -u docker --since '24 hours ago' --no-pager | grep -i exec"

# Check Docker events
ssh broker-server "docker events --since 24h --until 0s --filter type=container 2>/dev/null | tail -50"
```

### Decision point

| Finding | Action |
|---------|--------|
| No privileged containers, no socket mounts, no suspicious processes | Container escape unlikely. Investigate other vectors. |
| Docker socket mounted in a container | Critical vulnerability. Assume escape is possible/happened. Proceed to containment. |
| Privileged container found | Critical vulnerability. Audit that container immediately. |
| Unknown container running | Active escape in progress. Contain immediately. |
| Host processes with container-related parent PIDs | Escape confirmed. Contain immediately. |

---

## 3. Containment

### If escape is confirmed or suspected

```bash
# Stop ALL containers
ssh broker-server "docker compose -f ~/docker/wazuh/docker-compose.yml down"
# Or if compose file location is different:
ssh broker-server "docker stop \$(docker ps -q) 2>/dev/null"

# WARNING: This takes down Wazuh manager. Fleet-wide detection is now degraded.
# The wazuh-bridge will lose its alert source.
# The security-watch and response-daemon still function via NATS but no new Wazuh alerts will flow.
```

### Kill any rogue containers

```bash
ssh broker-server "docker ps -a --format '{{.Names}}' | grep -viE 'wazuh|litellm'"
# If any unknown containers:
ssh broker-server "docker rm -f <container-name>"
```

### Block container network access if needed

```bash
# Drop all traffic from Docker networks to host services
ssh broker-server "sudo iptables -I INPUT -i docker0 -j DROP"
ssh broker-server "sudo iptables -I INPUT -i br-+ -j DROP"
```

### Impact of containment

When Docker is stopped on broker-server:
- **Wazuh manager down:** No new alerts from any fleet machine. Agents will queue alerts locally and send when the manager is back.
- **LiteLLM down:** All daemons lose LLM access. The supervisor will report failures but daemons won't crash.
- **Wazuh dashboard down:** No web UI for alert review.
- **Broker, NATS, claude-peers services unaffected:** These run as systemd user services, not in Docker.

---

## 4. Investigation

### Audit Docker compose configuration

```bash
ssh broker-server "cat ~/docker/wazuh/docker-compose.yml"
# Check for:
# - privileged: true
# - volumes mounting /var/run/docker.sock
# - volumes mounting sensitive host paths (/, /etc, /home, /root)
# - network_mode: host
# - cap_add with dangerous capabilities (SYS_ADMIN, SYS_PTRACE, NET_ADMIN)
# - security_opt: seccomp:unconfined
```

### Check container filesystem for modifications

```bash
# What files did the container modify (vs its base image)?
ssh broker-server "docker diff wazuh-manager 2>/dev/null"
# A = Added, C = Changed, D = Deleted
# Look for unexpected additions in /tmp, /var/tmp, or outside normal Wazuh paths
```

### Check for evidence of escape inside the container

```bash
# If the container is still running, exec into it to investigate
ssh broker-server "docker exec wazuh-manager bash -c 'ls /proc/1/root/ 2>/dev/null && echo HOST_ROOT_ACCESSIBLE || echo CONTAINED'"

# Check for tools used in escape
ssh broker-server "docker exec wazuh-manager bash -c 'which nsenter chroot mount 2>/dev/null'"

# Check container's process list for suspicious activity
ssh broker-server "docker exec wazuh-manager ps auxf 2>/dev/null"

# Check container's network connections
ssh broker-server "docker exec wazuh-manager ss -tnp 2>/dev/null"
```

### Check host for post-escape artifacts

```bash
# Modified files on host during the attack window
ssh broker-server "find /etc /usr/local/bin /home/user -mtime -1 -type f 2>/dev/null | head -30"

# New systemd services
ssh broker-server "systemctl list-unit-files --state=enabled --no-pager | diff - <(cat /path/to/known-good-services.txt)" 2>/dev/null

# New crontabs
ssh broker-server "crontab -l 2>/dev/null; sudo crontab -l 2>/dev/null"

# New SSH authorized keys
ssh broker-server "cat ~/.ssh/authorized_keys"

# Check if the broker or NATS was tampered with
ssh broker-server "sha256sum ~/.local/bin/claude-peers"
ssh broker-server "sha256sum /usr/local/bin/nats-server 2>/dev/null"
```

### Check Docker daemon logs

```bash
ssh broker-server "journalctl -u docker --since '48 hours ago' --no-pager | grep -iE 'error\|warn\|privilege\|capability\|mount\|exec'"
```

---

## 5. Eradication

### Rebuild containers with minimal privileges

```bash
# Review and harden the docker-compose.yml:
# 1. Remove privileged: true if present
# 2. Remove /var/run/docker.sock mounts
# 3. Add read_only: true where possible
# 4. Drop all capabilities and add back only what's needed:
#    cap_drop:
#      - ALL
#    cap_add:
#      - <only-what's-needed>
# 5. Use specific user, not root:
#    user: "1000:1000"
# 6. Add security_opt:
#    security_opt:
#      - no-new-privileges:true
# 7. Use network isolation:
#    networks:
#      - wazuh-internal  (not host mode)
```

### Clean up any post-escape artifacts on the host

```bash
# Remove unauthorized files, crontabs, systemd units, SSH keys
# See the General Recovery Checklist in INCIDENT_RESPONSE.md
```

### Restart containers with hardened configuration

```bash
ssh broker-server "docker compose -f ~/docker/wazuh/docker-compose.yml up -d"

# Verify containers started correctly
ssh broker-server "docker ps -a --format 'table {{.Names}}\t{{.Status}}'"

# Verify Wazuh agents reconnect
ssh broker-server "docker exec wazuh-manager /var/ossec/bin/agent_control -l"
```

### Remove iptables blocks if applied

```bash
ssh broker-server "sudo iptables -D INPUT -i docker0 -j DROP 2>/dev/null"
ssh broker-server "sudo iptables -D INPUT -i br-+ -j DROP 2>/dev/null"
```

---

## 6. Recovery

### Verify the full detection chain is operational

```bash
# Check wazuh-bridge is receiving alerts
ssh broker-server "journalctl --user -u sontara-wazuh-bridge --since '5 min ago' --no-pager | tail -10"

# Check broker health
curl -s http://<broker-ip>:7899/health | jq .

# Check NATS
ssh broker-server "NATS_URL='nats://<broker-ip>:4222' nats server check --token '<your-nats-token>'" 2>/dev/null

# Check all Wazuh agents
ssh broker-server "docker exec wazuh-manager /var/ossec/bin/agent_control -l"

# Trigger a test alert
# On any fleet machine, touch a monitored file:
ssh edge-node "touch ~/.config/claude-peers/test-alert-$(date +%s) && rm ~/.config/claude-peers/test-alert-*"
# Check if the alert flows through within 60 seconds
```

### If broker-server root was compromised

The attacker had root on the machine that hosts:
- **Broker:** The root UCAN key (`identity.pem` in `~/.config/claude-peers/`). If stolen, the attacker can mint tokens for any capability.
- **NATS server:** The NATS auth token. If stolen, the attacker can publish/subscribe to all fleet events.
- **Wazuh manager:** All fleet security data. The attacker can see what we monitor and don't monitor.
- **All daemon configs:** LLM API keys, fleet topology, SSH targets.

**Full credential rotation is required:**

```bash
# 1. Rotate broker root key
ssh broker-server "cd ~/.config/claude-peers && mv identity.pem identity.pem.compromised && mv root.pub root.pub.compromised"
ssh broker-server "claude-peers init broker"

# 2. Re-issue ALL fleet UCAN tokens
for machine in workstation edge-node workstation-2 laptop-1 iot-device; do
  ssh broker-server "claude-peers issue-token /path/to/${machine}-identity.pub peer-session"
done

# 3. Rotate NATS token
# Generate new token, update on all machines

# 4. Rotate LiteLLM API key
# Update in LiteLLM config and in all daemon agent.toml files

# 5. Rotate SSH keys on broker-server
ssh broker-server "ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ''"
```

---

## 7. Post-Incident Improvements

### Add Docker audit logging

```bash
# Enable Docker daemon audit in /etc/docker/daemon.json
{
  "log-driver": "journald",
  "log-opts": {
    "tag": "docker/{{.Name}}"
  }
}

# Add auditd rules for Docker
# /etc/audit/rules.d/docker.rules
-w /usr/bin/docker -p rwxa -k docker
-w /var/lib/docker -p rwxa -k docker
-w /etc/docker -p rwxa -k docker
-w /var/run/docker.sock -p rwxa -k docker
```

### Add Wazuh rules for container security

```xml
<!-- Add to local_rules.xml -->
<rule id="100150" level="12">
  <decoded_as>journald</decoded_as>
  <match type="pcre2">docker.*privileged.*true</match>
  <description>Privileged Docker container started on fleet machine</description>
  <group>docker,container_security,</group>
</rule>

<rule id="100151" level="13">
  <decoded_as>journald</decoded_as>
  <match type="pcre2">docker.*exec.*nsenter|docker.*exec.*chroot</match>
  <description>Suspicious Docker exec (possible container escape attempt)</description>
  <group>docker,container_escape,</group>
</rule>
```

### Implement container runtime security

Consider deploying Falco or Sysdig for container-specific security monitoring:
- Detects unexpected process execution inside containers
- Detects file access outside expected paths
- Detects network connections to unexpected destinations
- Detects privilege escalation attempts

### Principle of least privilege for containers

Audit and harden every container:

```yaml
# Template for hardened container in docker-compose.yml
services:
  example:
    image: example:latest
    read_only: true
    tmpfs:
      - /tmp
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    # Only add back specific capabilities if needed
    # cap_add:
    #   - NET_BIND_SERVICE
    user: "1000:1000"
    # Never mount Docker socket
    # Never use privileged: true
    # Never use network_mode: host unless absolutely required
```

### Network segmentation for containers

Create isolated Docker networks so containers can only reach what they need:

```yaml
networks:
  wazuh-internal:
    driver: bridge
    internal: true  # No external access
  wazuh-external:
    driver: bridge
    # Only dashboard gets external access

services:
  wazuh-manager:
    networks:
      - wazuh-internal
  wazuh-indexer:
    networks:
      - wazuh-internal
  wazuh-dashboard:
    networks:
      - wazuh-internal
      - wazuh-external
```
