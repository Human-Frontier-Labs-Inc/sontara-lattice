# Docker Socket Exposure Incident Response Playbook

**System:** Sontara Lattice (claude-peers) fleet
**Last updated:** 2026-03-28
**Audience:** the operator (fleet operator)
**Severity tier:** Tier 3 (Approval Required) -- Docker socket access equals root on broker-server

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

### What the Docker socket is

The Docker socket (`/var/run/docker.sock`) is the Unix domain socket through which the Docker CLI communicates with the Docker daemon. Any process that can write to this socket has **full control over Docker**, which effectively means **root access to the host**.

The Docker socket exists only on **broker-server (<broker-ip>)** -- the only fleet machine running Docker.

### Containers on broker-server

| Container | Image | Purpose | Socket Mounted? | Risk |
|-----------|-------|---------|----------------|------|
| wazuh-manager | wazuh/wazuh-manager | Security monitoring | **CHECK** | CRITICAL if mounted -- attacker can disable monitoring AND get host root |
| wazuh-indexer | wazuh/wazuh-indexer | Elasticsearch for Wazuh | Unlikely | HIGH -- contains all security data |
| wazuh-dashboard | wazuh/wazuh-dashboard | Web UI | Unlikely | LOW |
| litellm | LiteLLM proxy | LLM routing | Unlikely | HIGH -- sees all daemon prompts |

### Attack scenarios

**Scenario A: Docker socket mounted inside a container**

```
1. A container (e.g., wazuh-manager) has /var/run/docker.sock bind-mounted
2. Attacker compromises the container (via Wazuh vulnerability, log injection, etc.)
3. From inside the container, attacker runs:
   docker -H unix:///var/run/docker.sock run -v /:/host --privileged -it alpine chroot /host
4. Attacker now has a root shell on the broker-server host
5. From host root:
   - Read identity.pem (root trust key)
   - Access all NATS streams
   - Modify broker code/config
   - Install persistence
   - Pivot to other fleet machines
```

**Scenario B: Compromised process on broker-server accesses the socket**

```
1. Attacker gains unprivileged shell on broker-server
2. The user user is in the docker group (required to run docker without sudo)
3. Attacker runs: docker run -v /:/host --privileged -it alpine chroot /host
4. Same result: full host root
```

**Scenario C: Remote Docker API exposure**

```
1. Docker daemon is configured to listen on a TCP port (not just the Unix socket)
2. Any Tailscale peer can connect to the Docker API
3. Full remote control of all containers and the host
```

### Why this is critical

Docker socket access is a **root-equivalent privilege**. It bypasses:
- All filesystem permissions
- All userspace security (Wazuh, AppArmor, SELinux)
- All network isolation (can create host-networked containers)
- All resource limits

If any container or process can access the Docker socket, the security boundary between container and host is **nonexistent**.

---

## Detection

### Check if Docker socket is mounted in any container

```bash
ssh broker-server "
echo '=== Docker Socket Mount Check ==='
for container in \$(docker ps -q); do
    NAME=\$(docker inspect --format '{{.Name}}' \$container | sed 's/^\///')
    MOUNTS=\$(docker inspect --format '{{range .Mounts}}{{.Source}}:{{.Destination}} {{end}}' \$container)
    if echo \"\$MOUNTS\" | grep -q 'docker.sock'; then
        echo \"CRITICAL: \$NAME has docker.sock mounted!\"
        echo \"  Mounts: \$MOUNTS\"
    else
        echo \"OK: \$NAME -- no socket mount\"
    fi
done
"
```

### Check Docker socket permissions

```bash
ssh broker-server "
echo '=== Docker Socket Permissions ==='
ls -la /var/run/docker.sock
echo ''
echo '=== Docker group members ==='
getent group docker
echo ''
echo '=== Is user in docker group? ==='
id user | grep -o 'docker' && echo 'YES -- user can use docker without sudo' || echo 'NO -- sudo required'
"
```

### Check for Docker API TCP exposure

```bash
ssh broker-server "
echo '=== Docker daemon listening sockets ==='
ss -tlnp | grep dockerd
echo ''
echo '=== Docker daemon config ==='
cat /etc/docker/daemon.json 2>/dev/null || echo 'No daemon.json'
echo ''
echo '=== Docker systemd override ==='
systemctl cat docker.service 2>/dev/null | grep -i 'host\|tcp\|listen'
"
```

### Check for privileged containers

```bash
ssh broker-server "
echo '=== Privileged Container Check ==='
for container in \$(docker ps -q); do
    NAME=\$(docker inspect --format '{{.Name}}' \$container | sed 's/^\///')
    PRIV=\$(docker inspect --format '{{.HostConfig.Privileged}}' \$container)
    CAPS=\$(docker inspect --format '{{.HostConfig.CapAdd}}' \$container)
    PID_MODE=\$(docker inspect --format '{{.HostConfig.PidMode}}' \$container)
    NET_MODE=\$(docker inspect --format '{{.HostConfig.NetworkMode}}' \$container)

    WARNINGS=''
    [ \"\$PRIV\" = 'true' ] && WARNINGS=\"\${WARNINGS} PRIVILEGED\"
    [ \"\$CAPS\" != '[]' ] && [ \"\$CAPS\" != '<no value>' ] && WARNINGS=\"\${WARNINGS} CAPS=\$CAPS\"
    [ \"\$PID_MODE\" = 'host' ] && WARNINGS=\"\${WARNINGS} PID=host\"
    [ \"\$NET_MODE\" = 'host' ] && WARNINGS=\"\${WARNINGS} NET=host\"

    if [ -n \"\$WARNINGS\" ]; then
        echo \"WARNING: \$NAME --\$WARNINGS\"
    else
        echo \"OK: \$NAME\"
    fi
done
"
```

### Detect processes accessing the Docker socket

```bash
ssh broker-server "
echo '=== Processes with docker.sock open ==='
sudo lsof /var/run/docker.sock 2>/dev/null || echo 'lsof not available or no access'
echo ''
echo '=== Recent docker commands (from audit log) ==='
ausearch -c docker 2>/dev/null | tail -20 || echo 'auditd not running'
echo ''
echo '=== Docker events (last hour) ==='
timeout 5 docker events --since 1h --until now 2>/dev/null | tail -20
"
```

### Detect new containers being spawned

```bash
ssh broker-server "
echo '=== All containers (including stopped) ==='
docker ps -a --format 'table {{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Names}}\t{{.CreatedAt}}'
echo ''
echo '=== Recently created containers (last 24h) ==='
docker ps -a --filter 'since=24h' --format 'table {{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Names}}\t{{.CreatedAt}}' 2>/dev/null || \
docker ps -a --format '{{.CreatedAt}}\t{{.Names}}\t{{.Image}}' | head -10
"
```

---

## Immediate Triage (0-5 minutes)

### Step 1: Check for active exploitation

```bash
ssh broker-server "
echo '=== Active container check ==='
# Look for containers that shouldn't be there
EXPECTED_CONTAINERS='wazuh-manager wazuh-indexer wazuh-dashboard litellm'
for container in \$(docker ps --format '{{.Names}}'); do
    if ! echo \"\$EXPECTED_CONTAINERS\" | grep -qw \"\$container\"; then
        echo \"UNEXPECTED CONTAINER: \$container\"
        docker inspect \$container | python3 -c '
import json, sys
data = json.load(sys.stdin)[0]
print(f\"  Image: {data[\"Config\"][\"Image\"]}\")
print(f\"  Created: {data[\"Created\"]}\")
print(f\"  Privileged: {data[\"HostConfig\"][\"Privileged\"]}\")
mounts = data.get(\"Mounts\", [])
for m in mounts:
    print(f\"  Mount: {m[\"Source\"]} -> {m[\"Destination\"]}\")
'
    fi
done
echo 'Done'
"
```

### Step 2: Kill any suspicious containers immediately

```bash
ssh broker-server "
# Kill any container not in the expected list
EXPECTED='wazuh-manager wazuh-indexer wazuh-dashboard litellm'
for container in \$(docker ps --format '{{.Names}}'); do
    if ! echo \"\$EXPECTED\" | grep -qw \"\$container\"; then
        echo \"KILLING: \$container\"
        docker kill \$container
        docker rm \$container
    fi
done
"
```

---

## Containment

### Remove socket mount from containers

```bash
ssh broker-server "
# If any container has docker.sock mounted, it must be restarted without the mount
# 1. Check docker-compose.yml for socket mounts
find ~/docker -name 'docker-compose.yml' -o -name 'docker-compose.yaml' | while read f; do
    if grep -q 'docker.sock' \"\$f\"; then
        echo \"FOUND docker.sock mount in: \$f\"
        grep -n 'docker.sock' \"\$f\"
    fi
done

# 2. If found, edit the compose file to remove the socket mount, then recreate
# docker compose -f <file> up -d --force-recreate
"
```

### Restrict Docker socket access

```bash
ssh broker-server "
# Change socket permissions to root-only (breaks docker without sudo)
sudo chmod 660 /var/run/docker.sock
sudo chown root:root /var/run/docker.sock
echo 'Docker socket restricted to root only'

# Remove user from docker group if needed
# sudo gpasswd -d user docker
# echo 'Removed user from docker group -- docker requires sudo now'
"
```

---

## Investigation

### Full container security audit

```bash
ssh broker-server "
echo '=== Complete Container Security Audit ==='
for container in \$(docker ps -q); do
    NAME=\$(docker inspect --format '{{.Name}}' \$container | sed 's/^\///')
    echo ''
    echo \"--- \$NAME ---\"
    docker inspect \$container | python3 -c '
import json, sys
data = json.load(sys.stdin)[0]
hc = data[\"HostConfig\"]
print(f\"  Image: {data[\"Config\"][\"Image\"]}\")
print(f\"  Privileged: {hc[\"Privileged\"]}\")
print(f\"  PidMode: {hc.get(\"PidMode\", \"default\")}\")
print(f\"  NetworkMode: {hc.get(\"NetworkMode\", \"default\")}\")
print(f\"  CapAdd: {hc.get(\"CapAdd\", [])}\")
print(f\"  SecurityOpt: {hc.get(\"SecurityOpt\", [])}\")
print(f\"  ReadonlyRootfs: {hc.get(\"ReadonlyRootfs\", False)}\")
print(f\"  User: {data[\"Config\"].get(\"User\", \"root (default)\")}\")
mounts = data.get(\"Mounts\", [])
for m in mounts:
    rw = \"RW\" if m.get(\"RW\", True) else \"RO\"
    src = m.get(\"Source\", \"unknown\")
    dst = m.get(\"Destination\", \"unknown\")
    dangerous = \"*** DANGEROUS ***\" if any(p in src for p in [\"/var/run/docker\", \"/\", \"/etc\", \"/root\"]) else \"\"
    print(f\"  Mount [{rw}]: {src} -> {dst} {dangerous}\")
'
done
"
```

### Check for Docker escape artifacts

```bash
ssh broker-server "
echo '=== Check for container escape indicators ==='
# Look for processes that were started from within containers but are running on the host
docker inspect --format '{{.State.Pid}}' \$(docker ps -q) 2>/dev/null | while read pid; do
    # Check if any child processes escaped the container namespace
    ls /proc/\$pid/task/*/children 2>/dev/null | while read children; do
        cat \$children 2>/dev/null
    done
done

echo '=== Check host filesystem for container-written files ==='
# If a container had host mounts, check for unexpected files
find /tmp -newer /var/run/docker.sock -type f 2>/dev/null | head -20
find /home/user -name '.bash_history' -newer /var/run/docker.sock 2>/dev/null
"
```

### Check Docker daemon logs

```bash
ssh broker-server "
echo '=== Docker daemon logs ==='
journalctl -u docker --since '24 hours ago' --no-pager | grep -iE 'create|start|exec|error|warning' | tail -30
"
```

---

## Recovery

### Step 1: Rebuild containers without dangerous configurations

```bash
ssh broker-server "
# Stop all containers
docker compose down 2>/dev/null || docker stop \$(docker ps -q)

# Verify compose files have no socket mounts
# Edit any offending docker-compose.yml files

# Recreate with security constraints
# Add to docker-compose.yml for each service:
# security_opt:
#   - no-new-privileges:true
# read_only: true  (where possible)
# tmpfs:
#   - /tmp
# No socket mounts
# No privileged mode
# Minimal capabilities

docker compose up -d
"
```

### Step 2: Verify host integrity after container escape

If a container escape occurred, the host may be compromised. Run the full investigation from the KERNEL_EXPLOIT and PERSISTENCE_AUDIT playbooks.

```bash
ssh broker-server "
# Quick host integrity check
echo '=== Checking for persistence ==='
crontab -l 2>/dev/null
ls -la /etc/cron.d/ /etc/cron.daily/ 2>/dev/null | head -20
systemctl list-units --type=service --state=running | head -30
ls -la ~/.config/systemd/user/*.service 2>/dev/null
cat ~/.bashrc | tail -5
cat ~/.profile | tail -5
"
```

---

## Post-Incident Hardening

### 1. Never mount Docker socket into containers

This is the single most important rule. No container should ever have `/var/run/docker.sock` mounted. If a tool requires it (e.g., container monitoring), use a Docker socket proxy with read-only access instead.

### 2. Use rootless Docker

```bash
ssh broker-server "
# Install rootless Docker (runs Docker daemon as non-root)
# This eliminates the root escalation path entirely
dockerd-rootless-setuptool.sh install 2>/dev/null || echo 'Install rootless Docker tools first'
# See: https://docs.docker.com/engine/security/rootless/
"
```

### 3. Enable Docker content trust

```bash
ssh broker-server "
# Only pull signed images
export DOCKER_CONTENT_TRUST=1
# Add to ~/.bashrc or systemd environment
echo 'export DOCKER_CONTENT_TRUST=1' >> ~/.bashrc
"
```

### 4. Restrict container capabilities

For each container in docker-compose.yml:

```yaml
services:
  wazuh-manager:
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE  # Only what's actually needed
    read_only: true
    tmpfs:
      - /tmp
      - /var/run
```

### 5. Add Docker event monitoring

```bash
# Monitor for suspicious Docker activity via a systemd service or daemon
ssh broker-server "
# Create a Docker event monitor
cat > ~/.local/bin/docker-event-monitor.sh << 'SCRIPT'
#!/bin/bash
docker events --format '{{json .}}' | while read event; do
    TYPE=\$(echo \$event | python3 -c 'import json,sys; print(json.load(sys.stdin).get(\"Action\",\"\"))')
    if echo \"\$TYPE\" | grep -qE 'create|exec_create|exec_start'; then
        echo \"\$(date -u +%Y-%m-%dT%H:%M:%SZ) ALERT: Docker event: \$TYPE\" >> /tmp/docker-events.log
        # TODO: publish to NATS fleet.security.docker
    fi
done
SCRIPT
chmod +x ~/.local/bin/docker-event-monitor.sh
"
```

### 6. Network restrictions for containers

```bash
# Use Docker networks to isolate containers from each other
# Only expose the ports that are actually needed
ssh broker-server "
docker network create --internal wazuh-internal 2>/dev/null
# Move Wazuh containers to internal network where possible
"
```

---

## Monitoring Gaps

| Gap | Severity | Status | Remediation |
|-----|----------|--------|-------------|
| Docker socket mount status not audited | **CRITICAL** | NOT MONITORED | Add periodic check for socket mounts in containers |
| No Docker event monitoring | **HIGH** | NOT IMPLEMENTED | Monitor for container creation, exec, and privilege changes |
| Container capabilities not restricted | **HIGH** | NOT CONFIRMED | Audit all containers for excessive capabilities |
| Wazuh container security posture unknown | **HIGH** | NOT CONFIRMED | Check if wazuh-manager has socket mount or host mounts that allow host access |
| No rootless Docker | **HIGH** | NOT IMPLEMENTED | Rootless Docker eliminates the root escalation path |
| Docker API TCP exposure not checked | **MEDIUM** | NOT CONFIRMED | Verify Docker daemon only listens on Unix socket, not TCP |
| No Docker content trust | **MEDIUM** | NOT IMPLEMENTED | Enable DOCKER_CONTENT_TRUST to prevent pulling unsigned images |
| user in docker group | **MEDIUM** | LIKELY | Any process running as user can use Docker = root equivalent |
| No container image vulnerability scanning | **MEDIUM** | NOT IMPLEMENTED | Scan container images for known vulnerabilities |
