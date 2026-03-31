# Binary Deployment and Upgrade Attack Incident Response Playbook

**System:** Sontara Lattice (claude-peers) fleet
**Last updated:** 2026-03-28
**Audience:** the operator (fleet operator)
**Severity tier:** Tier 3 (Approval Required) -- compromised binaries affect entire fleet

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

### Current deployment method

claude-peers binaries are deployed via a simple, unsigned pipeline:

```
1. Build on workstation:  cd ~/projects/claude-peers && go build -o claude-peers .
2. Copy via scp:      scp claude-peers broker-server:~/.local/bin/
3. Copy to other machines via scp
4. No hash verification on the receiving end
5. No code signing
6. No reproducible build verification
```

This pipeline has zero integrity verification. The receiving machine has no way to confirm the binary it received is the one that was built from the expected source code.

### Attack Scenario A: Build machine (workstation) compromise

```
1. Attacker gains access to workstation (<workstation-ip>)
2. Modifies source code in ~/projects/claude-peers/ or the Go toolchain
3. Binary is built with backdoor:
   - Exfiltrates UCAN tokens, NATS tokens, identity keys
   - Opens a reverse shell
   - Modifies fleet events in transit
   - Injects commands into daemon responses
4. the operator deploys the poisoned binary to all fleet machines via scp
5. Every machine in the fleet is now running attacker-controlled code
```

**Impact:** Total fleet compromise. The attacker controls the claude-peers binary on every machine.

### Attack Scenario B: Man-in-the-middle during scp transfer

```
1. Attacker intercepts the scp transfer (compromised Tailscale relay, ARP spoofing on local network)
2. Replaces the binary in transit
3. Target machine receives and runs the malicious binary
```

**Likelihood:** Low (Tailscale uses WireGuard encryption), but possible if Tailscale itself is compromised.

### Attack Scenario C: Mixed binary versions during rolling upgrade

```
1. the operator builds a new version and starts deploying
2. broker-server gets the new binary, but edge-node/iot-device still run the old one
3. If the new version has a protocol change, mixed versions may:
   - Fail to communicate (denial of service)
   - Interpret messages differently (state corruption)
   - One version accepts something the other rejects (security gap)
4. Window of vulnerability exists until all machines are upgraded
```

### Attack Scenario D: Go dependency supply chain

```
1. A Go dependency in go.mod is compromised upstream
2. go build pulls the malicious version
3. The resulting binary contains attacker code
4. Deployed to entire fleet
```

### What the claude-peers binary can access

On every fleet machine, the claude-peers binary runs with full user privileges and has access to:

- `~/.config/claude-peers/identity.pem` -- machine private key
- `~/.config/claude-peers/token.jwt` -- UCAN authentication token
- `~/.config/claude-peers/config.json` -- NATS token, broker URL
- All fleet event bus messages (NATS subscriber)
- Broker API (authenticated)
- Network access to all Tailscale peers

---

## Detection

### Binary integrity checks

```bash
echo "=== Fleet Binary Integrity Audit ==="

# Get the hash of the local (source) binary
LOCAL_HASH=$(sha256sum ~/projects/claude-peers/claude-peers 2>/dev/null | awk '{print $1}')
echo "Local build hash: $LOCAL_HASH"

# Compare against deployed binaries
for machine in "<workstation-ip>" "broker-server" "edge-node" "<workstation-2-ip>" "<user>@<laptop-1-ip><laptop-1-ip>" "<iot-device-ip>"; do
    REMOTE_HASH=$(ssh -o ConnectTimeout=5 $machine "sha256sum ~/.local/bin/claude-peers 2>/dev/null || sha256sum \$(which claude-peers) 2>/dev/null" 2>/dev/null | awk '{print $1}')
    if [ -z "$REMOTE_HASH" ]; then
        echo "  $machine: UNREACHABLE or binary not found"
    elif [ "$REMOTE_HASH" = "$LOCAL_HASH" ]; then
        echo "  $machine: MATCH ($REMOTE_HASH)"
    else
        echo "  $machine: MISMATCH! Expected $LOCAL_HASH, got $REMOTE_HASH"
    fi
done
```

### Version check across fleet

```bash
echo "=== Fleet Binary Version Audit ==="
for machine in "<workstation-ip>" "broker-server" "edge-node" "<workstation-2-ip>" "<user>@<laptop-1-ip><laptop-1-ip>" "<iot-device-ip>"; do
    VERSION=$(ssh -o ConnectTimeout=5 $machine "claude-peers version 2>/dev/null || claude-peers --version 2>/dev/null" 2>/dev/null)
    echo "  $machine: ${VERSION:-UNKNOWN}"
done
```

### Go dependency audit

```bash
# Check for known vulnerabilities in dependencies
cd ~/projects/claude-peers
go list -m all | head -30

# Check for replaced modules (could indicate tampering)
grep "replace" go.mod

# Verify module checksums
go mod verify
echo "Module verification: $?"

# Check go.sum for unexpected changes
git diff go.sum | head -50
```

### Detect modified source between builds

```bash
cd ~/projects/claude-peers

# Check for uncommitted changes that might indicate tampering
git status
git diff --stat

# Check if the built binary matches the committed source
echo "Last commit: $(git log -1 --oneline)"
echo "Binary mtime: $(stat -c %y claude-peers 2>/dev/null || stat -f %m claude-peers 2>/dev/null)"
```

### Wazuh FIM detection

```bash
# Wazuh should alert on binary changes if FIM is monitoring the right paths
ssh broker-server "
docker exec wazuh-manager cat /var/ossec/etc/ossec.conf 2>/dev/null | grep -A5 'syscheck' | head -20
docker exec wazuh-manager cat /var/ossec/etc/ossec.conf 2>/dev/null | grep 'local/bin'
"
```

---

## Immediate Triage (0-5 minutes)

### Step 1: Identify which machines have mismatched binaries

```bash
# Run the integrity check above
# If ANY machine has a different hash, treat it as potentially compromised
```

### Step 2: Stop the suspicious binary

```bash
SUSPECT_MACHINE="broker-server"  # Replace with the machine showing mismatch

ssh $SUSPECT_MACHINE "
pkill -f claude-peers
echo 'claude-peers stopped'
# Rename the binary so it cannot be restarted
mv ~/.local/bin/claude-peers ~/.local/bin/claude-peers.quarantined.\$(date +%s)
echo 'Binary quarantined'
"
```

### Step 3: Preserve the suspicious binary for analysis

```bash
SUSPECT_MACHINE="broker-server"
mkdir -p /tmp/binary-forensics

scp $SUSPECT_MACHINE:~/.local/bin/claude-peers.quarantined.* /tmp/binary-forensics/ 2>/dev/null
sha256sum /tmp/binary-forensics/*
echo "Suspicious binary preserved at /tmp/binary-forensics/"
```

---

## Containment

### Stop all fleet binaries if build machine compromise is suspected

```bash
echo "=== Emergency: Stopping claude-peers on all machines ==="
for machine in "<workstation-ip>" "broker-server" "edge-node" "<workstation-2-ip>" "<user>@<laptop-1-ip><laptop-1-ip>" "<iot-device-ip>"; do
    ssh -o ConnectTimeout=5 $machine "
        pkill -f claude-peers 2>/dev/null
        mv ~/.local/bin/claude-peers ~/.local/bin/claude-peers.quarantined.\$(date +%s) 2>/dev/null
    " 2>/dev/null &
done
wait
echo "All fleet binaries stopped and quarantined"
```

### If workstation (build machine) is compromised

```bash
# Do NOT build new binaries on workstation until it is verified clean
# Option 1: Build on broker-server
ssh broker-server "
cd /tmp
git clone https://github.com/YOUR_ORG/claude-peers.git
cd claude-peers
git log -1 --oneline
go build -o claude-peers .
sha256sum claude-peers
"

# Option 2: Build on laptop-1
ssh <user>@<laptop-1-ip><laptop-1-ip> "
cd /tmp
git clone https://github.com/YOUR_ORG/claude-peers.git
cd claude-peers
go build -o claude-peers .
sha256sum claude-peers
"
```

---

## Investigation

### Analyze the suspicious binary

```bash
# Compare the quarantined binary against a known-good build
cd ~/projects/claude-peers

# Rebuild from a known-good commit
KNOWN_GOOD_COMMIT="abc1234"  # Replace with last known good commit
git stash
git checkout $KNOWN_GOOD_COMMIT
go build -o claude-peers-known-good .
git checkout -
git stash pop 2>/dev/null

# Compare
sha256sum claude-peers-known-good /tmp/binary-forensics/claude-peers.quarantined.*

# Check binary size difference
ls -la claude-peers-known-good /tmp/binary-forensics/claude-peers.quarantined.*

# String analysis: look for unexpected URLs, IPs, or domains
strings /tmp/binary-forensics/claude-peers.quarantined.* | grep -iE 'http://|https://|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u > /tmp/binary-forensics/suspicious-strings.txt
strings claude-peers-known-good | grep -iE 'http://|https://|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u > /tmp/binary-forensics/known-good-strings.txt
diff /tmp/binary-forensics/known-good-strings.txt /tmp/binary-forensics/suspicious-strings.txt
```

### Check the Go toolchain

```bash
# Verify Go itself hasn't been tampered with
which go
go version
sha256sum $(which go)

# Check GOPATH and GOMODCACHE for unexpected modules
ls ~/go/pkg/mod/ | head -20
# Look for recently modified modules
find ~/go/pkg/mod/ -mtime -1 -type f 2>/dev/null | head -20
```

### Check source code integrity

```bash
cd ~/projects/claude-peers

# Compare local source against remote
git fetch origin
git diff origin/main...HEAD --stat

# Check for suspicious commits
git log --oneline -20

# Look for unexpected files
git status
git ls-files --others --exclude-standard
```

### Check Syncthing sync history

```bash
# Syncthing syncs ~/projects/ between workstation and broker-server
# An attacker could have modified source via Syncthing
find ~/projects/claude-peers -name '*.sync-conflict-*' 2>/dev/null
```

---

## Recovery

### Step 1: Verify build environment is clean

```bash
cd ~/projects/claude-peers

# Reset to known-good state from Git
git fetch origin
git reset --hard origin/main
go mod verify
echo "Module verification exit code: $?"
```

### Step 2: Build and hash

```bash
cd ~/projects/claude-peers
go build -o claude-peers .
BUILD_HASH=$(sha256sum claude-peers | awk '{print $1}')
echo "Build hash: $BUILD_HASH"
echo "$BUILD_HASH" > claude-peers.sha256
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $BUILD_HASH $(git log -1 --format=%H)" >> build-log.txt
```

### Step 3: Deploy with verification

```bash
BUILD_HASH=$(sha256sum ~/projects/claude-peers/claude-peers | awk '{print $1}')

for machine in "broker-server" "edge-node" "<workstation-2-ip>" "<user>@<laptop-1-ip><laptop-1-ip>" "<iot-device-ip>"; do
    echo "Deploying to $machine..."
    scp ~/projects/claude-peers/claude-peers $machine:/tmp/claude-peers-new 2>/dev/null

    REMOTE_HASH=$(ssh -o ConnectTimeout=5 $machine "sha256sum /tmp/claude-peers-new" 2>/dev/null | awk '{print $1}')
    if [ "$REMOTE_HASH" = "$BUILD_HASH" ]; then
        echo "  Hash verified: $REMOTE_HASH"
        ssh $machine "
            mv /tmp/claude-peers-new ~/.local/bin/claude-peers
            chmod +x ~/.local/bin/claude-peers
            rm -f ~/.local/bin/claude-peers.quarantined.* 2>/dev/null
        " 2>/dev/null
        echo "  Deployed successfully"
    else
        echo "  HASH MISMATCH: expected $BUILD_HASH, got $REMOTE_HASH"
        echo "  ABORTING deployment to $machine"
        ssh $machine "rm -f /tmp/claude-peers-new" 2>/dev/null
    fi
done
```

### Step 4: Restart fleet services

```bash
for machine in "broker-server" "edge-node" "<workstation-2-ip>" "<user>@<laptop-1-ip><laptop-1-ip>" "<iot-device-ip>"; do
    ssh -o ConnectTimeout=5 $machine "
        nohup claude-peers run > /tmp/claude-peers.log 2>&1 &
    " 2>/dev/null &
done
wait
echo "Fleet restarted"
```

---

## Post-Incident Hardening

### 1. Hash verification on every deployment

```bash
#!/bin/bash
# ~/.local/bin/fleet-deploy
# Safe deployment with hash verification

set -euo pipefail

BINARY="$1"
BUILD_HASH=$(sha256sum "$BINARY" | awk '{print $1}')
TARGETS=("broker-server" "edge-node" "<workstation-2-ip>" "<user>@<laptop-1-ip><laptop-1-ip>" "<iot-device-ip>")

echo "Deploying $BINARY (hash: $BUILD_HASH)"

for machine in "${TARGETS[@]}"; do
    echo "--- $machine ---"
    scp "$BINARY" "$machine:/tmp/claude-peers-deploy"
    REMOTE_HASH=$(ssh "$machine" "sha256sum /tmp/claude-peers-deploy" | awk '{print $1}')

    if [ "$REMOTE_HASH" != "$BUILD_HASH" ]; then
        echo "ABORT: Hash mismatch on $machine ($REMOTE_HASH)"
        ssh "$machine" "rm -f /tmp/claude-peers-deploy"
        exit 1
    fi

    ssh "$machine" "mv /tmp/claude-peers-deploy ~/.local/bin/claude-peers && chmod +x ~/.local/bin/claude-peers"
    echo "OK: deployed and verified"
done

echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $BUILD_HASH deployed to ${#TARGETS[@]} machines" >> ~/projects/claude-peers/deploy-log.txt
echo "Deployment complete"
```

### 2. Build reproducibility

```bash
# Record build environment with every release
echo "=== Build Environment ===" > build-env.txt
echo "Go version: $(go version)" >> build-env.txt
echo "GOOS: $(go env GOOS)" >> build-env.txt
echo "GOARCH: $(go env GOARCH)" >> build-env.txt
echo "Git commit: $(git log -1 --format=%H)" >> build-env.txt
echo "Git dirty: $(git diff --quiet && echo 'no' || echo 'YES')" >> build-env.txt
echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> build-env.txt
go mod verify >> build-env.txt 2>&1
```

### 3. Go dependency scanning

```bash
# Before every build, run vulnerability check
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...
```

### 4. Signed releases (future)

For production hardening, implement binary signing:

- Build on a dedicated machine or CI
- Sign the binary with a GPG key stored on a hardware token
- Distribute the signature alongside the binary
- Verify signature before installation on each machine

### 5. Automated fleet-wide binary audit

Add to a cron job or daemon: weekly hash comparison of all deployed binaries against the expected hash, alert on any mismatch.

---

## Monitoring Gaps

| Gap | Severity | Status | Remediation |
|-----|----------|--------|-------------|
| No binary signing or hash verification on deploy | **CRITICAL** | NOT IMPLEMENTED | Use the fleet-deploy script above as a minimum |
| No build reproducibility checks | **HIGH** | NOT IMPLEMENTED | Record build environment, verify clean git state before building |
| No automated binary integrity audit | **HIGH** | NOT IMPLEMENTED | Periodic fleet-wide hash comparison |
| No Go dependency vulnerability scanning | **HIGH** | NOT IMPLEMENTED | Run `govulncheck` before building |
| Binary deployed via scp with no integrity check | **CRITICAL** | CURRENT STATE | Always verify hash after scp transfer |
| No deployment log | **MEDIUM** | NOT IMPLEMENTED | Record what was deployed, when, to where, with what hash |
| Wazuh may not monitor ~/.local/bin/ | **MEDIUM** | NOT CONFIRMED | Verify FIM covers binary paths on all machines |
| No rollback mechanism | **MEDIUM** | NOT IMPLEMENTED | Keep previous binary versions for fast rollback |
| Mixed version window during rolling deploy | **LOW** | INHERENT | Deploy to all machines as quickly as possible; consider atomic fleet-wide upgrade |
