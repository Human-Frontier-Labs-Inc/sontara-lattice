# Race Condition Attack Playbook

Sontara Lattice fleet -- last updated 2026-03-28.

**Tier:** Varies -- most race conditions are theoretical DoS or data integrity issues. One (UCAN validation + health check race) could enable quarantine bypass.

**Current Detection: NONE** -- Race conditions are logic bugs, not detectable by FIM or log analysis. They manifest as intermittent failures, data corruption, or unexpected state.

---

## Known Race Conditions in the Codebase

### 1. UCAN Token Validation + Health Check Race (security-relevant)

**Location:** `ucan_middleware.go` lines 48-60

**The bug:** Token validation and quarantine check are two separate operations. The middleware first validates the UCAN token (line 35-46), then checks if the machine is quarantined (line 49-60). These are not atomic.

```go
// Step 1: Validate token (succeeds)
claims, err := validator.Validate(tokenStr)

// Step 2: Check quarantine (separate lock acquisition)
h := health.getMachineHealth(claims.MachineName)
if h != nil && h.Status == "quarantined" {
    // Reject
}
```

**Attack scenario:**
1. Machine is quarantined (health score >= 10)
2. Attacker sends a request at time T
3. At time T, token validation succeeds (UCAN is still technically valid -- quarantine is a broker-level concept, not a token revocation)
4. Between step 1 and step 2, another goroutine processes an `unquarantine` request
5. At time T+1ms, the quarantine check sees status "healthy" and allows the request through

**Practical exploitability:** LOW. Requires precise timing of the unquarantine call between the two checks. The window is microseconds. An attacker would need to control both the unquarantine timing AND the request timing. However, if the attacker has the UCAN token from a compromised machine, they could script thousands of simultaneous requests while triggering unquarantine, increasing the chance of hitting the window.

**Fix:**
```go
// Hold the health lock during both validation and quarantine check
// Or: make quarantine a property of the token itself (revocation list)
```

### 2. Multiple Simultaneous Registrations from Same Token

**Location:** `broker.go` (peer registration handler)

**The bug:** If the same UCAN token is used by two concurrent requests to register as different peer IDs, both may succeed. The broker doesn't enforce one-peer-per-token atomically.

**Attack scenario:**
1. Attacker steals a UCAN token from machine X
2. Attacker sends two simultaneous `/register` requests: one as "machine-X", one as "machine-X-shadow"
3. Both pass UCAN validation (same token, both valid)
4. Both get registered as peers
5. The shadow peer can now receive messages intended for machine-X and send messages as a fleet peer

**Practical exploitability:** MEDIUM. Requires a stolen token. The attacker gets a shadow identity in the fleet.

**Fix:** Track token hashes in a concurrent-safe set. First registration for a token hash wins. Subsequent registrations with the same token hash are rejected.

### 3. Concurrent Daemon Runs Modifying Same Files

**Location:** `supervisor.go` lines 218-240

**The bug:** The supervisor uses `s.running[d.Name]` as a mutex to prevent concurrent runs of the same daemon. But if two different daemons (e.g., librarian and fleet-scout) both write to the same file, there's no coordination.

**Attack scenario (accidental, not malicious):**
1. fleet-scout runs a health check and writes to `/tmp/health-report.txt`
2. librarian runs simultaneously, reads the same directory for its documentation audit
3. librarian reads a partially written health report, misinterprets it, and creates a PR with wrong data
4. Not a security issue directly, but a data integrity issue

**Practical exploitability:** LOW. Daemons write to `/tmp/daemon-<name>/` isolated workspaces. Cross-daemon file conflicts are unlikely in normal operation.

**Fix:** The workspace isolation (`--workspace /tmp/daemon-<name>`) already prevents most conflicts. Document the convention and enforce it.

### 4. Syncthing Conflict During Binary Deploy

**Location:** `deploy.sh` and Syncthing sync

**The bug:** The deploy script (`deploy.sh`) uses `scp` to copy binaries to `~/.local/bin/claude-peers` on each machine. If Syncthing is syncing `~/.local/bin/` (it doesn't currently, but `~/projects/claude-peers/` IS synced), a partially written binary could be synced to another machine.

**Attack scenario:**
1. Deploy script starts writing `claude-peers` binary to workstation
2. Syncthing detects the file change mid-write and starts syncing the partial file to broker-server
3. broker-server gets a truncated/corrupt binary
4. If the service restarts, it tries to execute the corrupt binary and crashes

**Practical exploitability:** LOW for the binary (deploy path `~/.local/bin/` is not Syncthing-synced). MEDIUM for daemon files (the `daemons/` directory IS Syncthing-synced from workstation to broker-server).

**Scenario where this matters:**
1. You edit `daemons/fleet-scout/fleet-scout.agent` on workstation
2. Syncthing starts syncing the file to broker-server
3. The supervisor on broker-server invokes fleet-scout, reading the .agent file
4. The file is partially written -- the prompt is truncated or contains garbage
5. The LLM receives a malformed prompt and produces unpredictable output

**Fix:** Use Syncthing's `.stignore` to temporarily ignore daemon files during edits. Or add a staging/verification step between Syncthing sync and supervisor reads (see DAEMON_HIJACK.md section 9).

### 5. Health Score Update + Quarantine Check Race

**Location:** `security.go` lines 37-88 and `ucan_middleware.go` lines 48-60

**The bug:** The health score is updated in `updateMachineHealth()` which holds `b.healthMu.Lock()`. The quarantine check in the middleware uses `getMachineHealth()` which holds `b.healthMu.RLock()`. These are properly serialized by the RWMutex. HOWEVER, the score update and the quarantine status change are in the same critical section, but the middleware reads them separately.

**Specific race:** Between `Score += 10` (line 58) and `Status = "quarantined"` (line 61-62 via the switch statement at line 66), there's no gap because they're in the same Lock(). BUT the decay function (`decayHealthScores()`) runs on a 5-minute ticker and can reduce the score below quarantine threshold right after the quarantine was set.

Wait -- actually the code checks `if h.Status == "quarantined" { continue }` in the decay function (line 111). Quarantined machines don't decay. This is correct. **This is NOT a bug.**

### 6. NATS Message Ordering

**Location:** `nats.go` -- JetStream subscriptions

**The bug:** NATS JetStream provides at-least-once delivery with ordering guarantees per subject. But security events on `fleet.security.>` and daemon events on `fleet.daemon.>` are different subjects. The security-watch correlator (`security_watch.go`) processes events as they arrive, but events from different subjects may arrive out of order.

**Attack scenario:**
1. An attacker triggers two events simultaneously on the same machine: a brute force attempt and a credential file modification
2. The credential modification event arrives at security-watch first
3. The brute force event arrives second
4. The correlation window check (`checkCredentialTheft`) looks backward for FIM events followed by peer registration, but the ordering assumption may cause missed correlations

**Practical exploitability:** LOW. The correlation windows are 5-10 minutes, which is vastly larger than any message ordering jitter. A few milliseconds of reordering won't cause missed detections.

---

## 1. Detection

Race conditions don't generate alerts. You detect them by their symptoms:

### Symptoms to watch for

| Symptom | Possible Race Condition |
|---------|----------------------|
| Quarantined machine successfully makes API calls | UCAN + health check race (#1) |
| Two peers registered with same token hash | Simultaneous registration race (#2) |
| Daemon produces garbled output | Syncthing partial sync race (#4) |
| Health score drops below quarantine but machine stays quarantined | Not a race (intentional behavior) |
| Daemon email says "tests FAILED" but tests pass when you check | Stale file read during sync |

### Proactive checks

```bash
# Check for duplicate peer registrations
curl -s -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt)" \
  http://<broker-ip>:7899/peers | jq '.[] | {id, machine_name}'
# Look for the same machine_name with multiple peer IDs

# Check for requests from quarantined machines in broker logs
ssh broker-server "journalctl --user -u claude-peers-broker --since '24 hours ago' --no-pager | grep 'QUARANTINED'" | head -10
# If there are 200 OK responses interspersed with 403 QUARANTINED for the same machine, the race was hit
```

---

## 2. Containment

### If quarantine bypass is suspected

```bash
# Re-quarantine the machine explicitly
curl -X POST -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt)" \
  http://<broker-ip>:7899/quarantine/<machine>

# Revoke the machine's UCAN token at the broker level
# Currently no token revocation endpoint exists -- this is a gap
# The only option is to restart the broker (clears the token validator's known tokens)
# WARNING: this requires all machines to re-register
ssh broker-server "systemctl --user restart claude-peers-broker"
```

### If duplicate registration is detected

```bash
# Identify the shadow peer
curl -s -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt)" \
  http://<broker-ip>:7899/peers | jq '.[] | select(.machine_name == "<machine>")'

# The legitimate peer should have a known peer_id
# Remove the shadow by restarting the broker (no peer deletion endpoint currently)
```

---

## 3. Prevention

### Make quarantine check atomic with authentication

Modify `ucan_middleware.go` to hold the health read lock during the entire authentication + authorization flow:

```go
// Current (vulnerable):
claims, err := validator.Validate(tokenStr)  // Separate operation
h := health.getMachineHealth(claims.MachineName)  // Separate operation

// Fixed (atomic):
// Validate and check health under a single read lock
h := health.getMachineHealth(claims.MachineName)
if h != nil && h.Status == "quarantined" {
    return 403  // Check quarantine BEFORE accepting the request
}
claims, err := validator.Validate(tokenStr)  // Then validate
```

Actually, the machine name comes from the token claims, so you can't check quarantine before parsing the token. The real fix is to add a token revocation list: when a machine is quarantined, add its token hash to a blocklist checked during validation.

### Add token binding to peer registration

Enforce one peer per token:

```go
// In the registration handler:
tokenHash := TokenHash(tokenStr)
b.mu.Lock()
if existingPeer, ok := b.tokenToPeer[tokenHash]; ok && existingPeer != peerID {
    b.mu.Unlock()
    return 409, "token already bound to peer " + existingPeer
}
b.tokenToPeer[tokenHash] = peerID
b.mu.Unlock()
```

### Add file locking for daemon invocations

Before reading a daemon's .agent file, acquire a file lock:

```go
// In supervisor invoke():
lockPath := filepath.Join(d.Dir, ".lock")
lock, err := os.Create(lockPath)
if err == nil {
    syscall.Flock(int(lock.Fd()), syscall.LOCK_EX)
    defer func() {
        syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
        lock.Close()
    }()
}
```

### Syncthing ignore during edits

Add to `.stignore` in the daemons folder:

```
// .stignore
(?d).~*
(?d)*~
(?d).*.swp
```

Or implement a deploy gate: edits to daemon files on workstation trigger a "pending" state. The supervisor on broker-server waits for a "deploy" signal (via NATS or a marker file) before reading the new files.

### Add token revocation list

The broker should maintain a set of revoked token hashes. When a machine is quarantined, its token hash is added to the revocation list. The UCAN middleware checks the revocation list during validation, BEFORE the quarantine status check. This closes the race window entirely because revocation is checked inside the token validation function, not as a separate step.

---

## 4. Testing Race Conditions

### Test UCAN + health check race

```bash
# Script that simultaneously sends API requests and unquarantine commands
# On broker-server:

# First, quarantine edge-node
claude-peers quarantine edge-node

# Then, in parallel:
# Terminal 1: flood API requests as edge-node
for i in $(seq 1 1000); do
  curl -s -H "Authorization: Bearer $(cat /path/to/edge-node-token.jwt)" \
    http://127.0.0.1:7899/peers -o /dev/null -w "%{http_code}\n" &
done

# Terminal 2: unquarantine in the middle
sleep 0.1
claude-peers unquarantine edge-node

# Check: any 200 responses BEFORE the unquarantine? That's the race.
```

### Test Syncthing partial read

```bash
# Simulate a large .agent file being written while supervisor reads it
# On workstation, write a large file slowly:
dd if=/dev/urandom bs=1 count=10000 2>/dev/null | base64 > ~/projects/claude-peers/daemons/fleet-scout/fleet-scout.agent.test

# On broker-server, read it while it's syncing:
while true; do wc -c ~/claude-peers-daemons/fleet-scout/fleet-scout.agent.test 2>/dev/null; sleep 0.1; done
# If the file size changes between reads, the partial sync window exists

# Clean up
rm ~/projects/claude-peers/daemons/fleet-scout/fleet-scout.agent.test
```
