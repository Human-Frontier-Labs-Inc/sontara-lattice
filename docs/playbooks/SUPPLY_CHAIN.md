# Playbook: Dependency Supply Chain Attack

**Severity:** Critical
**Scope:** Entire fleet -- every machine running the claude-peers binary
**Last updated:** 2026-03-28

## Scenario

A malicious Go module is introduced into the sontara-lattice build via a compromised dependency. Because the binary is built once on workstation and deployed via `scp` to all fleet machines through `deploy.sh`, a single poisoned build contaminates the entire fleet simultaneously.

## Attack Vectors

### Vector 1: Trojanized Direct Dependency
An attacker compromises the GitHub account of a direct dependency maintainer (e.g., `nats-io/nats.go`, `golang-jwt/jwt`, `modernc.org/sqlite`) and publishes a malicious version. Running `go get -u` pulls it in.

### Vector 2: Compromised Transitive Dependency
A transitive dependency (e.g., `klauspost/compress`, `nats-io/nkeys`, `remyoudompheng/bigfft`) is poisoned. These are harder to notice because they don't appear in your import statements -- they're pulled in via `// indirect` in go.mod.

### Vector 3: Typosquatting
A similarly-named module is accidentally imported instead of the real one during development.

### Vector 4: go.sum Bypass
If `GONOSUMCHECK` or `GONOSUMDB` is set in the build environment, the Go checksum database is bypassed entirely and the trojanized module passes verification.

## What the Attacker Gets

This is the worst supply chain scenario because the claude-peers binary has deep access on every machine:

- **Broker (broker-server):** Full access to the broker database (all peer data, messages, events), NATS publishing, fleet memory, machine health scores. The binary runs as a systemd service with the root UCAN token.
- **All machines:** The binary reads `~/.config/claude-peers/identity.pem` (ed25519 private key), `token.jwt` (UCAN auth token), and `config.json` (NATS token, LLM API key). A trojanized binary can exfiltrate all of these on first run.
- **Supervisor (broker-server):** If the supervisor binary is compromised, it controls all 6 daemon invocations and has `os.Environ()` access -- which includes `CLAUDE_PEERS_NATS_TOKEN`, `CLAUDE_PEERS_LLM_API_KEY`, and any other env vars.

## Detection

### Currently Monitoring
- **Wazuh FIM on binaries:** Rule 100101 fires when `claude-peers*` in `/usr/local/bin/` or `~/.local/bin/` changes. This catches the deploy itself but does NOT distinguish a legitimate deploy from a compromised one.
- **Binary tamper response:** The response-daemon captures the md5sum of changed binaries.

### NOT Currently Monitoring -- GAPS

| Gap | Risk | Fix |
|---|---|---|
| **go.sum not monitored** | No alert when dependencies change. A trojanized dep slips in silently. | Add FIM on `go.sum` and `go.mod` in the project directory. Alert on any change outside of a known `go get` session. |
| **No binary checksum verification on deploy** | `deploy.sh` does a raw `scp` with no hash check. The binary on the target is whatever was copied. | Add `sha256sum` comparison: compute hash before scp, verify on target after scp, reject mismatch. |
| **No reproducible build verification** | Two builds from the same source can produce different binaries (timestamps, build IDs). No way to verify a binary matches its source. | Use `go build -trimpath -ldflags="-s -w"` and store expected hashes per release. |
| **No outbound network monitoring** | A trojanized binary could phone home to a C2 server. Nothing watches for unexpected outbound connections from the claude-peers process. | Monitor outbound connections from the binary. Expected destinations: broker IP (<broker-ip>:7899), NATS (<broker-ip>:4222). Anything else is suspicious. |
| **No dependency pinning** | `go.mod` uses `// indirect` comments but does not vendor dependencies. Every `go build` fetches from the module proxy. | Run `go mod vendor` and commit the vendor directory. Build with `go build -mod=vendor`. |

## Investigation

### Step 1: Verify the Go module tree

```bash
# On the build machine (workstation)
cd ~/projects/claude-peers

# Verify all module checksums match go.sum
go mod verify

# If this prints "all modules verified" -- checksums are intact.
# If it prints errors, a module has been tampered with since go.sum was written.
```

### Step 2: Diff go.sum against known-good

```bash
# Check git history for unexpected go.sum changes
git log --oneline -20 -- go.sum go.mod

# Diff against the last known-good commit
git diff <known-good-commit> -- go.sum

# Look for new or changed entries -- each line is a module@version hash
```

### Step 3: Check for unexpected imports

```bash
# List all imported packages
go list -m all

# Check for suspicious modules (typosquats, unexpected domains)
go list -m all | grep -v 'github.com/your-github-org'

# Check for replace directives that might redirect imports
grep 'replace' go.mod
```

### Step 4: Check the deployed binaries

```bash
# Compute hash of the source binary on workstation
sha256sum ~/projects/claude-peers/claude-peers-linux-amd64

# Compare against what's running on each machine
for machine in broker-server edge-node workstation-2 iot-device laptop-1; do
  echo "=== $machine ==="
  ssh $machine "sha256sum ~/.local/bin/claude-peers 2>/dev/null || md5 ~/.local/bin/claude-peers"
done
```

### Step 5: Check for unexpected network activity from the binary

```bash
# On each Linux machine
ssh broker-server "ss -tnp | grep claude-peers"
ssh edge-node "ss -tnp | grep claude-peers"

# On macOS
ssh laptop-1 "lsof -i -n -P | grep claude-peers"

# Expected connections: <broker-ip>:7899 (broker), <broker-ip>:4222 (NATS)
# Anything else is suspicious
```

## Containment

### Immediate (within minutes)

1. **Stop the binary on ALL machines:**
   ```bash
   for machine in broker-server edge-node workstation-2 iot-device laptop-1 workstation; do
     echo "=== Stopping $machine ==="
     ssh $machine "pkill -f claude-peers; systemctl --user stop claude-peers-broker 2>/dev/null; systemctl --user stop claude-peers-supervisor 2>/dev/null" 2>/dev/null
   done
   ```

2. **Quarantine the build directory:**
   ```bash
   # On workstation -- do NOT run go build again until the dep is identified
   mv ~/projects/claude-peers/go.sum ~/projects/claude-peers/go.sum.suspect
   ```

3. **Capture the suspect binary for analysis:**
   ```bash
   cp ~/.local/bin/claude-peers /tmp/claude-peers-suspect-$(date +%s)
   sha256sum /tmp/claude-peers-suspect-*
   ```

## Recovery

### Step 1: Identify the compromised dependency

```bash
# Diff go.sum against the last known-good version
git diff <last-known-good> -- go.sum | head -100

# Check when each dependency was last updated
go list -m -u all
```

### Step 2: Pin to known-good versions

```bash
# In go.mod, pin the compromised dependency to the last known-good version
go get github.com/compromised-module@v1.2.3-known-good

# Or better: vendor everything
go mod vendor
```

### Step 3: Clean rebuild

```bash
# Clean the module cache
go clean -modcache

# Rebuild with vendored deps
go build -mod=vendor -trimpath -ldflags="-s -w" -o claude-peers .

# Cross-compile for all targets
GOOS=linux GOARCH=amd64 go build -mod=vendor -trimpath -o claude-peers-linux-amd64 .
GOOS=linux GOARCH=arm64 go build -mod=vendor -trimpath -o claude-peers-linux-arm64 .
GOOS=darwin GOARCH=arm64 go build -mod=vendor -trimpath -o claude-peers-darwin-arm64 .
```

### Step 4: Compute and record checksums

```bash
sha256sum claude-peers-linux-amd64 claude-peers-linux-arm64 claude-peers-darwin-arm64 > checksums.sha256
```

### Step 5: Deploy with verification

```bash
# Deploy each binary with post-deploy hash check
for machine in broker-server edge-node workstation-2 iot-device laptop-1; do
  scp claude-peers-linux-amd64 $machine:~/.local/bin/claude-peers
  REMOTE_HASH=$(ssh $machine "sha256sum ~/.local/bin/claude-peers" | awk '{print $1}')
  LOCAL_HASH=$(sha256sum claude-peers-linux-amd64 | awk '{print $1}')
  if [ "$REMOTE_HASH" != "$LOCAL_HASH" ]; then
    echo "HASH MISMATCH on $machine -- DO NOT START"
  else
    echo "$machine: verified"
  fi
done
```

### Step 6: Full credential rotation

A compromised binary had access to every credential on every machine. Assume all are leaked:

1. Regenerate the broker keypair and root token on broker-server
2. Regenerate keypairs and tokens on every client machine
3. Rotate the NATS token
4. Rotate the LLM API key (LiteLLM proxy / Anthropic / Vertex AI)
5. Rotate any SSH keys that were accessible to the binary's process
6. Check `~/.ssh/authorized_keys` on all machines for injected keys
7. Check for persistence mechanisms the trojanized binary may have installed

## Prevention

### Must-Do (Not Optional)

1. **Vendor dependencies:** Run `go mod vendor` and commit the vendor directory. Build with `-mod=vendor`. This eliminates the module proxy as an attack surface.

2. **Hash verification on deploy:** Modify `deploy.sh` to compute sha256 before scp, verify after scp, and refuse to start on mismatch.

3. **FIM on go.sum/go.mod:** Add Wazuh file integrity monitoring on `~/projects/claude-peers/go.sum` and `go.mod`. Any change outside a known `go get` session should trigger a warning.

4. **Pin dependency versions:** Never use `go get -u` without reviewing the diff. Pin every dependency to exact versions.

### Should-Do

5. **Outbound network allowlist:** On broker-server, use iptables to restrict outbound connections from the claude-peers process to known destinations only (broker, NATS).

6. **Binary signing:** Sign the build output with a GPG key. Verify the signature on each machine before allowing the binary to start.

7. **SBOM generation:** Generate a Software Bill of Materials on each build. Store it alongside the checksums. If a CVE hits a dependency, you can immediately check if you're affected.

## Architectural Weakness

The entire fleet runs the same binary built from a single source on a single machine. There is no build reproducibility, no binary signing, no checksum verification on deploy, and no dependency vendoring. The deploy script (`deploy.sh`) does a raw `scp` with no integrity checks. A single compromised `go get` on workstation poisons every machine in the fleet within one deploy cycle. This is a high-impact, low-detection-probability attack.
