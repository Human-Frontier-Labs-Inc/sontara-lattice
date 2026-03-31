# Architecture

Sontara Lattice is a single Go binary (`claude-peers`) that contains multiple cooperating services. Each service is a subcommand. They communicate via a central trust broker and a NATS JetStream event bus.

---

## Component Diagram

```
┌────────────────────────────────────────────────────────────────────────┐
│                          Fleet Network                                  │
│                                                                         │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐               │
│  │  Machine A   │   │  Machine B   │   │  Machine C   │               │
│  │ (broker)     │   │ (client)     │   │ (client)     │               │
│  │              │   │              │   │              │               │
│  │ claude-peers │   │ claude-peers │   │ claude-peers │               │
│  │  broker      │   │  server      │   │  server      │               │
│  │  supervisor  │   │              │   │              │               │
│  │  gridwatch   │   │ Wazuh agent  │   │ Wazuh agent  │               │
│  │  wazuh-brdg  │   │              │   │              │               │
│  │  sec-watch   │   │              │   │              │               │
│  │  resp-daemon │   │              │   │              │               │
│  │              │   │              │   │              │               │
│  │ Wazuh Manager│   │              │   │              │               │
│  │ NATS Server  │   │              │   │              │               │
│  └──────┬───────┘   └──────┬───────┘   └──────┬───────┘               │
│         │                  │                  │                        │
│         └──────────────────┼──────────────────┘                        │
│                            │ Tailscale VPN                             │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Trust Broker (`broker_core.go`)

The broker is the central registry and trust authority. It runs as an HTTP server on port 7899 (default) backed by SQLite.

**Responsibilities:**
- Register and track peers (Claude Code sessions, services)
- Route messages between peers
- Validate all requests with UCAN tokens
- Maintain per-machine health scores (updated from NATS security events)
- Emit fleet events to NATS as a dual-write to SQLite

**SQLite schema:**
- `peers` -- registered sessions (id, pid, machine, cwd, git_root, tty, summary, last_seen)
- `messages` -- pending messages (from_id, to_id, text, delivered)
- `events` -- broker event log (type, peer_id, machine, data)
- `kv` -- key-value store (fleet memory document)

**Stale cleanup:** Peers that miss heartbeats for more than `stale_timeout` seconds (default: 300) are removed automatically. The cleanup goroutine also prunes delivered messages older than 1 hour and runs a SQLite WAL checkpoint every 30 seconds.

**Rate limiting:** `/send-message` is limited to 10 req/min per IP; `/register` to 5 req/min. Both use a token bucket implementation in `rate_limiter.go`.

**Health scoring integration:** The broker runs `subscribeSecurityEvents` as a goroutine. It connects to NATS independently, subscribes to `fleet.security.>`, and calls `updateMachineHealth` on each event. A separate `startHealthDecay` goroutine runs every 5 minutes and reduces scores by 2 for non-quarantined machines.

---

## UCAN Auth (`auth_ucan.go`, `auth_middleware.go`)

**Token structure:**
```
JWT header: {"alg": "EdDSA"}
JWT claims:
  iss: <issuer Ed25519 pubkey, base64url>
  aud: [<audience Ed25519 pubkey, base64url>]
  sub: "claude-peers"
  iat: <issued at>
  exp: <expires at>
  cap: [{"resource": "peer/register"}, ...]
  prf: <SHA-256 hash of parent token, or empty for root>
```

**Root token** (broker only): `iss == aud[0]` (self-signed). Contains all capabilities. Stored as `root-token.jwt`. Never refreshed via the broker endpoint.

**Delegated token**: issued by the broker's private key for a specific machine's public key. `prf` field contains `SHA-256(parent_token)` as a base64url string. The validator checks the proof hash against its `knownTokens` map to verify the chain.

**Attenuation enforcement:** `MintToken` parses the parent token and rejects any capability not present in the parent. You cannot escalate privileges through delegation.

**Middleware (`auth_middleware.go`):** Every request (except `/health` and `/challenge`) passes through `ucanMiddleware`. It extracts the Bearer token, calls `validator.Validate()`, and stores the claims in the request context. The `requireCapability` wrapper checks that the validated claims contain the required resource.

**Token refresh:** The `/refresh-token` endpoint accepts a valid or recently-expired token (up to 1 hour grace) and issues a new 24-hour token for the same audience. This lets machines auto-renew without manual intervention.

**Quarantine enforcement:** The middleware checks the machine's health status via the `healthChecker` interface. If the machine is quarantined, it rejects requests with 403 regardless of token validity.

---

## NATS Event Bus (`fleet_nats.go`)

NATS JetStream is the real-time event backbone. The broker, security services, supervisor, and gridwatch all pub/sub to the `FLEET` stream.

**Stream config:**
- Subject filter: `fleet.>`
- Retention: `LimitsPolicy` (not work-queue)
- Max age: 24 hours
- Max bytes: 256 MB
- Max messages per subject: 10,000
- Max message size: 32 KB
- Duplicate window: 2 minutes

**FleetEvent structure:**
```go
type FleetEvent struct {
    Type      string `json:"type"`
    PeerID    string `json:"peer_id,omitempty"`
    Machine   string `json:"machine,omitempty"`
    Summary   string `json:"summary,omitempty"`
    CWD       string `json:"cwd,omitempty"`
    Data      string `json:"data,omitempty"`
    Timestamp string `json:"timestamp"`
}
```

Security events carry a JSON-encoded `SecurityEvent` in the `Data` field. This allows consumers like `security-watch` and `response-daemon` to access the full alert details.

**NATS URL derivation:** If `nats_url` is not set, it's derived from `broker_url` by replacing the port with 4222. If the broker is at `http://10.0.0.1:7899`, NATS is assumed at `nats://10.0.0.1:4222`.

---

## Security Pipeline

### Wazuh Bridge (`security_wazuh.go`)

Tails `alerts.json` using raw `Read()` calls with a line buffer rather than `bufio.Scanner`, which handles continuous appends without blocking. Detects file rotation by comparing inodes every 10 seconds.

**Alert classification** maps Wazuh rule groups to NATS subjects:
| Group | Subject | Type |
|-------|---------|------|
| `quarantine` | `fleet.security.quarantine` | quarantine |
| `syscheck`, `fim` | `fleet.security.fim` | fim |
| `authentication`, `sshd`, `pam`, `sudo` | `fleet.security.auth` | auth |
| `process`, `new_port` | `fleet.security.process` | process |
| `network`, `non_tailscale` | `fleet.security.network` | network |
| (other) | `fleet.security.alert` | general |

Levels < 3 are dropped (noise). Rule 2501 is explicitly suppressed to prevent a feedback loop where Wazuh re-ingests its own log lines as authentication failures.

**Severity mapping:**
| Level | Severity | Health delta |
|-------|----------|-------------|
| 1-5 | info | 0 |
| 6-9 | warning | +1 (capped at 9) |
| 10-12 | critical | +10 |
| 13-15 | quarantine | status = quarantined |

### Security Watch (`security_watch.go`)

Long-running correlator. Subscribes to `fleet.security.>` and maintains a 30-minute sliding window of events per machine.

**Correlation rules:**
- **Distributed attack:** Same rule ID fires on 3+ machines within 5 minutes → escalate to quarantine, email
- **Brute force:** 5+ `auth` type events from same machine within 10 minutes → escalate, email
- **Credential theft:** FIM event on `identity.pem` or `token.jwt` followed by a peer registration event on same machine within 5 minutes → escalate, email

Email throttle: maximum 1 email per machine per 15 minutes.

### Response Daemon (`security_response.go`)

Subscribes to fleet events and classifies incidents by type:

| Incident | Trigger | Response Tier |
|----------|---------|---------------|
| `brute_force` | `quarantine` event with "brute" in data | Tier 2: forensics + IP block + email |
| `binary_tamper` | Rule 100101, level ≥ 13 | Tier 2: forensics + email |
| `rogue_service` | Rule 100130 | Tier 1: capture unit file + email |
| `credential_theft` | `quarantine` event with "credential" | Tier 3: forensics + email + approval gate |
| `lateral_movement` | `quarantine` event with "distributed" | Tier 3: forensics on all machines + email |
| `quarantine` | Any quarantine severity | Tier 1: email |

Incidents are deduplicated within a 30-minute window per machine+type. IP blocks expire after 1 hour and are removed automatically.

**Dry-run mode:** Set `RESPONSE_DRY_RUN=true` to log actions without executing them.

---

## Health Scoring Algorithm

Scores accumulate on security events and decay over time. The algorithm lives in `security_health.go`.

**Accumulation:**
```
warning event  → score += 1; if score > 9: score = 9  (warnings can degrade, never quarantine alone)
critical event → score += 10
quarantine event → status = "quarantined" (bypasses score)
```

**Status from score:**
```
score >= 10 → quarantined
score >= 5  → degraded
score < 5   → healthy
```

**Decay:** Every 5 minutes, non-quarantined machines lose 2 points (floor 0). A machine that had one critical event (score = 10) would be quarantined. After decay, it takes 5+ minutes to drop to degraded and another 2.5 minutes to return to healthy.

**Recovery from quarantine:** Requires explicit operator action:
```bash
claude-peers unquarantine <machine>
```
This resets score to 0 and status to "healthy".

---

## Daemon Supervisor (`supervisor_core.go`)

The supervisor discovers daemons by scanning the daemon directory for subdirectories containing a `.agent` file. Discovery happens at startup only (no hot-reload).

**Daemon lifecycle:**
1. Discover all daemons in `daemon_dir`
2. For each daemon, start a goroutine based on schedule type:
   - `interval:X` → sleep initial jitter (5–30s based on name hash), then tick every X
   - `event:subject` → subscribe to NATS subject, invoke on each matching event
3. On invocation:
   a. Check if already running (skip if yes)
   b. Check cooldown (skip if failed within last 5 minutes)
   c. Run `triage.sh` if it exists (exit 0 = proceed, exit 1 = skip)
   d. Execute agent binary with 15-minute hard timeout
   e. On 3rd consecutive failure, send email alert
   f. Publish result to `fleet.daemon.<name>` via NATS

**Environment filtering:** The daemon process only receives `PATH`, `HOME`, `USER`, `SHELL`, `LANG`, `TERM`, `TMPDIR`, `XDG_RUNTIME_DIR`, `OPENAI_API_KEY`, `LITELLM_API_KEY`, `ANTHROPIC_API_KEY`, and `SSH_AUTH_SOCK`. This prevents broker secrets, NATS tokens, and UCAN tokens from leaking into LLM-powered agent processes.

---

## Fleet Dream (`fleet_dream.go`)

The `dream` command snapshots current fleet state (peers, events, health) into a Markdown document and writes it to the broker's fleet memory endpoint (`POST /fleet-memory`). Claude Code sessions can read this via `GET /fleet-memory`.

`dream-watch` subscribes to NATS and re-runs the snapshot whenever significant fleet events arrive, keeping the memory document current without polling.

---

## Gridwatch Server (`gridwatch_server.go`)

A static-file + API server. The frontend is embedded in the binary via `//go:embed gridwatch-ui` and served directly.

**Data collection goroutines:**
- `collectStatsLoop` -- SSH to each machine every 5s, run a one-liner shell script, parse output for CPU/mem/disk/processes
- `collectPeersLoop` -- poll broker `/list-peers` and `/events` every 5s
- `collectSecurityLoop` -- poll broker `/machine-health` every 5s
- `runServiceMonitor` -- check configured services (Docker, Syncthing, systemd units) via SSH
- `collectLLMLoop` -- poll LiteLLM `/health`, `/props`, `/slots`, `/metrics` every 3s
- `subscribeNATS` -- consume `fleet.>` JetStream for real-time events

The SSH stat collection uses separate shell commands for Linux and macOS, with a `0.5s` sleep between `/proc/stat` reads to calculate CPU delta. Results are parsed from a structured text output (`CPU:`, `MEM:`, `DISK:`, `PROC:` prefixes) rather than JSON to minimize SSH round-trips.

**Ticker bus** (`gridwatch_ticker.go`): A ring buffer of events pushed to Server-Sent Events subscribers. Used for the live event feed in the UI. Gridwatch watches for status changes between polls and debounces: a machine must show the same status for 2 consecutive polls before an event is emitted.
