# Sontara Lattice

Self-hosted security monitoring and autonomous agent orchestration for AI fleets.

```
┌─────────────────────────────────────────────────────────────┐
│                    Sontara Lattice                          │
│                                                             │
│  Claude Code sessions  ──►  Trust Broker  ──►  NATS        │
│  Autonomous daemons    ──►  Wazuh EDR     ──►  Gridwatch   │
│  Fleet machines        ──►  UCAN tokens   ──►  Incidents   │
└─────────────────────────────────────────────────────────────┘
```

## What is this?

Sontara Lattice is a security-first platform for running autonomous AI agents across multiple machines. It provides:

- **Endpoint Detection & Response** -- Wazuh EDR monitors file integrity, auth logs, and process execution across your entire fleet with 25 custom rules tuned for AI infrastructure
- **Automated Incident Response** -- Detects brute force, credential theft, binary tampering, and lateral movement; captures forensics, blocks IPs, emails alerts automatically
- **Agent Supervisor** -- Manages background AI daemons with scheduling, triage gates, failure recovery, and 15-minute hard timeouts
- **Fleet Dashboard** -- 6-page real-time kiosk dashboard showing machine health, security events, NATS stream activity, and daemon status
- **Cryptographic Auth** -- UCAN (User Controlled Authorization Networks) with Ed25519 key pairs; every request requires a capability-scoped token chained to a root of trust
- **Real-time Events** -- NATS JetStream for fleet-wide event streaming with 24-hour retention and per-subject limits

**This is running in production** on a 7-machine Tailscale mesh (Arch, Ubuntu, Debian, macOS, Raspberry Pi).

---

## Quick Start

### Docker Compose (recommended)

```bash
git clone https://github.com/your-github-org/sontara-lattice.git
cd sontara-lattice
bash setup.sh
```

Select option 1. The script builds the stack, generates a NATS token, and waits for the broker to become healthy. Then:

```bash
# Initialize the broker keypair and root UCAN token
docker compose exec broker claude-peers init broker

# Check it's up
curl http://localhost:7899/health
```

Services after setup:
| Service | URL |
|---------|-----|
| Broker API | http://localhost:7899 |
| Gridwatch UI | http://localhost:8888 |
| NATS | nats://localhost:4222 |
| NATS Monitor | http://localhost:8222 |
| Wazuh Manager | https://localhost:55000 |

### Build from source

```bash
git clone https://github.com/your-github-org/sontara-lattice.git
cd sontara-lattice
go build -o claude-peers .
cp claude-peers ~/.local/bin/
```

Cross-compile for fleet machines:
```bash
# Linux arm64 (Raspberry Pi 5, Apple Silicon)
GOOS=linux GOARCH=arm64 go build -o claude-peers-linux-arm64 .

# Linux amd64
GOOS=linux GOARCH=amd64 go build -o claude-peers-linux-amd64 .

# macOS Apple Silicon
GOOS=darwin GOARCH=arm64 go build -o claude-peers-darwin-arm64 .
```

### Manual setup (no Docker)

**On the broker machine:**
```bash
claude-peers init broker
claude-peers broker &
```

**On each client machine:**
```bash
claude-peers init client http://<broker-ip>:7899

# Copy root.pub from broker to ~/.config/claude-peers/root.pub
scp broker:~/.config/claude-peers/root.pub ~/.config/claude-peers/root.pub

# On the broker, issue a token for this machine
claude-peers issue-token /path/to/this-machine-identity.pub peer-session
# (output is a JWT)

# On this machine, save it
claude-peers save-token <jwt>
```

---

## Architecture

```
                        ┌──────────────────────────────────────────┐
                        │            Trust Broker (HTTP)           │
                        │  SQLite ── UCAN Validator ── Health Map  │
                        └─────────────┬────────────────────────────┘
                                      │ REST API (UCAN auth)
          ┌───────────────────────────┼───────────────────────┐
          │                           │                       │
    ┌─────▼──────┐            ┌───────▼──────┐        ┌──────▼──────┐
    │ Claude Code│            │   Daemon     │        │  Gridwatch  │
    │  (MCP srv) │            │  Supervisor  │        │  Dashboard  │
    └─────┬──────┘            └───────┬──────┘        └──────┬──────┘
          │                           │                       │
          └───────────────────────────▼───────────────────────┘
                              NATS JetStream (fleet.>)
                    ┌─────────────────┬────────────────────┐
                    │                 │                    │
             ┌──────▼─────┐   ┌───────▼──────┐   ┌───────▼──────┐
             │Wazuh Bridge │   │Security Watch│   │  Response    │
             │ (tail logs) │   │ (correlator) │   │  Daemon      │
             └──────┬──────┘   └───────┬──────┘   └──────────────┘
                    │                  │
             ┌──────▼──────────────────▼──────┐
             │         Wazuh Manager          │
             │  (FIM, auth logs, proc monitor)│
             └────────────────────────────────┘
```

**Data flow for security events:**
1. Wazuh agent on fleet machine detects file change, auth failure, or process anomaly
2. Wazuh manager writes JSON to `alerts.json`
3. `wazuh-bridge` tails the file and publishes `SecurityEvent` to `fleet.security.*` via NATS
4. Broker's `subscribeSecurityEvents` goroutine updates the machine's health score
5. `security-watch` correlator checks for distributed attacks, brute force, credential theft
6. On escalation: `security-watch` publishes to `fleet.security.quarantine`
7. `response-daemon` captures forensics, blocks IPs, sends email, updates incident state

**Data flow for agent coordination:**
1. Claude Code starts, MCP server auto-registers with broker via `/register`
2. Peer gets an ID, heartbeats every 30s
3. Other sessions call `/list-peers` and see each other
4. Broker publishes `fleet.peer.joined` to NATS
5. Gridwatch receives the NATS event and updates the dashboard in real time

---

## Security Features

**Cryptographic identity** -- every machine has an Ed25519 keypair. Tokens are JWTs signed with EdDSA. The broker validates every token against the fleet root public key. Delegation chains are verified: a child token cannot have capabilities its parent didn't have.

**Capability scoping** -- tokens carry exactly the capabilities they need. A `peer-session` token can register and message but cannot write fleet memory. A `fleet-read` token can list peers and read events but cannot send messages.

**Health scoring** -- machines accumulate a score as security events arrive. Warning events add 1 point; critical events add 10. Score ≥ 5 = degraded; score ≥ 10 = quarantined (capabilities revoked). Scores decay by 2 every 5 minutes for non-quarantined machines. Quarantine requires explicit `claude-peers unquarantine <machine>`.

**25 custom Wazuh rules** covering:
- UCAN credential file modification (level 12)
- Binary tampering in system paths (level 13)
- SSH key changes (level 10)
- Shell startup file persistence (level 10)
- DNS config modification (level 12)
- LD_PRELOAD injection (level 13)
- PAM config changes (level 10)
- Cron persistence (level 9)
- Syncthing config (level 10, exfil detection)
- Sudoers modification (level 13)
- Kernel module persistence (level 12)
- And more

**Automated response** tiers:
- Tier 1: Email alert
- Tier 2: Forensics snapshot + IP block + email
- Tier 3: Forensics on all affected machines + email with rotation notice + approval gate

---

## Dashboard

The Gridwatch dashboard is embedded in the binary and serves over HTTP. Start it:

```bash
# With gridwatch.json config
claude-peers gridwatch

# Or via Docker Compose
docker compose up gridwatch
```

Configure machines in `~/.config/claude-peers/gridwatch.json`:
```json
{
  "port": 8888,
  "machines": [
    {"id": "server", "host": "user@10.0.0.1", "os": "ubuntu", "specs": "32GB RAM"},
    {"id": "local",  "host": "",              "os": "arch",   "specs": "16GB RAM"}
  ],
  "nats_url": "nats://localhost:4222"
}
```

Pages: Fleet, Services, NATS, Agents, Peers, Security. See [docs/DASHBOARD.md](docs/DASHBOARD.md) for full details.

---

## Attack Simulations

Test your detection and response pipeline:

```bash
# Single scenario (default target: edge-node)
claude-peers sim-attack brute-force
claude-peers sim-attack credential-theft --target=myserver
claude-peers sim-attack binary-tamper --dry-run

# All 16 scenarios
claude-peers sim-attack --all

# Multiple targets for lateral movement
claude-peers sim-attack lateral-movement --target=machine1,machine2
```

Available scenarios:
`brute-force`, `credential-theft`, `binary-tamper`, `rogue-service`, `lateral-movement`, `ssh-key-swap`, `cron-persistence`, `shell-persistence`, `config-tamper`, `shell-rc-persist`, `cron-persist`, `dns-hijack`, `ld-preload`, `pam-tamper`, `syncthing-exfil`, `message-flood`, `token-replay`

Note: `dns-hijack`, `ld-preload`, `pam-tamper` require sudo on the target. They gracefully skip if absent.

---

## Configuration

Config file: `~/.config/claude-peers/config.json`

```json
{
  "role": "client",
  "broker_url": "http://10.0.0.1:7899",
  "machine_name": "myhost",
  "nats_url": "nats://10.0.0.1:4222",
  "nats_token": "your-nats-token",
  "llm_base_url": "http://10.0.0.1:4000/v1",
  "llm_model": "vertex_ai/claude-sonnet-4-6",
  "llm_api_key": "sk-...",
  "alert_email": "you@example.com",
  "fleet_targets": {
    "server": "user@10.0.0.1",
    "laptop": "user@10.0.0.2"
  }
}
```

All fields have environment variable overrides:

| Field | Env var |
|-------|---------|
| `broker_url` | `CLAUDE_PEERS_BROKER_URL` |
| `listen` | `CLAUDE_PEERS_LISTEN` |
| `machine_name` | `CLAUDE_PEERS_MACHINE` |
| `db_path` | `CLAUDE_PEERS_DB` |
| `nats_url` | `CLAUDE_PEERS_NATS` |
| `nats_token` | `CLAUDE_PEERS_NATS_TOKEN` |
| `daemon_dir` | `CLAUDE_PEERS_DAEMONS` |
| `llm_base_url` | `CLAUDE_PEERS_LLM_URL` |
| `llm_model` | `CLAUDE_PEERS_LLM_MODEL` |
| `llm_api_key` | `CLAUDE_PEERS_LLM_API_KEY` |
| `wazuh_alerts_path` | `WAZUH_ALERTS_PATH` |

Key files in `~/.config/claude-peers/`:
| File | Purpose |
|------|---------|
| `config.json` | Runtime configuration |
| `identity.pem` | Ed25519 private key (mode 0600) |
| `identity.pub` | Ed25519 public key |
| `root.pub` | Fleet root public key (from broker) |
| `token.jwt` | UCAN capability token (mode 0600) |
| `root-token.jwt` | Root UCAN token (broker only) |

---

## Custom Daemons

Daemons live in `./daemons/<name>/` and require a `.agent` file at minimum:

```
daemons/
  my-daemon/
    my-daemon.agent   # Agent prompt and goals (required)
    daemon.json       # Schedule config (optional, default: interval:15m)
    agent.toml        # LLM provider config (optional)
    policy.toml       # Tool allowlists and safety constraints (optional)
    triage.sh         # Gate script: exit 0 = run, exit 1 = skip (optional)
```

**daemon.json:**
```json
{
  "schedule": "interval:30m",
  "description": "Monitor log files for errors"
}
```

Schedule formats:
- `interval:15m` -- run every 15 minutes
- `event:fleet.peer.joined` -- run on NATS events matching this subject
- `cron:*/30 * * * *` -- cron expression (5-field)

See [docs/DAEMONS.md](docs/DAEMONS.md) for the full guide including examples.

---

## Broker API

All endpoints except `/health` require a UCAN Bearer token.

| Method | Path | Capability | Description |
|--------|------|-----------|-------------|
| GET | `/health` | public | Broker status |
| POST | `/register` | `peer/register` | Register a peer |
| POST | `/heartbeat` | `peer/heartbeat` | Keep-alive |
| POST | `/list-peers` | `peer/list` | Discover peers |
| POST | `/send-message` | `msg/send` | Send a message |
| POST | `/poll-messages` | `msg/poll` | Receive messages |
| POST | `/set-summary` | `peer/set-summary` | Update work summary |
| GET | `/events` | `events/read` | Recent broker events |
| GET | `/fleet-memory` | `memory/read` | Fleet memory document |
| POST | `/fleet-memory` | `memory/write` | Update fleet memory |
| GET | `/machine-health` | `events/read` | Per-machine health scores |
| POST | `/unquarantine` | `memory/write` | Restore quarantined machine |
| POST | `/refresh-token` | (valid/expired token) | Renew UCAN token |
| POST | `/challenge` | public | Ed25519 challenge-response |

---

## NATS Subjects

All events use `fleet.>` with a 24-hour retention window.

| Subject | Publisher | Content |
|---------|-----------|---------|
| `fleet.peer.joined` | Broker | Peer registration events |
| `fleet.peer.left` | Broker | Peer departure events |
| `fleet.summary` | Broker | Summary changes |
| `fleet.message` | Broker | Message delivery |
| `fleet.security.fim` | Wazuh bridge | File integrity alerts |
| `fleet.security.auth` | Wazuh bridge | Authentication events |
| `fleet.security.process` | Wazuh bridge | Process anomalies |
| `fleet.security.network` | Wazuh bridge | Network events |
| `fleet.security.quarantine` | Wazuh bridge / security-watch | Quarantine triggers |
| `fleet.daemon.<name>` | Supervisor | Daemon run results |
| `fleet.commit` | Fleet git | Git push events |

---

## Dependencies

- **Go 1.23+**
- **NATS Server** with JetStream (bundled in Docker Compose)
- **Wazuh Manager 4.14.x** + Wazuh agents on fleet machines (bundled in Docker Compose)
- **[vinayprograms/agent](https://github.com/vinayprograms/agent)** -- required for daemon supervisor (LLM agent runtime)
- `golang-jwt/jwt/v5` -- UCAN/JWT token implementation
- `nats-io/nats.go` -- NATS client
- `modernc.org/sqlite` -- broker persistent storage (pure Go, no CGO)

---

## Further Reading

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) -- component internals, data flows, health scoring
- [docs/SECURITY.md](docs/SECURITY.md) -- threat model, Wazuh rules, attack simulations, hardening
- [docs/DAEMONS.md](docs/DAEMONS.md) -- writing and deploying custom daemons
- [docs/DASHBOARD.md](docs/DASHBOARD.md) -- Gridwatch setup and customization
- [docs/GCP.md](docs/GCP.md) -- deploying on Google Cloud
- [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) -- step-by-step first-time setup

---

## License

MIT
