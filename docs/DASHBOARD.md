# Gridwatch Dashboard

Gridwatch is the fleet observability dashboard built into Sontara Lattice. It provides real-time visibility into machine health, active Claude sessions, security status, daemon activity, and NATS event flow.

The dashboard UI is embedded in the `claude-peers` binary and served directly -- no separate web server needed.

---

## Starting the Dashboard

**Prerequisites:** A `gridwatch.json` config file defining your machines.

```bash
# Default config location
~/.config/claude-peers/gridwatch.json

# Or specify via env
GRIDWATCH_CONFIG=/path/to/gridwatch.json claude-peers gridwatch

# Or via Docker Compose
docker compose up gridwatch
```

The dashboard starts on port 8888 by default. Access it at `http://localhost:8888`.

---

## Configuration

Create `~/.config/claude-peers/gridwatch.json`:

```json
{
  "port": 8888,
  "machines": [
    {
      "id": "server",
      "host": "user@10.0.0.1",
      "os": "ubuntu",
      "specs": "32GB RAM",
      "ip": "10.0.0.1"
    },
    {
      "id": "workstation",
      "host": "",
      "os": "arch",
      "specs": "16GB RAM",
      "ip": ""
    },
    {
      "id": "macbook",
      "host": "user@10.0.0.2",
      "os": "macos",
      "specs": "M1 Pro",
      "ip": "10.0.0.2"
    },
    {
      "id": "raspi",
      "host": "user@10.0.0.3",
      "os": "ubuntu",
      "specs": "16GB RAM",
      "ip": "10.0.0.3"
    }
  ],
  "llm_url": "http://10.0.0.1:4000",
  "nats_url": "nats://10.0.0.1:4222",
  "nats_monitor_url": "http://10.0.0.1:8222"
}
```

**Machine fields:**
| Field | Required | Description |
|-------|----------|-------------|
| `id` | yes | Unique identifier, shown in tiles and security page |
| `host` | no | SSH target (`user@host` or alias). Empty = local machine |
| `os` | yes | `"ubuntu"`, `"arch"`, `"debian"`, or `"macos"` |
| `specs` | no | Free-form hardware description shown in tile |
| `ip` | no | IP shown in tile |

**Optional top-level fields:**
| Field | Description |
|-------|-------------|
| `port` | HTTP port to listen on (default: 8888) |
| `llm_url` | LiteLLM or llama.cpp server base URL (enables LLM tile) |
| `nats_url` | NATS server URL (enables real-time NATS page) |
| `nats_monitor_url` | NATS HTTP monitoring endpoint (enables NATS stats) |

The broker URL is read from the main `config.json` (`broker_url`). Gridwatch uses it to fetch peers, events, and machine health.

---

## Dashboard Pages

The dashboard has 6 pages that auto-rotate. Click any page header to jump to it directly.

### 1. Fleet

The primary page. Shows a tile for each machine with:
- **Status indicator** -- online (green), degraded (yellow), offline (red), timeout (orange)
- **CPU %** -- real-time from `/proc/stat` (Linux) or `ps` sum (macOS)
- **Memory %** -- used / total
- **Disk %** -- root filesystem usage; turns red at 85%
- **Top processes** -- 5 highest memory consumers by name
- **Uptime**
- **Active Claude peers** -- count from broker
- **LLM status** (if `llm_url` configured) -- online/offline, model name, active slots

Machine stats are collected via SSH every 5 seconds using a compact one-liner shell command. Machines that fail SSH within 8 seconds show as `timeout`; machines unreachable at all show as `offline`.

### 2. Services

Monitored services across the fleet. Currently tracks:
- Docker daemon status via SSH (`docker info`)
- Syncthing status
- Configured systemd units

Services are collected alongside machine stats. A service appears red if its check fails.

### 3. NATS

Shows the JetStream stream status:
- Connection state (connected / disconnected)
- Recent fleet events (last 50), displayed as a live feed
- Daemon run history (last 20 daemon completions/failures)

Updates in real time as events arrive from the NATS subscription.

### 4. Agents

Daemon supervisor activity:
- Each known daemon with its last run status (complete, failed, running)
- Run duration
- Trigger type (startup, interval, nats event)
- Output summary extracted from agent output JSON

Daemon data comes from the `fleet.daemon.<name>` NATS subjects published by the supervisor.

### 5. Peers

Active Claude Code sessions across the fleet:
- Session ID (short hex)
- Machine name
- Working directory and git branch
- Current work summary (set by the session via `set_summary`)
- Time since last heartbeat
- TTY

Also shows recent broker events (peer joins, leaves, summary changes) from the `/events` endpoint.

### 6. Security

Per-machine Wazuh EDR status from the broker's `/machine-health` endpoint:
- Health score (0-15)
- Status: healthy / degraded / quarantined
- Last security event description
- Recent event history (last 10 events per machine)
- Demotion timestamp for quarantined machines

This page updates every 5 seconds.

---

## Live Ticker

All pages show a scrolling ticker at the bottom with real-time events:
- Machine status changes (online, offline, timeout)
- Disk usage alerts (>85%)
- Peer joins and leaves
- Daemon completions and failures
- Security events from Wazuh

The ticker uses Server-Sent Events (SSE) via `/api/ticker`. Events are stored in a ring buffer of 100 entries.

---

## Kiosk Mode Setup

The dashboard is designed to run unattended on a dedicated display.

**Chromium in kiosk mode:**
```bash
chromium --kiosk --noerrdialogs --disable-infobars --app=http://localhost:8888
```

**Auto-page rotation:** The dashboard auto-rotates through all 6 pages on a configurable interval (set in the UI's JavaScript, default varies). Individual pages can be pinned by clicking their header.

**Systemd service for kiosk:**
```ini
# ~/.config/systemd/user/gridwatch-kiosk.service
[Unit]
Description=Gridwatch fleet dashboard
After=network.target

[Service]
ExecStart=%h/.local/bin/claude-peers gridwatch
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
```

```bash
systemctl --user enable --now gridwatch-kiosk
```

**Display autostart** (for headless kiosk with Wayland/Hyprland):
```bash
# In hyprland config or autostart
chromium --kiosk http://localhost:8888 &
```

---

## Responsive Web Mode

The dashboard is also usable from a browser on any device on your network. Set `listen` to `0.0.0.0:8888` (or any accessible interface) and open `http://<machine-ip>:8888` from a phone or laptop.

The UI uses flexbox layout and scales for both 1080p kiosk displays and mobile screens.

---

## API Endpoints

The dashboard backend exposes these endpoints directly:

| Path | Description |
|------|-------------|
| `GET /api/stats` | Machine stats (CPU, mem, disk, processes, uptime) |
| `GET /api/peers` | Active peers and recent broker events |
| `GET /api/security` | Per-machine health scores from broker |
| `GET /api/nats` | NATS connection state, recent events, daemon runs |
| `GET /api/daemons` | Daemon run history |
| `GET /api/services` | Service monitor results |
| `GET /api/llm` | LLM server health and slot status |
| `GET /api/nats-stats` | NATS HTTP monitor data |
| `GET /api/ticker` | SSE stream of live events |

All responses are JSON. Useful for building custom dashboards or alerting integrations:

```bash
# Check security health programmatically
curl http://localhost:8888/api/security | python3 -m json.tool

# Watch fleet events as SSE
curl -N http://localhost:8888/api/ticker
```

---

## Adding Machines

Edit `gridwatch.json` and restart the gridwatch process. New machines appear as tiles on the Fleet page on the next collection cycle (within 5 seconds).

```bash
# On Docker Compose
docker compose restart gridwatch

# Manual
pkill -f 'claude-peers gridwatch'
claude-peers gridwatch &
```

SSH access must work from the machine running gridwatch to each fleet machine. Use `~/.ssh/config` to configure key, user, and hostname aliases. Gridwatch uses `ConnectTimeout=4` and `StrictHostKeyChecking=no` for SSH connections.
