# Daemon Guide

Daemons are background AI agent workflows managed by the supervisor. Each daemon is a directory containing an agent prompt and optional configuration files. The supervisor handles scheduling, triage, failure recovery, and reporting.

---

## Directory Structure

```
daemons/
  my-daemon/
    my-daemon.agent    # Agent prompt and goals (required, any .agent filename)
    daemon.json        # Schedule and description (optional)
    agent.toml         # LLM provider configuration (optional)
    policy.toml        # Tool allowlists and path restrictions (optional)
    triage.sh          # Gate script run before each invocation (optional)
```

The supervisor scans the daemon directory on startup. Any subdirectory containing a `.agent` file is treated as a daemon. Directories without a `.agent` file are ignored.

---

## File Reference

### `.agent` file

The agent prompt file. This is the only required file. The format is defined by the [vinayprograms/agent](https://github.com/vinayprograms/agent) binary.

```
# my-daemon.agent

description: Monitor fleet error logs and summarize anomalies

goals:
  - scan: Check recent error logs on all fleet machines via SSH
  - analyze: Identify recurring patterns or new error types
  - report: Output a summary of findings

context:
  - Fleet machines are accessible via SSH using aliases in ~/.ssh/config
  - Focus on errors from the last 2 hours only
  - Skip machines that are offline (SSH timeout within 5 seconds)
```

### `daemon.json`

Controls scheduling and provides a description for logging/dashboard display.

```json
{
  "schedule": "interval:30m",
  "description": "Monitor fleet error logs and summarize anomalies"
}
```

**Schedule formats:**

| Format | Example | Behavior |
|--------|---------|----------|
| `interval:X` | `interval:15m` | Run every X (Go duration: 15m, 1h, 30s) |
| `event:subject` | `event:fleet.peer.joined` | Run when matching NATS event arrives |
| `cron:EXPR` | `cron:0 * * * *` | Run on cron schedule (5-field) |

If `daemon.json` is missing, the schedule defaults to `interval:15m`.

**Event subjects** support the wildcard pattern from `fleet.>`. The match uses substring matching on event type: an event with type `fleet.peer.joined` matches subject pattern `fleet.peer.joined` or `fleet.peer.>`. If the NATS subscription fails, the daemon falls back to `interval:15m`.

### `agent.toml`

LLM provider configuration for the agent binary. If absent, the agent uses its built-in defaults.

```toml
[llm]
provider = "openai-compat"
model = "claude-sonnet-4-6"
max_tokens = 16384
base_url = "http://10.0.0.1:4000/v1"
api_key_env = "OPENAI_API_KEY"

[small_llm]
provider = "openai-compat"
model = "claude-haiku-4-5"
max_tokens = 4096
base_url = "http://10.0.0.1:4000/v1"
api_key_env = "OPENAI_API_KEY"
```

The `base_url` should point to a LiteLLM proxy or any OpenAI-compatible endpoint. The API key is read from the environment variable named in `api_key_env`.

### `policy.toml`

Restricts the tools available to the agent. Prevents daemons from taking destructive or out-of-scope actions.

```toml
[tools]
allowed = ["bash", "read_file", "write_file"]
denied = ["web_search", "git_commit"]

[paths]
allowed = ["~/logs", "/tmp"]
denied = ["/etc", "/root", "~/.config/claude-peers"]

[limits]
max_tokens = 8192
max_tool_calls = 50
```

### `triage.sh`

A shell script run before each daemon invocation. Exit 0 means there is work to do (proceed). Exit 1 means there is no work (skip this run).

The supervisor logs the triage result and stdout. If triage exits 1, the daemon is skipped without being counted as a failure.

```bash
#!/bin/bash
# Skip if nothing new in the last interval
last_run_marker="/tmp/.my-daemon-last-run"
if [ -f "${last_run_marker}" ]; then
    # Check if any target files are newer than the marker
    newer=$(find /path/to/logs -newer "${last_run_marker}" -name "*.log" 2>/dev/null | wc -l)
    if [ "${newer}" -eq 0 ]; then
        echo "no new log files"
        exit 1
    fi
fi
touch "${last_run_marker}"
echo "found new log files"
exit 0
```

---

## Triage Flow

The supervisor's invocation sequence for each daemon:

```
invoke(daemon, trigger)
  ├── already running?  → skip (logged)
  ├── failed within 5 min?  → skip (cooldown)
  ├── triage.sh exists?
  │     ├── exit 0  → proceed (log "triage pass: <stdout>")
  │     └── exit 1  → skip (log "triage skip: <stdout>")
  └── run agent binary (15-min hard timeout)
        ├── success  → reset fail count, publish to NATS, log
        └── failure  → increment fail count
              └── fail count == 3  → send email alert
```

---

## Scheduling Details

**Interval daemons** start with a small jitter based on the daemon name's length (5–30 seconds). This prevents all daemons from running simultaneously on startup.

**Event daemons** create a durable NATS consumer. The consumer is named `supervisor-<daemon-name>`. If the NATS subscription fails at startup, the daemon falls back to 15-minute interval scheduling.

**Concurrency:** Only one instance of a daemon runs at a time. If a daemon is already running when its next trigger fires, the trigger is dropped with a log message.

**Failure cooldown:** After any failure, the daemon is suppressed for 5 minutes before it can run again. This prevents rapid retry loops on persistent failures.

---

## Environment

Daemons receive a filtered environment. Only these variables are passed to the agent process:

```
PATH, HOME, USER, SHELL, LANG, TERM, TMPDIR, XDG_RUNTIME_DIR
OPENAI_API_KEY, LITELLM_API_KEY, ANTHROPIC_API_KEY
SSH_AUTH_SOCK
```

This is intentional. The broker auth token, NATS token, and UCAN credentials are **not** available to daemon processes. Daemons should not need direct broker access; they operate on fleet data via SSH, file system, or LLM calls.

If your daemon needs broker access, issue it a separate `fleet-read` token and inject it via a mechanism outside the daemon directory (e.g., an env var set in the systemd unit file for the supervisor).

---

## Built-in Daemons

The repo ships these daemons in `daemons/`:

| Daemon | Schedule | Description |
|--------|----------|-------------|
| `fleet-digest` | 60m | Compiles an hourly fleet status report and emails it |
| `fleet-scout` | 10m | Checks health of all machines and services, logs anomalies |
| `librarian` | 3h | Audits and updates documentation across fleet machines |
| `llm-watchdog` | 10m | Monitors LLM server health and restarts if down |
| `pr-helper` | 15m | Keeps GitHub pull requests mergeable |
| `sync-janitor` | 15m | Detects and reports Syncthing conflicts |

All built-in daemons include EDR-aware triage gates. The `librarian` triage, for example, checks the broker's `/machine-health` endpoint and reports how many machines are unhealthy, so the agent can audit more carefully when the fleet is under stress.

---

## Example: Simple Health Check Daemon

A minimal daemon that checks disk usage on all fleet machines and logs a warning if any machine exceeds 80%.

**daemons/disk-check/disk-check.agent:**
```
description: Check disk usage on all fleet machines

goals:
  - check: Run "df -h /" on each fleet machine via SSH and record disk usage
  - alert: If any machine is above 80% disk usage, include it in the output with current percentage
  - report: Output a one-line summary, e.g. "All machines OK" or "WARNING: server1 at 87%"
```

**daemons/disk-check/daemon.json:**
```json
{
  "schedule": "interval:30m",
  "description": "Check fleet disk usage"
}
```

**daemons/disk-check/triage.sh:**
```bash
#!/bin/bash
# Always run disk checks -- no triage skip
echo "disk check scheduled"
exit 0
```

That's it. No `agent.toml` needed if the supervisor is configured with `llm_base_url` and `llm_model` at the top level in `config.json`.

---

## Example: Event-triggered Log Monitor

A daemon that runs whenever a peer joins the fleet, checking if the new peer's machine has any recent errors.

**daemons/new-peer-check/new-peer-check.agent:**
```
description: Check a newly-joined fleet machine for health issues

goals:
  - identify: Determine which machine just joined from the NATS event context
  - check: SSH to that machine and review the last 50 lines of journalctl for errors
  - report: Output any errors found, or "Machine <name> looks healthy" if none
```

**daemons/new-peer-check/daemon.json:**
```json
{
  "schedule": "event:fleet.peer.joined",
  "description": "Health check triggered on peer join"
}
```

When a new peer registers with the broker, the broker publishes a `fleet.peer.joined` event to NATS. The supervisor's NATS subscription delivers it to this daemon's goroutine, which runs the agent with the event data available in the working directory.

---

## Supervisor Configuration

The supervisor binary and daemon directory are resolved in this order:

**Agent binary (`agent_bin`):**
1. `agent_bin` in config.json
2. `agent` in PATH
3. `~/projects/vinay-agent/bin/agent`
4. `~/.local/bin/agent`
5. Fatal if not found

**Daemon directory (`daemon_dir`):**
1. `daemon_dir` in config.json
2. `CLAUDE_PEERS_DAEMONS` env var
3. `./daemons/` relative to repo root (detected by walking up from cwd)
4. `~/claude-peers-daemons/`
5. `~/.config/claude-peers/daemons/`
6. Directory next to the `claude-peers` executable
7. Fatal if not found

Start the supervisor:
```bash
claude-peers supervisor
```

Or with Docker Compose (the `supervisor` service in `docker-compose.yml`).
