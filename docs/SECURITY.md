# Security

Sontara Lattice is built around the assumption that your AI infrastructure is a target. This document covers the threat model, what's monitored, the detection rule set, response actions, and how to harden a deployment.

---

## Threat Model

**What we're protecting:**
- UCAN tokens and Ed25519 private keys that grant access to the fleet broker
- The broker itself (SQLite, fleet memory, peer registry)
- AI daemon workflows and their outputs
- The machines running Claude Code sessions and autonomous daemons

**Attacker capabilities we assume:**
- SSH brute force against any publicly-exposed machine
- Compromise of one fleet machine (use it as a pivot)
- Attempt to steal UCAN tokens from disk and replay them
- Tamper with binaries or daemon configs to redirect agent behavior
- Add persistence mechanisms (cron, shell RC, systemd units)

**What we do not protect against:**
- A compromised broker machine (the broker is the trust anchor; if it's owned, rotate everything)
- Physical access to machines
- Compromise of the LLM provider

---

## What Is Monitored

### File Integrity (Wazuh FIM)

Wazuh agents monitor these paths in real time:

**UCAN credentials:**
- `~/.config/claude-peers/identity.pem` (private key)
- `~/.config/claude-peers/token.jwt`
- `~/.config/claude-peers/root.pub`
- `~/.config/claude-peers/config.json`

**Binaries:**
- `~/.local/bin/claude-peers` (expected update path)
- `/usr/local/bin/claude-peers` (tamper path)
- `/usr/bin/claude-peers` (tamper path)

**Persistence vectors:**
- `~/.bashrc`, `~/.zshrc`, `~/.profile`, `~/.bash_profile`
- `/var/spool/cron`, `/etc/crontab`, `/etc/cron.*`
- `/etc/environment`, `/etc/profile.d/`
- `~/.config/autostart/` (XDG desktop persistence)
- `~/.config/systemd/user/` (user systemd units)
- `/etc/systemd/` (system-wide systemd units)

**Privilege escalation:**
- `/etc/sudoers`
- `/etc/pam.d/` (PAM auth bypass)

**Infrastructure:**
- `~/.ssh/id_*`, `~/.ssh/authorized_keys`, `~/.ssh/config`
- `/etc/hosts`, `/etc/resolv.conf`, `/etc/nsswitch.conf` (DNS hijack)
- `/etc/ld.so.preload` (binary hooking)
- `/etc/modules-load.d/` (rootkit persistence)
- `/etc/udev/rules.d/` (device-triggered persistence)
- `~/.config/syncthing/` (exfil setup)
- `go.sum` (supply chain)
- `claude-peers-daemons/` directories (daemon hijack)

### Authentication Logs

Wazuh monitors PAM, sshd, and sudo logs. Default Wazuh rules detect brute force attempts, invalid user login attempts, and privilege escalations.

### Process Execution

Wazuh process monitoring detects new listener ports and unexpected process starts.

---

## Detection Rules

Custom rules are in `wazuh/local_rules.xml`. All rules belong to group `claude-peers`.

| Rule ID | Level | Description | Groups |
|---------|-------|-------------|--------|
| 100099 | 7 | claude-peers binary deployed to `~/.local/bin/` | fim, binary_deploy |
| 100100 | 12 | UCAN credential file modified (identity.pem, token.jwt, root.pub) | fim, credential_change |
| 100101 | 13 | claude-peers binary tampered in system path (/usr/local/bin, /usr/bin) | fim, binary_tamper |
| 100102 | 10 | SSH key or auth config modified | fim, ssh_key_change |
| 100110 | 10 | Shell startup file modified (possible persistence) | fim, shell_persistence |
| 100111 | 9 | Crontab modified | fim, cron_persistence |
| 100112 | 10 | System environment modified (/etc/environment, /etc/profile.d/) | fim, env_persistence |
| 100113 | 11 | claude-peers config.json modified (possible MITM) | fim, config_tamper |
| 100114 | 9 | System cron config modified (/etc/cron.*) | fim, cron_persistence |
| 100115 | 12 | DNS config modified (/etc/hosts, resolv.conf, nsswitch.conf) | fim, dns_hijack |
| 100116 | 11 | go.sum modified (possible supply chain attack) | fim, supply_chain |
| 100117 | 11 | Daemon config modified (possible daemon hijack) | fim, daemon_hijack |
| 100118 | 10 | Syncthing config modified (possible exfil setup) | fim, syncthing_tamper |
| 100119 | 13 | ld.so.preload modified (binary hooking attack) | fim, ld_preload |
| 100130 | 9 | Systemd unit file changed | fim, persistence |
| 100200 | 15 | QUARANTINE: credential + binary change on same host (within 5 min) | quarantine |
| 100201 | 13 | QUARANTINE: shell persistence + SSH key change on same host (within 5 min) | quarantine |
| 100202 | 10 | PAM config modified (possible auth bypass) | fim, pam_tamper |
| 100203 | 12 | Kernel module load config modified (possible rootkit) | fim, kernel_module |
| 100204 | 9 | udev rules modified (device-triggered persistence) | fim, udev_persistence |
| 100205 | 13 | sudoers modified (possible privilege escalation) | fim, privesc |
| 100206 | 10 | /etc/environment modified | fim, env_persistence |
| 100207 | 8 | XDG autostart entry modified | fim, xdg_persistence |
| 100208 | 9 | User systemd unit modified | fim, systemd_persistence |

**Composite rules (100200, 100201)** use Wazuh's `frequency`+`timeframe` correlation to fire when two related events happen on the same source IP within 300 seconds.

### Severity to Health Score

When the Wazuh bridge publishes events to NATS, the broker maps Wazuh levels to health score impacts:

| Level | Severity | Health Impact |
|-------|----------|--------------|
| 1-5 | info | None (logged, not scored) |
| 6-9 | warning | +1 (capped at 9; warnings never quarantine alone) |
| 10-12 | critical | +10 (may immediately quarantine) |
| 13-15 | quarantine | Machine status = quarantined immediately |

---

## Incident Response

### Automated Actions

The `response-daemon` listens on NATS and executes responses based on incident type:

**Brute force (Tier 2):**
1. Capture forensic snapshot (last 100 auth log lines, active connections, running processes)
2. Block source IP via firewall rule on the affected machine (iptables/ufw, expires in 1 hour)
3. Send email alert with incident details

**Binary tamper (Tier 2):**
1. Capture forensic snapshot including SHA-256 hash of the modified file
2. Send email alert

**Rogue service (Tier 1):**
1. Capture the systemd unit file content via SSH
2. Send email alert

**Credential theft (Tier 3):**
1. Capture forensic snapshot
2. Send email with explicit notice that credential rotation is required
3. Set incident status to `approval_pending` (no automatic quarantine)

**Lateral movement (Tier 3):**
1. Capture forensics on ALL affected machines in parallel
2. Send email with full fleet audit requirement
3. Set incident status to `approval_pending`

**IP Block behavior:**
- Blocks are added via SSH to the affected machine
- Duration: 1 hour (configurable via `RESPONSE_FORENSIC_DIR` environment)
- Auto-expires: a goroutine checks and removes expired blocks every 60 seconds
- Tailscale IPs (100.x.x.x) are never blocked

**Forensics:** Snapshots are saved to `~/.config/claude-peers/forensics/<incident-id>/` on the machine running the response daemon.

### Manual Recovery

After a quarantine event:

```bash
# Remove quarantine flag from broker
claude-peers unquarantine <machine>

# Re-verify the machine's binaries and credentials
ssh <machine> sha256sum ~/.local/bin/claude-peers
ssh <machine> ls -la ~/.config/claude-peers/

# If credentials were compromised, rotate
ssh <machine> rm ~/.config/claude-peers/token.jwt
claude-peers reauth-fleet  # re-issues tokens for all machines via SSH
```

---

## Attack Simulation Guide

The `sim-attack` command lets you test your detection and response pipeline end-to-end. Simulations are designed to trigger Wazuh alerts and verify that events flow from Wazuh → NATS → health scores → email alerts.

### Running simulations

```bash
# Dry run (describe what would happen, no actual execution)
claude-peers sim-attack brute-force --dry-run

# Target a specific machine (default: edge-node)
claude-peers sim-attack brute-force --target=myserver

# Run all 16 simulations sequentially
claude-peers sim-attack --all --target=myserver
```

The tool refuses to target `broker-server` (the broker) without an explicit confirmation prompt.

### Available scenarios

| Scenario | What it does | Detects via |
|----------|-------------|-------------|
| `brute-force` | Generates rapid SSH auth failures | Wazuh auth rules |
| `credential-theft` | Modifies UCAN token files | Rule 100100 (level 12) |
| `binary-tamper` | Copies a file to `/usr/local/bin/` matching the claude-peers pattern | Rule 100101 (level 13) |
| `rogue-service` | Creates a systemd unit file | Rule 100130 (level 9) |
| `lateral-movement` | Simulates brute force + file changes across two machines simultaneously | Cross-machine correlation |
| `ssh-key-swap` | Modifies `~/.ssh/authorized_keys` | Rule 100102 (level 10) |
| `cron-persistence` | Adds a crontab entry | Rule 100111 (level 9) |
| `shell-persistence` | Appends a line to `~/.bashrc` | Rule 100110 (level 10) |
| `config-tamper` | Modifies `config.json` | Rule 100113 (level 11) |
| `shell-rc-persist` | Creates a `/etc/profile.d/` entry | Rule 100112 (level 10) |
| `cron-persist` | Creates a file in `/etc/cron.d/` | Rule 100114 (level 9) |
| `dns-hijack` | Appends an entry to `/etc/hosts` (requires sudo) | Rule 100115 (level 12) |
| `ld-preload` | Modifies `/etc/ld.so.preload` (requires sudo) | Rule 100119 (level 13) |
| `pam-tamper` | Adds a comment to a PAM config file (requires sudo) | Rule 100202 (level 10) |
| `syncthing-exfil` | Modifies Syncthing config | Rule 100118 (level 10) |
| `message-flood` | Sends many broker messages in rapid succession | Rate limiter |
| `token-replay` | Attempts to reuse an old token | UCAN expiry validation |

**Cleanup:** Each simulation includes a cleanup step that reverts the changes. Simulations that require sudo (`dns-hijack`, `ld-preload`, `pam-tamper`) gracefully skip if sudo is unavailable.

### What to verify after a simulation

1. Wazuh alert appeared in `/var/ossec/logs/alerts/alerts.json` on the Wazuh manager
2. `wazuh-bridge` published the event to NATS (check logs)
3. Broker updated machine health score (`curl http://localhost:7899/machine-health`)
4. For escalations: email received, forensics directory created

---

## Hardening Checklist

**Broker machine:**
- [ ] Run broker on a private network interface only (Tailscale IP, not 0.0.0.0)
- [ ] Firewall port 7899 to Tailscale subnet only
- [ ] Firewall port 4222 (NATS) to Tailscale subnet only
- [ ] Set a strong NATS token (`CLAUDE_PEERS_NATS_TOKEN`)
- [ ] Use NKey auth for NATS instead of token auth (`claude-peers generate-nkey`)
- [ ] Back up `~/.config/claude-peers/identity.pem` and `root-token.jwt` offline

**Client machines:**
- [ ] `~/.config/claude-peers/identity.pem` mode 0600
- [ ] `~/.config/claude-peers/token.jwt` mode 0600
- [ ] Install Wazuh agent and register to your Wazuh manager
- [ ] Enable FIM for the paths listed in the "What Is Monitored" section
- [ ] Set `stale_timeout: 300` in config (default) -- removes dead peers promptly

**UCAN tokens:**
- [ ] Issue minimum-capability tokens for each role (don't use `fleet-write` for services that only need `fleet-read`)
- [ ] Tokens expire in 24 hours; set up `claude-peers refresh-token` as a cron job or use `dream-watch` (handles auto-refresh)
- [ ] Use `claude-peers reauth-fleet` after any credential rotation to push fresh tokens to all machines

**Wazuh:**
- [ ] Deploy the custom rules from `wazuh/local_rules.xml` to your Wazuh manager
- [ ] Configure the Wazuh agent's `agent.conf` to monitor the FIM paths listed above
- [ ] Use `wazuh/shared_agent.conf` from this repo as a starting point
- [ ] Enable active response in Wazuh for level 13+ alerts (optional, response-daemon handles this)

**Email alerts:**
- [ ] Set `alert_email` in `config.json` or `RESPONSE_EMAIL_TO` env var
- [ ] Test with `claude-peers sim-attack brute-force --dry-run`
