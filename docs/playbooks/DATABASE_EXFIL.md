# Playbook: Broker Database Exfiltration

**System:** Sontara Lattice (claude-peers) fleet
**Last updated:** 2026-03-28
**Audience:** the operator (fleet operator)
**Severity tier:** Tier 3 (Approval Required) -- complete fleet communication history exposed

---

## Table of Contents

1. [Attack Model](#attack-model)
2. [What the Database Contains](#what-the-database-contains)
3. [Detection Signals](#detection-signals)
4. [Immediate Triage (0-5 minutes)](#immediate-triage)
5. [Investigation](#investigation)
6. [Containment](#containment)
7. [Recovery](#recovery)
8. [Decision Tree](#decision-tree)
9. [Monitoring Gaps](#monitoring-gaps)
10. [Hardening Recommendations](#hardening-recommendations)

---

## Attack Model

The broker runs on broker-server (<broker-ip>) and stores all fleet state in a SQLite database at `~/.claude-peers.db` (configured via `db_path` in config.json, defaults to `$HOME/.claude-peers.db`). The database uses WAL journal mode (`journal_mode(wal)`) for concurrent access.

### Database Location and Access

| Property | Value |
|----------|-------|
| Path | `~/.claude-peers.db` on broker-server |
| Journal | `~/.claude-peers.db-wal` (write-ahead log) |
| SHM | `~/.claude-peers.db-shm` (shared memory) |
| Permissions | Owned by `user:user`, mode 0644 (default SQLite) |
| Size | Varies -- grows with message history and events |

### Attack Vectors

**Vector 1: Direct File Copy**
An attacker with SSH access to broker-server copies the database file:
```bash
scp broker-server:~/.claude-peers.db ./stolen.db
```
The WAL file must also be copied for a complete snapshot:
```bash
scp broker-server:~/.claude-peers.db-wal ./stolen.db-wal
```

**Vector 2: SQLite CLI Dump**
An attacker with shell access runs:
```bash
sqlite3 ~/.claude-peers.db ".dump" > fleet_dump.sql
```

**Vector 3: Syncthing Sync**
If an attacker adds `~/.claude-peers.db` to a Syncthing folder (see SYNCTHING_EXFIL playbook), the database continuously syncs to their machine -- including real-time updates.

**Vector 4: Compromised Daemon/Session**
A compromised Claude session or daemon with bash access on broker-server can read the database directly:
```bash
sqlite3 ~/.claude-peers.db "SELECT * FROM messages"
```

**Vector 5: Backup Exposure**
If broker-server backups include the home directory, the database is in the backup. Backup theft exposes all historical fleet data.

---

## What the Database Contains

### Table: `peers`

Every Claude Code instance that has registered with the broker:

| Column | Content | Sensitivity |
|--------|---------|-------------|
| `id` | Unique peer identifier (hex) | Low -- random ID |
| `pid` | Process ID on the machine | Low |
| `machine` | Machine hostname (workstation, edge-node, etc.) | Medium -- fleet topology |
| `cwd` | Working directory path | Medium -- reveals project structure |
| `git_root` | Git repository root path | Medium -- reveals project names |
| `tty` | Terminal identifier | Low |
| `name` | Auto-generated name (machine/project) | Medium |
| `project` | Repository or directory name | Medium |
| `branch` | Git branch | Low |
| `summary` | LLM-generated description of what the session is working on | **HIGH** -- describes active work |
| `registered_at` | Registration timestamp | Low |
| `last_seen` | Last heartbeat timestamp | Low |

### Table: `messages`

All peer-to-peer messages:

| Column | Content | Sensitivity |
|--------|---------|-------------|
| `id` | Auto-increment message ID | Low |
| `from_id` | Sender peer ID | Medium |
| `to_id` | Recipient peer ID | Medium |
| `text` | **Full message content in plaintext** | **CRITICAL** -- may contain source code, credentials, instructions |
| `sent_at` | Timestamp | Low |
| `delivered` | Delivery status (0=pending, 1=delivered) | Low |

Messages include:
- Peer-to-peer coordination messages
- Code snippets shared between sessions
- Instructions passed between Claude instances
- Any data a Claude session decides to send via `send_message`

### Table: `events`

Broker event log:

| Column | Content | Sensitivity |
|--------|---------|-------------|
| `type` | Event type (peer_joined, message_sent, summary_changed) | Medium -- activity patterns |
| `peer_id` | Associated peer | Low |
| `machine` | Machine name | Medium |
| `data` | Event data (summaries, peer IDs) | **HIGH** -- includes work descriptions |
| `created_at` | Timestamp | Low |

### Table: `kv`

Key-value store containing fleet memory:

| Key | Content | Sensitivity |
|-----|---------|-------------|
| `fleet_memory` | Full fleet-activity.md content | **HIGH** -- fleet topology, active sessions, security status |

### Aggregate Intelligence from the Database

An attacker with the full database can reconstruct:

1. **Complete fleet topology.** Every machine name, every IP (from summaries/messages), every project being worked on.
2. **Work patterns.** When each machine is active, what projects are being developed, who communicates with whom.
3. **Security posture.** Fleet memory includes security status. Events include security alerts.
4. **Communication content.** Every message ever sent between Claude sessions (up to 1 hour after delivery).
5. **Active projects.** Git repositories, branches, working directories across the fleet.
6. **Operational details.** Summaries describe what each session is doing in detail.

---

## Detection Signals

### Primary: File Integrity Monitoring

**CRITICAL GAP: `.db` files are explicitly ignored by Wazuh syscheck.**

From `wazuh/shared_agent.conf`:
```xml
<ignore type="sregex">.db$</ignore>
<ignore type="sregex">.db-journal$</ignore>
```

This means:
- Direct copies of `~/.claude-peers.db` are invisible to FIM
- Database modifications are invisible to FIM
- WAL file changes are invisible to FIM

This was originally added to reduce noise (SQLite databases change frequently), but it creates a blind spot for database theft.

### Secondary: File Access Patterns

```bash
# On broker-server: check recent access to the database
ssh broker-server "stat ~/.claude-peers.db"

# Check if the file was recently copied (look for large reads)
# This requires auditd or inotifywait -- neither is currently configured
ssh broker-server "lsof ~/.claude-peers.db 2>/dev/null"
```

### Tertiary: Network Transfer Detection

```bash
# Check for large file transfers from broker-server
# SCP/SFTP would show up as SSH traffic
ssh broker-server "ss -tnp | grep ssh | grep -v '100\.\|127\.\|::1'"

# Check for unusual outbound data volume
ssh broker-server "iftop -t -s 5 -n 2>/dev/null | head -20"
```

### Quaternary: SQLite Process Audit

```bash
# Check for non-broker processes accessing the database
ssh broker-server "
BROKER_PID=\$(pgrep -f 'claude-peers broker' | head -1)
lsof ~/.claude-peers.db 2>/dev/null | grep -v \"^\$BROKER_PID\" | grep -v 'PID'
"

# Check for sqlite3 CLI usage
ssh broker-server "pgrep -fa sqlite3 2>/dev/null"
ssh broker-server "grep -r 'sqlite3.*claude-peers' ~/.bash_history ~/.zsh_history 2>/dev/null"
```

---

## Immediate Triage (0-5 minutes)

### Step 1: Check who is accessing the database right now

```bash
ssh broker-server "
echo '=== Processes with .claude-peers.db open ==='
lsof ~/.claude-peers.db 2>/dev/null

echo ''
echo '=== sqlite3 processes ==='
pgrep -fa sqlite3 2>/dev/null || echo 'No sqlite3 processes'

echo ''
echo '=== File stat ==='
stat ~/.claude-peers.db

echo ''
echo '=== WAL file stat ==='
stat ~/.claude-peers.db-wal 2>/dev/null || echo 'No WAL file'
"
```

### Step 2: Check for copies of the database

```bash
ssh broker-server "
echo '=== Recent .db files in home directory ==='
find ~ -name '*.db' -newer ~/.claude-peers.db -not -path '*/\.*' 2>/dev/null

echo ''
echo '=== Files named claude-peers anywhere ==='
find /tmp /var/tmp /dev/shm ~ -name '*claude-peers*' -not -path '*/.config/claude-peers*' -not -path '*/projects/claude-peers*' 2>/dev/null

echo ''
echo '=== Recent large file transfers (check scp/rsync history) ==='
grep -E 'scp|rsync.*claude-peers' ~/.bash_history ~/.zsh_history 2>/dev/null
"
```

### Step 3: Check database content for evidence of unauthorized queries

```bash
# SQLite doesn't have built-in query logging
# But we can check the WAL for recent write activity
ssh broker-server "
echo '=== Database size ==='
ls -la ~/.claude-peers.db ~/.claude-peers.db-wal ~/.claude-peers.db-shm 2>/dev/null

echo ''
echo '=== Current peer count ==='
sqlite3 ~/.claude-peers.db 'SELECT COUNT(*) FROM peers' 2>/dev/null

echo ''
echo '=== Current message count ==='
sqlite3 ~/.claude-peers.db 'SELECT COUNT(*) FROM messages' 2>/dev/null

echo ''
echo '=== Fleet memory size ==='
sqlite3 ~/.claude-peers.db 'SELECT length(value) FROM kv WHERE key=\"fleet_memory\"' 2>/dev/null
"
```

---

## Investigation

### Determine if the file was copied

```bash
# If auditd is available (it is on broker-server by default):
ssh broker-server "
# Search audit log for access to the database
ausearch -f ~/.claude-peers.db --start recent 2>/dev/null | tail -30

# If ausearch is empty, try journalctl
journalctl --since '24 hours ago' --no-pager 2>/dev/null | grep 'claude-peers.db' | tail -20
"

# Check SSH auth log for file transfer sessions
ssh broker-server "
journalctl -u sshd --since '24 hours ago' --no-pager 2>/dev/null | grep -iE 'session\|sftp\|scp' | tail -20
"
```

### Determine the exposure window

```bash
# When was the database last accessed (vs. last modified)?
ssh broker-server "
echo 'Access time:'
stat -c '%x' ~/.claude-peers.db
echo 'Modify time:'
stat -c '%y' ~/.claude-peers.db
echo 'Change time:'
stat -c '%z' ~/.claude-peers.db
"

# Note: noatime mount option may be set, making access time unreliable
ssh broker-server "mount | grep -E '/ |/home' | grep -o 'noatime\|relatime\|strictatime'"
```

### Check what sensitive data is currently in the database

```bash
ssh broker-server "
echo '=== Messages with potential credentials ==='
sqlite3 ~/.claude-peers.db \"
SELECT from_id, to_id, length(text), sent_at
FROM messages
WHERE text LIKE '%BEGIN%PRIVATE%'
   OR text LIKE '%ssh-%'
   OR text LIKE '%eyJ%'
   OR text LIKE '%API_KEY%'
   OR text LIKE '%SECRET%'
   OR text LIKE '%password%'
   OR text LIKE '%DATABASE_URL%'
\" 2>/dev/null

echo ''
echo '=== Event data samples ==='
sqlite3 ~/.claude-peers.db \"
SELECT type, substr(data, 1, 100), created_at
FROM events
WHERE length(data) > 50
ORDER BY created_at DESC
LIMIT 10
\" 2>/dev/null
"
```

---

## Containment

### Step 1: Restrict file permissions

```bash
ssh broker-server "
# Set database to owner-only read/write
chmod 600 ~/.claude-peers.db
chmod 600 ~/.claude-peers.db-wal 2>/dev/null
chmod 600 ~/.claude-peers.db-shm 2>/dev/null

# Verify
ls -la ~/.claude-peers.db*
"
```

### Step 2: Kill unauthorized database accessors

```bash
ssh broker-server "
BROKER_PID=\$(pgrep -f 'claude-peers broker' | head -1)
for pid in \$(lsof -t ~/.claude-peers.db 2>/dev/null); do
  if [ \"\$pid\" != \"\$BROKER_PID\" ]; then
    echo \"Killing unauthorized accessor PID \$pid: \$(ps -p \$pid -o cmd= 2>/dev/null)\"
    kill \$pid
  fi
done
"
```

### Step 3: If database was confirmed stolen, rotate all secrets

If the database was exfiltrated, the attacker has:

| Data | Rotation Action |
|------|----------------|
| Fleet topology (machine names, IPs, projects) | Cannot rotate. Attacker has reconnaissance data. Consider this in future threat modeling. |
| Message content | Rotate any credentials that were sent via peer messages. Check messages table. |
| Fleet memory content | Contains security status, which may reveal monitoring gaps to the attacker. |
| Work summaries | Reveals active projects and focus areas. Operational security consideration. |
| Peer session patterns | Reveals when you work, which machines you use, which projects you switch between. |

---

## Recovery

### Step 1: Clean sensitive data from the database

```bash
# Delete all delivered messages (they've already been read)
ssh broker-server "sqlite3 ~/.claude-peers.db \"
DELETE FROM messages WHERE delivered = 1;
SELECT 'Deleted delivered messages, remaining:', COUNT(*) FROM messages;
\""

# Delete old events
ssh broker-server "sqlite3 ~/.claude-peers.db \"
DELETE FROM events WHERE created_at < datetime('now', '-1 hour');
SELECT 'Remaining events:', COUNT(*) FROM events;
\""

# Compact the database (reclaim space, remove deleted data from disk)
ssh broker-server "sqlite3 ~/.claude-peers.db 'VACUUM'"
```

### Step 2: Verify file permissions are correct

```bash
ssh broker-server "
ls -la ~/.claude-peers.db*
echo ''
echo 'Owner:'
stat -c '%U:%G %a' ~/.claude-peers.db
"
```

### Step 3: Set up temporary monitoring

Until proper FIM is added for the database file:

```bash
# Create a simple inotify watcher (temporary)
ssh broker-server "
nohup inotifywait -m -e access,modify,open ~/.claude-peers.db --format '%T %e %f' --timefmt '%Y-%m-%d %H:%M:%S' >> /tmp/claude-peers-db-audit.log 2>&1 &
echo 'Watcher PID: \$!'
"
```

---

## Decision Tree

```
Broker database theft suspected
|
+-- How was it detected?
|   +-- Unusual file access on broker-server
|   +-- Large SSH file transfer from broker-server
|   +-- Database file found in unexpected location
|   +-- Attacker revealed knowledge of fleet internals (implying DB access)
|
+-- Was the database file copied?
|   +-- Check auditd logs: ausearch -f ~/.claude-peers.db
|   +-- Check SSH session logs for SCP/SFTP
|   +-- Check for copies in /tmp, /var/tmp, other locations
|   +-- Check Syncthing for rogue folder sharing the DB path
|
+-- What data was in the database at time of theft?
|   +-- Messages: check messages table for credential patterns
|   +-- Events: check events table for security-sensitive data
|   +-- Fleet memory: check kv table for fleet topology data
|   +-- Peers: check peers table for active session details
|
+-- Was it a one-time copy or ongoing access?
|   +-- One-time: attacker has a snapshot. Rotate secrets, clean DB.
|   +-- Ongoing (Syncthing sync, persistent access):
|       +-- CRITICAL: attacker has real-time fleet visibility
|       +-- Cut access immediately (remove Syncthing share, revoke SSH, etc.)
|
+-- CRITICAL: Is FIM still ignoring .db files?
    +-- YES: fix immediately -- remove .db ignore from syscheck
    +-- NO: verify FIM alerts are working for this file
```

---

## Monitoring Gaps

| Gap | Severity | Status | Remediation |
|-----|----------|--------|-------------|
| **`.db` files explicitly ignored by Wazuh syscheck** | **CRITICAL** | KNOWN GAP | The regex `<ignore type="sregex">.db$</ignore>` in shared_agent.conf blinds FIM to ALL .db file changes. Remove this ignore and add a specific allowlist for noisy but non-sensitive .db files instead. |
| **`.db-journal` files also ignored** | **HIGH** | KNOWN GAP | `<ignore type="sregex">.db-journal$</ignore>` also blinds FIM to WAL/journal file access |
| **No auditd rule for database file** | **HIGH** | NOT IMPLEMENTED | Add auditd watch: `auditctl -w ~/.claude-peers.db -p rwa -k claude-peers-db` |
| **Database content is plaintext** | **HIGH** | ARCHITECTURAL | Messages, events, and fleet memory stored unencrypted. At-rest encryption would limit exposure. |
| **Database permissions too permissive** | **MEDIUM** | DEFAULT | SQLite creates files with umask-based permissions. Broker should explicitly set 0600. |
| **No database access logging** | **MEDIUM** | NOT IMPLEMENTED | SQLite has no built-in audit logging. Use auditd or inotifywait for file-level access monitoring. |

---

## Hardening Recommendations

1. **Fix the Wazuh syscheck .db ignore.** Replace the blanket `.db$` ignore with specific ignores for known-noisy databases (like browser caches). Add explicit FIM monitoring for `~/.claude-peers.db`:
   ```xml
   <!-- Remove the global .db ignore -->
   <!-- <ignore type="sregex">.db$</ignore> -->

   <!-- Instead, ignore specific noisy databases -->
   <ignore>~/.mozilla/firefox</ignore>
   <ignore>~/.cache</ignore>

   <!-- Explicitly monitor the broker database on broker-server -->
   <directories check_all="yes" realtime="yes">~/.claude-peers.db</directories>
   ```
   Note: This will generate FIM events every time the broker writes to the database. Create a Wazuh rule that suppresses broker-process writes but alerts on other access.

2. **Add auditd rule for the database file.** On broker-server:
   ```bash
   sudo auditctl -w ~/.claude-peers.db -p rwa -k claude-peers-db
   # Make it persistent:
   echo '-w ~/.claude-peers.db -p rwa -k claude-peers-db' | sudo tee -a /etc/audit/rules.d/claude-peers.rules
   ```

3. **Set database permissions to 0600.** Modify the broker code to `os.Chmod` the database file to 0600 after creation. This prevents other users from reading it.

4. **Encrypt sensitive columns.** Encrypt the `messages.text` column and `kv.value` using a key derived from the broker's UCAN identity. This adds at-rest encryption for the most sensitive data.

5. **Reduce data retention.** Currently, delivered messages persist for up to 1 hour and events persist for up to 1 hour. Consider reducing both to 5 minutes. Less data at rest means less exposure if the database is stolen.

6. **Database backup encryption.** If broker-server backups include the home directory, ensure backups are encrypted at rest. The database in an unencrypted backup is just as exposed as the live database.
