#!/bin/bash
# Fleet backup -- backs up critical fleet state to a local archive
# Run daily via cron on the broker machine
set -euo pipefail

BACKUP_DIR="$HOME/.fleet-backups"
DATE=$(date +%Y%m%d-%H%M)
DEST="$BACKUP_DIR/$DATE"

mkdir -p "$DEST"

# Broker root key (MOST CRITICAL)
cp ~/.config/claude-peers/identity.pem "$DEST/"
cp ~/.config/claude-peers/identity.pub "$DEST/"
cp ~/.config/claude-peers/root.pub "$DEST/"
cp ~/.config/claude-peers/token.jwt "$DEST/"
cp ~/.config/claude-peers/config.json "$DEST/"

# Wazuh rules and config
docker exec wazuh-manager cat /var/ossec/etc/rules/local_rules.xml > "$DEST/wazuh-local_rules.xml" 2>/dev/null || true
docker exec wazuh-manager cat /var/ossec/etc/shared/default/agent.conf > "$DEST/wazuh-shared_agent.conf" 2>/dev/null || true

# Broker database
cp ~/.claude-peers.db "$DEST/" 2>/dev/null || true

# Daemon configs
cp -r ~/claude-peers-daemons "$DEST/daemons" 2>/dev/null || true

# Systemd service files
cp ~/.config/systemd/user/claude-peers-*.service "$DEST/" 2>/dev/null || true

# Compress
tar czf "$BACKUP_DIR/fleet-backup-$DATE.tar.gz" -C "$BACKUP_DIR" "$DATE"
rm -rf "$DEST"

# Keep last 7 days
find "$BACKUP_DIR" -name "fleet-backup-*.tar.gz" -mtime +7 -delete

echo "[backup] fleet-backup-$DATE.tar.gz created ($(du -h "$BACKUP_DIR/fleet-backup-$DATE.tar.gz" | cut -f1))"
