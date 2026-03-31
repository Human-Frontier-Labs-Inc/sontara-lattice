#!/bin/bash
# Secure fleet deploy -- builds, hashes, deploys, verifies
# Configure targets in ~/.config/claude-peers/deploy-targets.json:
# [
#   {"machine": "server", "binary": "amd64", "ssh_target": "server-host"},
#   {"machine": "workstation", "binary": "amd64", "ssh_target": "localhost"},
#   {"machine": "pi", "binary": "arm64", "ssh_target": "pi-host"}
# ]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

CONFIG="${DEPLOY_TARGETS:-$HOME/.config/claude-peers/deploy-targets.json}"
if [ ! -f "$CONFIG" ]; then
    echo "[deploy] ERROR: no deploy-targets.json found at $CONFIG"
    echo "[deploy] Create one with machine/binary/ssh_target entries."
    exit 1
fi

echo "[deploy] Building..."
GOOS=linux GOARCH=amd64 go build -o /tmp/claude-peers-amd64 .
GOOS=linux GOARCH=arm64 go build -o /tmp/claude-peers-arm64 .
GOOS=linux GOARCH=arm GOARM=7 go build -o /tmp/claude-peers-armv7 .
GOOS=darwin GOARCH=arm64 go build -o /tmp/claude-peers-darwin .

# Compute hashes
echo "[deploy] Hashes:"
for f in /tmp/claude-peers-amd64 /tmp/claude-peers-arm64 /tmp/claude-peers-armv7 /tmp/claude-peers-darwin; do
    sha256sum "$f" | tee -a /tmp/deploy-hashes.txt
done

echo "[deploy] Deploying to fleet..."

# Deploy function with hash verification
deploy_machine() {
    local machine=$1 binary=$2 ssh_target=$3
    echo "  $machine: deploying..."

    local hash=$(sha256sum "$binary" | awk '{print $1}')

    # Stop broker services if this is the broker machine
    if ssh "$ssh_target" 'test -f ~/.config/claude-peers/config.json' 2>/dev/null; then
        local role=$(ssh "$ssh_target" 'python3 -c "import json; print(json.load(open(\"~/.config/claude-peers/config.json\".replace(\"~\",__import__(\"os\").path.expanduser(\"~\")))).get(\"role\",\"\"))" 2>/dev/null' || true)
        if [ "$role" = "broker" ]; then
            ssh "$ssh_target" 'systemctl --user stop claude-peers-broker claude-peers-dream claude-peers-supervisor claude-peers-wazuh-bridge claude-peers-security-watch claude-peers-response-daemon 2>/dev/null' || true
            sleep 1
        fi
    fi

    scp "$binary" "$ssh_target":~/.local/bin/claude-peers
    ssh "$ssh_target" "chmod +x ~/.local/bin/claude-peers"

    # Verify hash on remote
    remote_hash=$(ssh "$ssh_target" "sha256sum ~/.local/bin/claude-peers | awk '{print \$1}'" 2>/dev/null)
    if [ "$hash" = "$remote_hash" ]; then
        echo "  $machine: hash verified OK"
    else
        echo "  $machine: HASH MISMATCH! Expected $hash, got $remote_hash"
        return 1
    fi

    # Restart broker services if this is the broker machine
    if [ "${role:-}" = "broker" ]; then
        ssh "$ssh_target" 'systemctl --user start claude-peers-broker claude-peers-dream claude-peers-supervisor claude-peers-wazuh-bridge claude-peers-security-watch claude-peers-response-daemon'
    fi
}

# Read targets from config
python3 -c "
import json, sys
targets = json.load(open('$CONFIG'))
for t in targets:
    print(t['machine'], t.get('binary', 'amd64'), t['ssh_target'])
" | while read machine arch ssh_target; do
    binary="/tmp/claude-peers-$arch"
    if [ ! -f "$binary" ]; then
        echo "  $machine: SKIP (no binary for arch $arch)"
        continue
    fi
    deploy_machine "$machine" "$binary" "$ssh_target"
done

echo "[deploy] Done. Hashes saved to /tmp/deploy-hashes.txt"
