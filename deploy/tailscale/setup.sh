#!/bin/bash
set -euo pipefail

# Sontara Lattice — Tailscale overlay setup
#
# Runs ON the GCP VM (or any Sontara Lattice broker host) to configure
# Tailscale for private mesh access. After this runs, fleet members connect
# via Tailscale IPs — no public firewall rules required.
#
# Usage:
#   ssh <vm> 'bash -s' < deploy/tailscale/setup.sh
# or copy to the VM and run directly.

echo "=== Sontara Lattice Tailscale Setup ==="
echo ""

# Must run as root or with sudo
if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: This script must run as root."
  echo "Usage: sudo bash setup.sh"
  exit 1
fi

# Check if already installed
if command -v tailscale >/dev/null 2>&1; then
  echo "Tailscale is already installed: $(tailscale version)"
  echo ""
  read -p "Re-configure? (y/N): " RECONFIGURE
  if [[ ! "$RECONFIGURE" =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
  fi
else
  echo "Installing Tailscale..."
  curl -fsSL https://tailscale.com/install.sh | sh
  echo "Tailscale installed: $(tailscale version)"
fi

echo ""
echo "Get an auth key from: https://login.tailscale.com/admin/settings/keys"
echo ""
echo "Recommended key settings:"
echo "  - Reusable: yes"
echo "  - Ephemeral: no (this is a long-lived broker)"
echo "  - Tags: tag:exit-node, tag:sontara-broker (optional, configure in ACLs)"
echo ""
read -p "Tailscale auth key: " TS_AUTH_KEY
if [ -z "$TS_AUTH_KEY" ]; then
  echo "ERROR: Auth key required."
  exit 1
fi

# Advertise exit node and enable IP forwarding
echo ""
echo "Enabling IP forwarding..."
echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-tailscale.conf
echo 'net.ipv6.conf.all.forwarding = 1' >> /etc/sysctl.d/99-tailscale.conf
sysctl -p /etc/sysctl.d/99-tailscale.conf >/dev/null

echo "Connecting to Tailscale..."
tailscale up \
  --authkey="$TS_AUTH_KEY" \
  --advertise-exit-node \
  --accept-routes \
  --hostname="sontara-broker"

# Get assigned Tailscale IP
TS_IP=$(tailscale ip -4 2>/dev/null || echo "")
if [ -z "$TS_IP" ]; then
  echo "WARNING: Could not determine Tailscale IP yet. Run: tailscale ip -4"
else
  echo ""
  echo "Tailscale IP: $TS_IP"
fi

echo ""
echo "Enabling tailscaled on boot..."
systemctl enable tailscaled

echo ""
echo "========================================"
echo " Tailscale setup complete"
echo "========================================"
echo ""
echo "This machine is now on your Tailscale network as 'sontara-broker'."
echo ""
if [ -n "$TS_IP" ]; then
  echo "Private broker access (no public firewall rules needed):"
  echo "  Broker:     http://$TS_IP:7899/health"
  echo "  Dashboard:  http://$TS_IP:8888"
  echo "  NATS:       nats://$TS_IP:4222"
  echo ""
fi
echo "IMPORTANT: Approve the exit node route in your Tailscale admin:"
echo "  https://login.tailscale.com/admin/machines"
echo "  -> Find 'sontara-broker' -> Edit route settings -> Approve exit node"
echo ""
echo "Connect client machines:"
echo "  claude-peers init client http://$TS_IP:7899"
echo ""
echo "Once all clients are on Tailscale, you can remove the public firewall rules:"
echo "  gcloud compute firewall-rules delete sontara-allow-broker \\"
echo "    sontara-allow-gridwatch sontara-allow-nats sontara-allow-wazuh"
