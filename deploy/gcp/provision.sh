#!/bin/bash
set -euo pipefail

echo "=== Sontara Lattice GCP Provisioning ==="
echo ""

# Check prerequisites
if ! command -v gcloud >/dev/null 2>&1; then
  echo "ERROR: gcloud CLI not found."
  echo "Install: https://cloud.google.com/sdk/docs/install"
  exit 1
fi

# Check authentication
if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null | grep -q "@"; then
  echo "ERROR: gcloud is not authenticated. Run: gcloud auth login"
  exit 1
fi

echo "gcloud OK ($(gcloud auth list --filter=status:ACTIVE --format='value(account)' 2>/dev/null | head -1))"
echo ""

# Project
DEFAULT_PROJECT=$(gcloud config get-value project 2>/dev/null || echo "")
read -p "GCP Project [${DEFAULT_PROJECT:-none}]: " INPUT_PROJECT
PROJECT="${INPUT_PROJECT:-$DEFAULT_PROJECT}"
if [ -z "$PROJECT" ]; then
  echo "ERROR: No project specified and none configured in gcloud."
  exit 1
fi

# Region
read -p "Region [us-central1]: " INPUT_REGION
REGION="${INPUT_REGION:-us-central1}"
ZONE="${REGION}-b"

# Machine type
echo ""
echo "Machine types:"
echo "  e2-medium     -- 2 vCPU, 4GB RAM  -- small fleets (up to ~10 peers)"
echo "  e2-standard-2 -- 2 vCPU, 8GB RAM  -- medium fleets (10-50 peers)"
echo "  e2-standard-4 -- 4 vCPU, 16GB RAM -- large fleets (50+ peers)"
read -p "Machine type [e2-medium]: " INPUT_MACHINE
MACHINE_TYPE="${INPUT_MACHINE:-e2-medium}"

# Instance name
read -p "Instance name [sontara-lattice]: " INPUT_INSTANCE
INSTANCE="${INPUT_INSTANCE:-sontara-lattice}"

# GitHub repo
REPO_URL="https://github.com/Human-Frontier-Labs-Inc/sontara-lattice.git"
read -p "Repo URL [$REPO_URL]: " INPUT_REPO
REPO_URL="${INPUT_REPO:-$REPO_URL}"

# Tailscale
echo ""
read -p "Set up Tailscale VPN access? (y/N): " WANT_TAILSCALE
WANT_TAILSCALE="${WANT_TAILSCALE:-n}"

TAILSCALE_AUTH_KEY=""
if [[ "$WANT_TAILSCALE" =~ ^[Yy]$ ]]; then
  echo "Get an auth key from https://login.tailscale.com/admin/settings/keys"
  echo "(Use an ephemeral reusable key with exit-node tag for production)"
  read -p "Tailscale auth key: " TAILSCALE_AUTH_KEY
  if [ -z "$TAILSCALE_AUTH_KEY" ]; then
    echo "WARNING: No auth key provided, skipping Tailscale setup."
    WANT_TAILSCALE="n"
  fi
fi

echo ""
echo "--- Provisioning plan ---"
echo "Project:      $PROJECT"
echo "Zone:         $ZONE"
echo "Machine type: $MACHINE_TYPE"
echo "Instance:     $INSTANCE"
echo "Repo:         $REPO_URL"
echo "Tailscale:    $([[ "$WANT_TAILSCALE" =~ ^[Yy]$ ]] && echo 'yes' || echo 'no')"
echo ""
read -p "Proceed? (y/N): " CONFIRM
if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
  echo "Aborted."
  exit 0
fi

echo ""
echo "=== Step 1/4: Firewall rules ==="

create_fw_rule() {
  local name="$1" allow="$2" desc="$3"
  if gcloud compute firewall-rules describe "$name" --project="$PROJECT" >/dev/null 2>&1; then
    echo "  $name: already exists, skipping"
  else
    gcloud compute firewall-rules create "$name" \
      --project="$PROJECT" \
      --allow="$allow" \
      --target-tags=sontara \
      --description="$desc" \
      --quiet
    echo "  $name: created ($allow)"
  fi
}

create_fw_rule "sontara-allow-broker"    "tcp:7899"            "Sontara Lattice trust broker"
create_fw_rule "sontara-allow-gridwatch" "tcp:8888"            "Sontara Lattice gridwatch dashboard"
create_fw_rule "sontara-allow-nats"      "tcp:4222,tcp:8222"   "NATS JetStream + monitoring"
create_fw_rule "sontara-allow-wazuh"     "tcp:1514,tcp:1515,tcp:55000,udp:514" "Wazuh agent enrollment and syslog"

echo ""
echo "=== Step 2/4: Writing startup script ==="

STARTUP_SCRIPT=$(cat <<STARTUP_EOF
#!/bin/bash
set -euo pipefail
exec >> /var/log/sontara-startup.log 2>&1
echo "[startup] \$(date) -- starting Sontara Lattice provisioning"

# Docker
echo "[startup] Installing Docker..."
curl -fsSL https://get.docker.com | sh
systemctl enable --now docker
echo "[startup] Docker installed"

# Go (needed to build from source)
echo "[startup] Installing Go..."
GO_VERSION="1.23.4"
wget -q "https://go.dev/dl/go\${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
tar -C /usr/local -xzf /tmp/go.tar.gz
rm /tmp/go.tar.gz
export PATH=\$PATH:/usr/local/go/bin
echo "export PATH=\$PATH:/usr/local/go/bin" >> /etc/profile.d/go.sh
echo "[startup] Go \${GO_VERSION} installed"

# Clone repository
echo "[startup] Cloning $REPO_URL..."
cd /opt
git clone "$REPO_URL" sontara-lattice
cd sontara-lattice

# Build binary
echo "[startup] Building claude-peers binary..."
/usr/local/go/bin/go build -o /usr/local/bin/claude-peers .
chmod +x /usr/local/bin/claude-peers
echo "[startup] Binary built: \$(claude-peers version 2>/dev/null || echo 'ok')"

# Initialize broker
echo "[startup] Initializing broker..."
claude-peers init broker

# Start the full stack via Docker Compose
echo "[startup] Starting Docker Compose stack..."
docker compose up -d

# Wait for broker health
echo "[startup] Waiting for broker health..."
for i in \$(seq 1 30); do
  if curl -sf http://localhost:7899/health >/dev/null 2>&1; then
    echo "[startup] Broker healthy after \${i}s"
    break
  fi
  sleep 1
done

TAILSCALE_SETUP
STARTUP_EOF
)

# Append Tailscale setup if requested
if [[ "$WANT_TAILSCALE" =~ ^[Yy]$ ]]; then
STARTUP_SCRIPT="${STARTUP_SCRIPT}
# Tailscale
echo '[startup] Installing Tailscale...'
curl -fsSL https://tailscale.com/install.sh | sh
tailscale up --authkey='${TAILSCALE_AUTH_KEY}' --advertise-exit-node --accept-routes
echo '[startup] Tailscale up'
"
fi

STARTUP_SCRIPT="${STARTUP_SCRIPT}
echo '[startup] Done. Sontara Lattice is running.'
echo '[startup] Broker: http://\$(curl -s http://checkip.amazonaws.com):7899/health'
echo '[startup] Dashboard: http://\$(curl -s http://checkip.amazonaws.com):8888'
"

STARTUP_FILE=$(mktemp /tmp/sontara-startup-XXXXXX.sh)
printf '%s' "$STARTUP_SCRIPT" > "$STARTUP_FILE"
echo "  Startup script written to $STARTUP_FILE"

echo ""
echo "=== Step 3/4: Creating VM ==="

gcloud compute instances create "$INSTANCE" \
  --project="$PROJECT" \
  --zone="$ZONE" \
  --machine-type="$MACHINE_TYPE" \
  --image-family=ubuntu-2404-lts-amd64 \
  --image-project=ubuntu-os-cloud \
  --boot-disk-size=50GB \
  --boot-disk-type=pd-balanced \
  --tags=sontara \
  --metadata-from-file=startup-script="$STARTUP_FILE" \
  --quiet

rm -f "$STARTUP_FILE"
echo "  VM created: $INSTANCE"

echo ""
echo "=== Step 4/4: Retrieving IP ==="

# Brief wait for GCE to assign the external IP
sleep 5
EXTERNAL_IP=$(gcloud compute instances describe "$INSTANCE" \
  --project="$PROJECT" \
  --zone="$ZONE" \
  --format='get(networkInterfaces[0].accessConfigs[0].natIP)' 2>/dev/null)

if [ -z "$EXTERNAL_IP" ]; then
  echo "WARNING: Could not retrieve external IP yet. Run:"
  echo "  gcloud compute instances describe $INSTANCE --zone=$ZONE --format='get(networkInterfaces[0].accessConfigs[0].natIP)'"
else
  echo "  External IP: $EXTERNAL_IP"
fi

echo ""
echo "========================================"
echo " Sontara Lattice provisioned on GCP"
echo "========================================"
echo ""
echo "VM:            $INSTANCE  ($EXTERNAL_IP)"
echo ""
echo "The startup script is running in the background."
echo "It installs Docker, builds the binary, and starts all services."
echo "Startup typically takes 3-5 minutes. Monitor progress:"
echo ""
echo "  gcloud compute ssh $INSTANCE --zone=$ZONE -- 'tail -f /var/log/sontara-startup.log'"
echo ""
echo "Once ready:"
echo "  Broker:     http://$EXTERNAL_IP:7899/health"
echo "  Dashboard:  http://$EXTERNAL_IP:8888"
echo "  NATS:       nats://$EXTERNAL_IP:4222"
echo "  Wazuh:      $EXTERNAL_IP:1514  (agent enrollment)"
echo ""
echo "SSH access:"
echo "  gcloud compute ssh $INSTANCE --zone=$ZONE"
echo ""
echo "Connect a client machine to this broker:"
echo "  claude-peers init client http://$EXTERNAL_IP:7899"
echo ""
if [[ "$WANT_TAILSCALE" =~ ^[Yy]$ ]]; then
  echo "Tailscale is configured. Once the node appears in your Tailscale admin,"
  echo "you can use the Tailscale IP instead of the public IP for all services."
  echo ""
fi
echo "To tear down:"
echo "  $(dirname "$0")/teardown.sh  --instance $INSTANCE --project $PROJECT --zone $ZONE"
