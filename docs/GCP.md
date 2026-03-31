# GCP Deployment

This guide covers deploying Sontara Lattice on Google Cloud Platform. The recommended setup runs all services on a single VM using Docker Compose, with Tailscale providing secure access from your fleet machines.

---

## Prerequisites

- A GCP project with billing enabled
- `gcloud` CLI installed and authenticated
- Tailscale account (for fleet connectivity)
- Domain or static IP for broker access (optional)

---

## VM Setup

### Create the VM

A general-purpose VM with 8GB+ RAM is sufficient for a 5-10 machine fleet. The Wazuh manager is the most memory-hungry component.

```bash
gcloud compute instances create sontara-lattice \
  --project=YOUR_PROJECT_ID \
  --zone=us-central1-a \
  --machine-type=n2-standard-2 \
  --image-family=ubuntu-2404-lts \
  --image-project=ubuntu-os-cloud \
  --boot-disk-size=50GB \
  --boot-disk-type=pd-ssd \
  --tags=sontara-lattice
```

For larger fleets or if you want Wazuh to store more alert history, use `n2-standard-4` (16GB RAM) and a 100GB boot disk.

### Configure firewall

```bash
# Allow Tailscale (UDP 41641) and SSH
gcloud compute firewall-rules create sontara-lattice-tailscale \
  --allow=udp:41641,tcp:22 \
  --target-tags=sontara-lattice \
  --description="Tailscale and SSH"

# Optional: allow broker and NATS from your office/home IP only
# Replace 1.2.3.4 with your IP
gcloud compute firewall-rules create sontara-lattice-services \
  --allow=tcp:7899,tcp:4222,tcp:8888,tcp:8222,tcp:55000 \
  --source-ranges=1.2.3.4/32 \
  --target-tags=sontara-lattice \
  --description="Sontara Lattice services (restricted)"
```

If you are using Tailscale for all fleet connectivity (recommended), you do not need to open these ports to the public internet. The firewall rule above is for direct access during initial setup.

### SSH to the VM

```bash
gcloud compute ssh sontara-lattice --zone=us-central1-a
```

---

## Install Dependencies

```bash
# Update and install Docker
sudo apt-get update
sudo apt-get install -y ca-certificates curl git

curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
newgrp docker

# Verify Docker Compose v2
docker compose version
```

---

## Install Tailscale

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
```

Note the Tailscale IP assigned to this machine. This is the IP your fleet machines will use to reach the broker. Example: `100.64.0.1`.

---

## Deploy Sontara Lattice

```bash
# Clone the repo
git clone https://github.com/your-github-org/sontara-lattice.git
cd sontara-lattice

# Run setup
bash setup.sh
```

Select option 1 (Docker Compose). The script:
1. Checks Docker is available
2. Generates a random NATS token
3. Writes `.env`
4. Runs `docker compose up -d --build`
5. Waits for the broker health check to pass

After setup, initialize the broker keypair:

```bash
docker compose exec broker claude-peers init broker
```

This generates:
- Ed25519 root keypair (identity.pem, identity.pub)
- root.pub (distribute to fleet machines)
- root-token.jwt (broker's own auth)
- token.jwt (peer token, same value as root for broker)

Check that everything is running:

```bash
curl http://localhost:7899/health
# {"status":"ok","peers":0,"machine":"sontara-lattice"}

docker compose ps
```

---

## Connect Fleet Machines

### On each fleet machine

**Step 1:** Install Tailscale and join the same network:
```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
```

**Step 2:** Install `claude-peers`:
```bash
# Download the appropriate binary for your architecture
# Linux amd64
curl -L https://github.com/your-github-org/sontara-lattice/releases/latest/download/claude-peers-linux-amd64 \
  -o ~/.local/bin/claude-peers
chmod +x ~/.local/bin/claude-peers

# Linux arm64 (Raspberry Pi 5)
curl -L https://github.com/your-github-org/sontara-lattice/releases/latest/download/claude-peers-linux-arm64 \
  -o ~/.local/bin/claude-peers
chmod +x ~/.local/bin/claude-peers

# macOS Apple Silicon
curl -L https://github.com/your-github-org/sontara-lattice/releases/latest/download/claude-peers-darwin-arm64 \
  -o ~/.local/bin/claude-peers
chmod +x ~/.local/bin/claude-peers
```

**Step 3:** Initialize the client config, using your broker's Tailscale IP:
```bash
claude-peers init client http://100.64.0.1:7899
```

**Step 4:** Copy `root.pub` from the broker to this machine:
```bash
# From the broker VM
docker compose exec broker cat /root/.config/claude-peers/root.pub

# On the fleet machine, create the file with that content
mkdir -p ~/.config/claude-peers
# paste the content into:
cat > ~/.config/claude-peers/root.pub << 'EOF'
<paste root.pub content here>
EOF
```

Or copy directly if you have SSH access to the broker VM:
```bash
scp user@100.64.0.1:~/sontara-lattice/.config/broker/root.pub \
  ~/.config/claude-peers/root.pub
```

**Step 5:** Issue a UCAN token for this machine on the broker:
```bash
# On the fleet machine, get this machine's public key
cat ~/.config/claude-peers/identity.pub

# On the broker VM, issue a token (copy the identity.pub content first)
echo "<paste identity.pub content>" > /tmp/this-machine.pub
docker compose exec broker \
  claude-peers issue-token /tmp/this-machine.pub peer-session
# Outputs a JWT
```

**Step 6:** Save the token on the fleet machine:
```bash
claude-peers save-token <jwt-from-step-5>
```

Verify it works:
```bash
claude-peers status
# Broker: ok (0 peer(s), host: sontara-lattice)
```

### Batch token issuance

For multiple machines, use `reauth-fleet` to issue tokens to all configured machines via SSH:

```bash
# Add fleet machines to config.json on the broker
# ~/.config/claude-peers/config.json on the broker VM
{
  "fleet_targets": {
    "server1": "user@100.64.0.2",
    "workstation": "user@100.64.0.3",
    "raspi": "user@100.64.0.4"
  }
}

# Then re-issue all tokens
claude-peers reauth-fleet
```

---

## Configure Wazuh Agents

Install Wazuh agents on each fleet machine and register them to your Wazuh manager:

```bash
# On each fleet machine (Debian/Ubuntu)
# Get the Wazuh manager IP (Tailscale IP of your GCP VM)
WAZUH_MANAGER_IP=100.64.0.1

curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
  sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
sudo chmod 644 /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | \
  sudo tee /etc/apt/sources.list.d/wazuh.list

sudo apt-get update
sudo apt-get install -y wazuh-agent

# Register agent
sudo /var/ossec/bin/agent-auth -m ${WAZUH_MANAGER_IP}

# Start
sudo systemctl enable --now wazuh-agent
```

For Arch Linux:
```bash
# Download from Wazuh packages directly
wget https://packages.wazuh.com/4.x/linux/wazuh-agent_4.14.4-1_amd64.rpm
# Or build from AUR: yay -S wazuh-agent
```

The custom FIM rules in `wazuh/local_rules.xml` are already deployed to the Wazuh manager via the Docker Compose volume mount:
```yaml
volumes:
  - ./wazuh/local_rules.xml:/var/ossec/etc/rules/local_rules.xml:ro
```

---

## Systemd Services (Long-term)

For fleet machines, run claude-peers services as systemd user units:

```bash
mkdir -p ~/.config/systemd/user

# MCP server (Claude Code integration)
cat > ~/.config/systemd/user/claude-peers-server.service << 'EOF'
[Unit]
Description=Claude Peers MCP Server
After=network.target

[Service]
ExecStart=%h/.local/bin/claude-peers server
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
EOF

# Dream watch (fleet memory sync)
cat > ~/.config/systemd/user/claude-peers-dream.service << 'EOF'
[Unit]
Description=Claude Peers Dream Watch
After=network.target

[Service]
ExecStart=%h/.local/bin/claude-peers dream-watch
Restart=always
RestartSec=10

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
systemctl --user enable --now claude-peers-server claude-peers-dream
```

On the broker VM, add these additional services via Docker Compose (already in `docker-compose.yml`):
- `supervisor` -- daemon supervisor
- `wazuh-bridge` -- Wazuh alert ingestion
- `security-watch` -- event correlation
- `response-daemon` -- automated incident response
- `gridwatch` -- fleet dashboard

---

## LLM Configuration (Optional)

The supervisor and response daemon work best with a configured LLM endpoint. Options:

**LiteLLM proxy pointing at any provider:**
```bash
# On the broker VM (or a separate machine)
pip install litellm
litellm --model anthropic/claude-sonnet-4-6 --port 4000
```

Or add LiteLLM to your Docker Compose and update the `.env`:
```
LLM_BASE_URL=http://litellm:4000/v1
LLM_MODEL=claude-sonnet-4-6
LLM_API_KEY=sk-ant-...
```

---

## GCP Cost Estimate

| Component | Size | Monthly cost (us-central1) |
|-----------|------|---------------------------|
| n2-standard-2 VM | 2 vCPU, 8GB | ~$50 |
| 50GB SSD boot disk | | ~$9 |
| Ingress/egress | (Tailscale encrypted, minimal) | ~$1 |
| **Total** | | **~$60/month** |

For a larger fleet with more alert history, n2-standard-4 + 100GB disk runs ~$100/month.

---

## Maintenance

**Update the stack:**
```bash
cd ~/sontara-lattice
git pull
docker compose down
docker compose up -d --build
```

**View logs:**
```bash
docker compose logs -f broker
docker compose logs -f wazuh-bridge
docker compose logs -f security-watch
```

**Re-issue all fleet tokens after key rotation:**
```bash
docker compose exec broker claude-peers reauth-fleet
```

**Backup broker credentials:**
```bash
# Copy broker keypair and root token off the VM
docker compose exec broker tar czf /tmp/broker-creds.tar.gz -C /root/.config/claude-peers .
docker compose cp broker:/tmp/broker-creds.tar.gz ./broker-creds-backup.tar.gz
```

Store this backup securely. If you lose `identity.pem`, you cannot issue new tokens or validate existing ones.
