# Sontara Lattice — GCP Deployment

Deploy the full Sontara Lattice stack to a single Google Compute Engine VM with one command. This provisions the trust broker, NATS JetStream, Wazuh EDR manager, gridwatch dashboard, and all supporting services via Docker Compose.

## Prerequisites

- [gcloud CLI](https://cloud.google.com/sdk/docs/install) installed and authenticated
- A GCP project with billing enabled
- Compute Engine API enabled (`gcloud services enable compute.googleapis.com`)

## Quick start

```bash
cd deploy/gcp
./provision.sh
```

The script prompts for:
- GCP project ID (defaults to your current `gcloud config` project)
- Region (default: `us-central1`)
- Machine type (default: `e2-medium`)
- Instance name (default: `sontara-lattice`)
- Optional Tailscale VPN setup

Provisioning takes about 3–5 minutes after the VM is created (Docker install + Go build + service startup).

## Machine type guidance

| Machine | vCPU | RAM | Fleet size |
|---------|------|-----|------------|
| `e2-medium` | 2 | 4 GB | Up to ~10 peers |
| `e2-standard-2` | 2 | 8 GB | 10–50 peers |
| `e2-standard-4` | 4 | 16 GB | 50+ peers |
| `e2-standard-8` | 8 | 32 GB | High-throughput / many daemons |

## What gets provisioned

**VM:**
- Ubuntu 24.04 LTS, 50 GB balanced persistent disk
- Tagged `sontara` (firewall rules target this tag)

**Firewall rules** (created in your project):
| Rule | Port | Service |
|------|------|---------|
| `sontara-allow-broker` | TCP 7899 | Trust broker API |
| `sontara-allow-gridwatch` | TCP 8888 | Gridwatch dashboard |
| `sontara-allow-nats` | TCP 4222, 8222 | NATS JetStream + monitoring |
| `sontara-allow-wazuh` | TCP 1514, 1515, 55000, UDP 514 | Wazuh agent enrollment + syslog |

**Services (via Docker Compose):**
- `broker` — trust broker (port 7899)
- `nats` — JetStream message bus (port 4222)
- `wazuh-manager` — EDR manager (ports 1514/1515/55000/514)
- `gridwatch` — real-time dashboard (port 8888)
- `supervisor` — daemon orchestrator
- `wazuh-bridge` — bridges Wazuh alerts to NATS
- `security-watch` — distributed attack correlator
- `response-daemon` — automated incident response

## Monitor startup

```bash
gcloud compute ssh sontara-lattice --zone=us-central1-b -- \
  'tail -f /var/log/sontara-startup.log'
```

## Access the stack

```
Broker health:    http://<IP>:7899/health
Dashboard:        http://<IP>:8888
NATS monitoring:  http://<IP>:8222
```

## Connect client machines

On each machine you want to add to the fleet:

```bash
# 1. Install the binary
go install github.com/your-github-org/sontara-lattice@latest
# or scp the pre-built binary from releases

# 2. Initialize as a client pointing at your GCP broker
claude-peers init client http://<VM_IP>:7899
```

## Tailscale (optional)

If you chose Tailscale during provisioning, the VM advertises itself as an exit node. After the node appears in your [Tailscale admin console](https://login.tailscale.com/admin/machines), approve the exit node route.

You can then use the Tailscale IP for all connections — no public firewall rules needed. In that case, delete the sontara firewall rules after switching:

```bash
gcloud compute firewall-rules delete sontara-allow-broker sontara-allow-gridwatch \
  sontara-allow-nats sontara-allow-wazuh
```

For a full Tailscale-only setup without any public ports, see [`../tailscale/setup.sh`](../tailscale/setup.sh).

## Teardown

```bash
./teardown.sh --instance sontara-lattice --project <PROJECT> --zone us-central1-b
```

This deletes the VM and all firewall rules. Docker volumes are destroyed with the VM — export any data first.

To keep the firewall rules (e.g., you plan to reprovision soon):

```bash
./teardown.sh --instance sontara-lattice --project <PROJECT> --zone us-central1-b --keep-firewall
```

## Troubleshooting

**VM created but services not responding after 10 minutes:**
```bash
gcloud compute ssh sontara-lattice --zone=us-central1-b -- 'cat /var/log/sontara-startup.log'
```

**Docker not running:**
```bash
gcloud compute ssh sontara-lattice --zone=us-central1-b -- 'systemctl status docker'
```

**Check running containers:**
```bash
gcloud compute ssh sontara-lattice --zone=us-central1-b -- \
  'cd /opt/sontara-lattice && docker compose ps'
```

**Broker health check:**
```bash
curl http://<VM_IP>:7899/health
```
