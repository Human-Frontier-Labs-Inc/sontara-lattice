#!/bin/bash
set -euo pipefail

echo "=== Sontara Lattice GCP Teardown ==="
echo ""

# Parse arguments
INSTANCE=""
PROJECT=""
ZONE=""
KEEP_FIREWALL=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --instance) INSTANCE="$2"; shift 2 ;;
    --project)  PROJECT="$2";  shift 2 ;;
    --zone)     ZONE="$2";     shift 2 ;;
    --keep-firewall) KEEP_FIREWALL=true; shift ;;
    *) echo "Unknown argument: $1"; exit 1 ;;
  esac
done

# Check prerequisites
if ! command -v gcloud >/dev/null 2>&1; then
  echo "ERROR: gcloud CLI not found."
  exit 1
fi

# Fill in from gcloud config if not provided
if [ -z "$PROJECT" ]; then
  PROJECT=$(gcloud config get-value project 2>/dev/null || echo "")
  read -p "GCP Project [${PROJECT:-none}]: " INPUT_PROJECT
  PROJECT="${INPUT_PROJECT:-$PROJECT}"
fi
if [ -z "$PROJECT" ]; then
  echo "ERROR: No project specified."
  exit 1
fi

if [ -z "$INSTANCE" ]; then
  read -p "Instance name [sontara-lattice]: " INPUT_INSTANCE
  INSTANCE="${INPUT_INSTANCE:-sontara-lattice}"
fi

if [ -z "$ZONE" ]; then
  read -p "Zone [us-central1-b]: " INPUT_ZONE
  ZONE="${INPUT_ZONE:-us-central1-b}"
fi

echo ""
echo "--- Teardown plan ---"
echo "Project:       $PROJECT"
echo "Zone:          $ZONE"
echo "Instance:      $INSTANCE"
echo "Firewall:      $([[ "$KEEP_FIREWALL" == true ]] && echo 'keep' || echo 'delete')"
echo ""
echo "WARNING: This will permanently delete the VM and all its data."
echo "Docker volumes (broker-data, nats-data, wazuh-data) will be lost."
echo ""
read -p "Type 'yes' to confirm: " CONFIRM
if [ "$CONFIRM" != "yes" ]; then
  echo "Aborted."
  exit 0
fi

echo ""
echo "=== Deleting VM ==="

if gcloud compute instances describe "$INSTANCE" --project="$PROJECT" --zone="$ZONE" >/dev/null 2>&1; then
  gcloud compute instances delete "$INSTANCE" \
    --project="$PROJECT" \
    --zone="$ZONE" \
    --quiet
  echo "  $INSTANCE: deleted"
else
  echo "  $INSTANCE: not found, skipping"
fi

if [ "$KEEP_FIREWALL" = false ]; then
  echo ""
  echo "=== Deleting firewall rules ==="

  delete_fw_rule() {
    local name="$1"
    if gcloud compute firewall-rules describe "$name" --project="$PROJECT" >/dev/null 2>&1; then
      gcloud compute firewall-rules delete "$name" --project="$PROJECT" --quiet
      echo "  $name: deleted"
    else
      echo "  $name: not found, skipping"
    fi
  }

  delete_fw_rule "sontara-allow-broker"
  delete_fw_rule "sontara-allow-gridwatch"
  delete_fw_rule "sontara-allow-nats"
  delete_fw_rule "sontara-allow-wazuh"
fi

echo ""
echo "=== Teardown complete ==="
echo ""
echo "The VM $INSTANCE and all associated data have been removed."
if [ "$KEEP_FIREWALL" = false ]; then
  echo "Firewall rules have been removed."
else
  echo "Firewall rules were kept (--keep-firewall)."
fi
