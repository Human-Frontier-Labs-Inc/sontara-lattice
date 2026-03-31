#!/bin/bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

setup_local() {
    echo ""
    echo "--- Local Docker Compose Setup ---"
    echo ""

    # Check prerequisites
    if ! command -v docker &>/dev/null; then
        echo "ERROR: docker is not installed. Install Docker Desktop or Docker Engine first."
        echo "  https://docs.docker.com/get-docker/"
        exit 1
    fi

    if ! docker compose version &>/dev/null 2>&1 && ! docker-compose version &>/dev/null 2>&1; then
        echo "ERROR: docker compose is not available."
        echo "  Install Docker Compose v2: https://docs.docker.com/compose/install/"
        exit 1
    fi

    COMPOSE_CMD="docker compose"
    if ! docker compose version &>/dev/null 2>&1; then
        COMPOSE_CMD="docker-compose"
    fi

    # Generate NATS token
    NATS_TOKEN=$(head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 32)
    echo "Generated NATS token."

    # Write .env
    ENV_FILE="${REPO_DIR}/.env"
    if [ -f "${ENV_FILE}" ]; then
        echo ""
        read -p ".env already exists. Overwrite? [y/N]: " overwrite
        if [[ ! "${overwrite:-N}" =~ ^[Yy]$ ]]; then
            echo "Keeping existing .env."
        else
            write_env
        fi
    else
        write_env
    fi

    echo ""
    echo "Starting stack..."
    cd "${REPO_DIR}"
    ${COMPOSE_CMD} up -d --build

    echo ""
    echo "Waiting for broker to become healthy..."
    for i in $(seq 1 30); do
        if curl -sf http://localhost:7899/health >/dev/null 2>&1; then
            break
        fi
        sleep 2
    done

    echo ""
    echo "=== Sontara Lattice is running ==="
    echo ""
    echo "  Broker API:      http://localhost:7899"
    echo "  Gridwatch UI:    http://localhost:8888"
    echo "  NATS:            nats://localhost:4222"
    echo "  NATS Monitor:    http://localhost:8222"
    echo "  Wazuh Manager:   https://localhost:55000"
    echo ""
    echo "To initialize the broker keypair and root token:"
    echo "  docker compose exec broker claude-peers init broker"
    echo ""
    echo "To check broker status:"
    echo "  curl http://localhost:7899/health"
    echo ""
    echo "To stop the stack:"
    echo "  docker compose down"
    echo ""
}

write_env() {
    cat > "${REPO_DIR}/.env" <<EOF
# Sontara Lattice — local deployment config
NATS_TOKEN=${NATS_TOKEN}

# LLM endpoint for daemon workflows (point at LiteLLM or compatible proxy)
LLM_BASE_URL=http://host.docker.internal:4000/v1
LLM_MODEL=vertex_ai/claude-sonnet-4-6
LLM_API_KEY=
EOF
    echo "Written .env"
}

setup_gcp() {
    echo ""
    PROVISION_SCRIPT="${REPO_DIR}/deploy/gcp/provision.sh"

    if [ ! -f "$PROVISION_SCRIPT" ]; then
        echo "ERROR: GCP provisioning script not found at deploy/gcp/provision.sh"
        exit 1
    fi

    if ! command -v gcloud >/dev/null 2>&1; then
        echo "ERROR: gcloud CLI not found."
        echo "Install: https://cloud.google.com/sdk/docs/install"
        exit 1
    fi

    bash "$PROVISION_SCRIPT"
}

echo "=== Sontara Lattice Setup ==="
echo ""
echo "Choose deployment:"
echo "  1) Local (Docker Compose)"
echo "  2) GCP (Google Cloud)"
echo ""
read -p "Selection [1]: " choice

case "${choice:-1}" in
  1) setup_local ;;
  2) setup_gcp ;;
  *) echo "Invalid selection."; exit 1 ;;
esac
