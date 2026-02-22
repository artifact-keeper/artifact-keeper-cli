#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"

echo "Starting E2E test backend..."
docker compose -f "$COMPOSE_FILE" up -d

echo "Waiting for backend health check..."
for i in $(seq 1 60); do
    if curl -sf http://localhost:8081/health > /dev/null 2>&1; then
        echo "Backend is healthy (attempt $i)"
        exit 0
    fi
    sleep 2
done

echo "ERROR: Backend did not become healthy within 120 seconds"
docker compose -f "$COMPOSE_FILE" logs backend
exit 1
