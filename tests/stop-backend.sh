#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"

# Compose requires these to parse the file. Their values don't matter for `down`.
export API_VERSION=unused JWT_SECRET=unused

echo "Stopping E2E test backend..."
docker compose -f "$COMPOSE_FILE" down -v
