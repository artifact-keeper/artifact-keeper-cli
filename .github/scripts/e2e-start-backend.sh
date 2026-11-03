#!/usr/bin/env bash
# Start a backend for the E2E tests and wait until it's healthy. It joins the
# network of the job's postgres service and listens on port 8081.
#
# Usage: e2e-start-backend.sh <version> <docker network>
set -euo pipefail

version="${1:?usage: $0 <version> <docker network>}"
network="${2:?usage: $0 <version> <docker network>}"

# The backend refuses to start on a weak or placeholder JWT_SECRET, and on one
# with fewer than 16 distinct characters. A random hex string sometimes has only
# 14 or 15, so use base64, which is also what the backend's error recommends.
JWT_SECRET="$(openssl rand -base64 48)"

docker run -d --name e2e-backend \
  --network "$network" \
  -e DATABASE_URL="postgresql://registry:registry@postgres:5432/artifact_registry_test" \
  -e ADMIN_PASSWORD="TestRunner!2026secure" \
  -e JWT_SECRET="$JWT_SECRET" \
  -e RATE_LIMIT_ENABLED="false" \
  -p 8081:8080 \
  "ghcr.io/artifact-keeper/artifact-keeper-backend:$version"

for i in $(seq 1 60); do
  if curl -sf http://localhost:8081/health > /dev/null 2>&1; then
    echo "Backend $version healthy after $i attempts"
    exit 0
  fi
  sleep 2
done
docker logs e2e-backend
exit 1
