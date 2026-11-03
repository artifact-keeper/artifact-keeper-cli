#!/usr/bin/env bash
# Print the backend version an E2E leg runs against.
#
#   pinned          the version in API_VERSION, which the SDK is generated from
#   latest          the newest backend release
#   previous-minor  the newest patch of the minor before the pin, the oldest
#                   server this CLI supports
#
# Usage: e2e-backend-version.sh <pinned|latest|previous-minor>
set -euo pipefail

leg="${1:?usage: $0 <pinned|latest|previous-minor>}"
backend=artifact-keeper/artifact-keeper
pinned="$(tr -d '[:space:]' < API_VERSION)"

case "$leg" in
  pinned)
    echo "$pinned"
    ;;
  latest)
    gh api "repos/$backend/releases/latest" --jq .tag_name | sed 's/^v//'
    ;;
  previous-minor)
    major="${pinned%%.*}"
    rest="${pinned#*.}"
    minor="${rest%%.*}"
    previous="$major.$((minor - 1))"
    version="$(gh api --paginate "repos/$backend/releases" \
        --jq '.[] | select(.prerelease | not) | select(.draft | not) | .tag_name' \
      | sed 's/^v//' | { grep -E "^${previous//./\\.}\.[0-9]+$" || true; } | sort -V | tail -1)"
    if [ -z "$version" ]; then
      echo "::error::The backend has no release on $previous" >&2
      exit 1
    fi
    echo "$version"
    ;;
  *)
    echo "::error::Unknown leg '$leg'" >&2
    exit 1
    ;;
esac
