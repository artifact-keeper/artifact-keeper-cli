#!/usr/bin/env bash
# Refuse a tag that doesn't match the code it points at, before anything builds.
#
# Tags are vX.Y.Z or vX.Y.Z-rc.N. Nothing else is allowed, because release.yml
# tells a prerelease from a release by the hyphen, and a tag such as v1.11.0rc1
# would otherwise count as a release and move the Homebrew tap.
#
# Usage: release-preflight.sh <tag>
set -euo pipefail

tag="${1:?usage: $0 <tag>}"

if ! [[ "$tag" =~ ^v([0-9]+\.[0-9]+\.[0-9]+)(-rc\.[0-9]+)?$ ]]; then
  echo "::error::Tag '$tag' is not vX.Y.Z or vX.Y.Z-rc.N."
  exit 1
fi
version="${BASH_REMATCH[1]}"
rc="${BASH_REMATCH[2]}"

cargo_version="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
if [ "$cargo_version" != "$version" ]; then
  echo "::error::Tag '$tag' is version $version, but Cargo.toml has $cargo_version."
  exit 1
fi

# An rc can run on an undated section. A release has to say when it happened.
heading="$(grep -F "## [$version]" CHANGELOG.md | head -1 || true)"
if [ -z "$heading" ]; then
  echo "::error::CHANGELOG.md has no section for $version."
  exit 1
fi
if [ -z "$rc" ] && ! [[ "$heading" =~ ^##\ \[$version\]\ -\ [0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
  echo "::error::CHANGELOG.md needs a date for $version: '$heading'."
  exit 1
fi

echo "Tag $tag matches Cargo.toml and CHANGELOG.md"
