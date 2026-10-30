#!/usr/bin/env bash
# Fail if a Linux binary requires a newer glibc than GLIBC_FLOOR.
#
# The floor is set by the glibc the binary was linked against, not by anything
# in our code, so it silently rises whenever the build image moves to a newer
# distro. Asserting it keeps `ak` runnable on Debian 12, Ubuntu 22.04, RHEL 9
# and Amazon Linux 2023. See artifact-keeper-cli#178.
#
# Usage: check-glibc-floor.sh <binary> [floor]   (floor defaults to $GLIBC_FLOOR)
set -euo pipefail

binary="${1:?usage: $0 <binary> [floor]}"
floor="${2:-${GLIBC_FLOOR:?GLIBC_FLOOR is not set}}"

required="$(readelf -V --wide "$binary" | grep -o 'GLIBC_2\.[0-9]*' | sed 's/^GLIBC_//' | sort -uV | tail -n1)"
if [ -z "$required" ]; then
  echo "::error::no GLIBC symbol versions found in $binary (not a glibc-linked ELF?)"
  exit 1
fi

echo "$binary requires glibc $required (floor: $floor)"
highest="$(printf '%s\n%s\n' "$required" "$floor" | sort -V | tail -n1)"
if [ "$highest" != "$floor" ]; then
  echo "::error::$binary requires glibc $required, above the supported floor of $floor."
  echo "Symbols above the floor:"
  readelf -V --wide "$binary" | grep -o 'GLIBC_2\.[0-9]*' | sort -uV | while read -r v; do
    [ "$(printf '%s\n%s\n' "${v#GLIBC_}" "$floor" | sort -V | tail -n1)" = "$floor" ] || echo "  $v"
  done
  exit 1
fi
