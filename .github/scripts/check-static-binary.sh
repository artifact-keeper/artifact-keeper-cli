#!/usr/bin/env bash
# Fail unless a Linux binary is fully statically linked.
#
# The Linux release binaries are built for the *-unknown-linux-musl targets so
# they run on any distro regardless of its glibc version, including Alpine and
# distroless images (#178). That only holds while nothing pulls in a dynamic
# dependency, e.g. a crate that links a system library, so assert it.
#
# Usage: check-static-binary.sh <binary>
set -euo pipefail

binary="${1:?usage: $0 <binary>}"

needed="$(readelf -d --wide "$binary" 2>/dev/null | grep '(NEEDED)' || true)"
interp="$(readelf -l --wide "$binary" | grep -A1 'INTERP' || true)"

if [ -n "$needed" ] || [ -n "$interp" ]; then
  echo "::error::$binary is not statically linked."
  [ -n "$interp" ] && printf 'Program interpreter:\n%s\n' "$interp"
  [ -n "$needed" ] && printf 'Shared library dependencies:\n%s\n' "$needed"
  exit 1
fi

echo "$binary is statically linked (no program interpreter, no shared library dependencies)"
