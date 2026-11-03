#!/usr/bin/env bash
# The body of the issue a failed release opens. It says where the tap stands, since
# that decides what someone has to do.
#
# Usage: release-failure-body.sh <run url>
# Reads RELEASE, HOMEBREW, VERIFY and VERIFY_MACOS: each job's result.
set -euo pipefail

run_url="${1:?usage: $0 <run url>}"

case "$HOMEBREW" in
  success)
    tap="The tap already points at this version, so brew users get it now. Only the macOS and brew check can show a problem at this point, because it installs from the tap, so it has to come after the tap moves. If the release is broken, revert Formula/ak.rb in artifact-keeper/homebrew-tap."
    ;;
  skipped)
    if [ "$VERIFY" != success ]; then
      tap="Linux verification didn't pass, so the tap wasn't touched and brew users keep the previous version."
    else
      tap="The tap wasn't touched, so brew users keep the previous version."
    fi
    ;;
  *)
    tap="The homebrew job didn't finish, so the tap may or may not have moved. Check Formula/ak.rb in artifact-keeper/homebrew-tap, and revert it if it points at this version."
    ;;
esac

cat <<BODY
Run: $run_url

release: $RELEASE, verify-release: $VERIFY, homebrew: $HOMEBREW, verify-macos: $VERIFY_MACOS

The release stays a prerelease, so install.sh and /releases/latest keep serving the previous one.

$tap
BODY
