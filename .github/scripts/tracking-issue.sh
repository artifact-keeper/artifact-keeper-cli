#!/usr/bin/env bash
# Keep one issue per problem: open it, or comment on the open one, while the
# problem lasts, and close it when it's gone. Finds the issue by its exact title.
#
# Usage: tracking-issue.sh fail <title> <body>
#        tracking-issue.sh pass <title> <comment>
set -euo pipefail

action="${1:?usage: $0 <fail|pass> <title> <body>}"
title="${2:?usage: $0 <fail|pass> <title> <body>}"
body="${3:?usage: $0 <fail|pass> <title> <body>}"

number="$(TITLE="$title" gh issue list --state open --search "\"$title\" in:title" \
  --json number,title --jq '.[] | select(.title == env.TITLE) | .number' | head -1)"

case "$action" in
  fail)
    if [ -n "$number" ]; then
      gh issue comment "$number" --body "$body"
    else
      gh issue create --title "$title" --body "$body"
    fi
    ;;
  pass)
    if [ -n "$number" ]; then
      gh issue close "$number" --comment "$body"
    fi
    ;;
  *)
    echo "::error::Unknown action '$action'" >&2
    exit 1
    ;;
esac
