#!/usr/bin/env bash
# Prints short release notes: what changed since the last release, from commit messages.
# Usage: release-notes.sh <previous-tag-regex> [git pathspec ...]
#   e.g. release-notes.sh '^(build-|v[0-9])' . ':!windows'
# Needs: full git history (fetch-depth: 0) and GH_TOKEN for `gh`.
# Set PREV_TAG to force the starting tag (used for testing).
set -euo pipefail

regex="$1"; shift
paths=("$@")
[ ${#paths[@]} -eq 0 ] && paths=(.)

prev="${PREV_TAG:-}"
if [ -z "$prev" ]; then
  prev=$(gh release list --limit 50 --json tagName,publishedAt \
    --jq "map(select(.tagName | test(\"$regex\"))) | sort_by(.publishedAt) | reverse | .[0].tagName // \"\"" 2>/dev/null || true)
fi

range="HEAD"
if [ -n "$prev" ] && git rev-parse -q --verify "refs/tags/$prev^{commit}" >/dev/null; then
  range="$prev..HEAD"
  count_arg=()
else
  count_arg=(-n 5)
fi

notes=$(git log "${count_arg[@]}" --no-merges --pretty='%an%x09- %s' "$range" -- "${paths[@]}" \
  | { grep -v -i '^dependabot' || true; } | cut -f2- | head -n 15)

if [ -z "$notes" ]; then
  notes="- Maintenance build, no visible changes."
fi

printf "What's new:\n%s\n" "$notes"
