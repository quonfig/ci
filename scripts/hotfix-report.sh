#!/usr/bin/env bash
# Monthly SSDLC audit evidence: every merged PR in the quonfig org that carried
# the `hotfix` label (i.e. bypassed the AI sanity check) in a date window.
#
# Usage: scripts/hotfix-report.sh [SINCE] [UNTIL]
#   SINCE/UNTIL are YYYY-MM-DD. Default: the previous calendar month.
set -euo pipefail

if [ $# -ge 1 ]; then
  since=$1
  until=${2:-$(date -u +%Y-%m-%d)}
else
  # Previous calendar month (BSD date on macOS, GNU date on Linux).
  if date -v-1m >/dev/null 2>&1; then
    since=$(date -v-1m -v1d +%Y-%m-%d)
    until=$(date -v1d -v-1d +%Y-%m-%d)
  else
    since=$(date -d "$(date +%Y-%m-01) -1 month" +%Y-%m-%d)
    until=$(date -d "$(date +%Y-%m-01) -1 day" +%Y-%m-%d)
  fi
fi

echo "Hotfix-labeled PRs merged in quonfig org, $since .. $until"
echo
gh search prs --owner quonfig --label hotfix --merged \
  --merged-at "$since..$until" --limit 200 \
  --json repository,number,title,author,closedAt,url \
  --template '{{range .}}{{.closedAt}}	{{.repository.nameWithOwner}}#{{.number}}	{{.author.login}}	{{.title}}	{{.url}}{{"\n"}}{{end}}'
echo
echo "For each PR, confirm a justification comment and a linked follow-up bead exist."
