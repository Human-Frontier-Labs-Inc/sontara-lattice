#!/bin/bash
# PR Helper triage: only run if there are open PRs that need attention.
# Check repos for open PRs with failing checks or merge conflicts.
for repo in WillyV3/claude-peers-go WillyV3/v3Consult; do
  count=$(curl -sf "https://api.github.com/repos/$repo/pulls?state=open&per_page=5" 2>/dev/null | python3 -c '
import sys, json
prs = json.load(sys.stdin)
print(len(prs))
' 2>/dev/null)
  [ "${count:-0}" -gt 0 ] && echo "$repo has $count open PRs" && exit 0
done
exit 1
