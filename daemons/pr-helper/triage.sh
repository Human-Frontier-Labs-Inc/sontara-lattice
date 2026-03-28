#!/bin/bash
# PR Helper triage: only run if there are open PRs across any org.
for org in human-frontier-lab williavs WillyV3; do
  repos=$(gh repo list "$org" --no-archived --json name -q '.[].name' --limit 100 2>/dev/null)
  for repo in $repos; do
    # Skip dotfiles repos
    echo "$repo" | grep -qi dotfiles && continue
    count=$(gh pr list --repo "$org/$repo" --state open --json number -q 'length' 2>/dev/null)
    [ "${count:-0}" -gt 0 ] && echo "$org/$repo has $count open PRs" && exit 0
  done
done
exit 1
