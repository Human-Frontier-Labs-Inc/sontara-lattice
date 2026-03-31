#!/bin/bash
# PR Helper: skip if our machine is quarantined (don't push from compromised host).
BROKER_URL="${CLAUDE_PEERS_BROKER_URL:-http://127.0.0.1:7899}"
MACHINE_NAME="${CLAUDE_PEERS_MACHINE:-$(hostname)}"
health=$(curl -sf -H "Authorization: Bearer $(cat ~/.config/claude-peers/token.jwt 2>/dev/null)" "$BROKER_URL/machine-health" 2>/dev/null)
our_status=$(echo "$health" | python3 -c "import sys,json; d=json.load(sys.stdin); h=d.get('$MACHINE_NAME',{}); print(h.get('status','healthy'))" 2>/dev/null)
if [ "$our_status" = "quarantined" ]; then
    echo "SKIP: $MACHINE_NAME is quarantined, refusing to push code"
    exit 1
fi
# Check for open PRs across configured orgs.
# Set PR_HELPER_ORGS env var (comma-separated) with your GitHub org names.
ORGS="${PR_HELPER_ORGS:-}"
IFS=',' read -ra ORG_LIST <<< "$ORGS"
for org in "${ORG_LIST[@]}"; do
    [ -z "$org" ] && continue
    repos=$(gh repo list "$org" --no-archived --json name -q '.[].name' --limit 100 2>/dev/null)
    for repo in $repos; do
        echo "$repo" | grep -qi dotfiles && continue
        count=$(gh pr list --repo "$org/$repo" --state open --json number -q 'length' 2>/dev/null)
        [ "${count:-0}" -gt 0 ] && echo "$org/$repo has $count open PRs" && exit 0
    done
done
exit 1
