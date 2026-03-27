#!/bin/bash
# Sync Janitor triage: only run if conflict files exist.
count=$(find ~/projects ~/hfl-projects -name "*.sync-conflict-*" 2>/dev/null | wc -l)
[ "$count" -gt 0 ] && echo "$count conflicts" && exit 0
exit 1
