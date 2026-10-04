#!/usr/bin/env bash
# D-06: re-running the agent on the same PR must not open duplicate fix PRs or duplicate findings.
# Usage: scripts/rerun-check.sh [repo] [pr]
set -euo pipefail
REPO=${1:-zulq2019/sec-agent-sample-app}; PR=${2:-1}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
DLL="$ROOT/src/SecAgent.Dashboard/bin/Debug/net10.0/secagent.dll"
count_prs() { gh pr list -R "$REPO" --state all --search "head:fix/" --json number,headRefName --limit 200 | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))'; }
heads()     { gh pr list -R "$REPO" --state all --search "head:fix/" --json headRefName --limit 200 | python3 -c 'import json,sys; print(" ".join(sorted(p["headRefName"] for p in json.load(sys.stdin))))'; }
before=$(count_prs); before_heads=$(heads)
echo "fix PRs before re-run: $before ($before_heads)"
start=$(date +%s)
dotnet "$DLL" run --repo "$REPO" --pr "$PR" | tail -n 25
echo "re-run took $(( $(date +%s) - start ))s"
after=$(count_prs); after_heads=$(heads)
echo "fix PRs after re-run:  $after ($after_heads)"
if [[ "$before" == "$after" && "$before_heads" == "$after_heads" ]]; then echo "D-06 PASS: no duplicate PRs"; else echo "D-06 FAIL: PR set changed"; exit 1; fi
