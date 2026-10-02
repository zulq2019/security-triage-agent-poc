#!/usr/bin/env bash
# SYNTHETIC usage data for demoing the dashboard Usage tab. NOT run by default, never called by a real run.
# Writes ~30 days of plausible model-call rows (Ollama models from rules/gateway/models.yaml plus the OpenAI / Azure
# PLACEHOLDER model names and PLACEHOLDER prices from the price book) into ModelUsage, every row flagged synthetic = 1.
# Re-running replaces earlier synthetic rows; real rows are never touched. The Usage tab shows a
# "Synthetic sample data in view" badge whenever any of these rows are in range, and a toggle hides them.
#   scripts/seed-usage.sh                 # 30 days, seed 42
#   scripts/seed-usage.sh --days 14 --seed 7
#   scripts/seed-usage.sh --clear         # remove all synthetic rows
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
DLL="$ROOT/src/SecAgent.Dashboard/bin/Debug/net10.0/secagent.dll"
[ -f "$DLL" ] || dotnet build "$ROOT/SecAgent.slnx" -v q
dotnet "$DLL" seed-usage "$@"
