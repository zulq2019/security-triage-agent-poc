#!/usr/bin/env bash
# infra/validate.sh - local + CI validation of the Bicep (no Azure login, nothing is deployed).
#   1. bicep build  every .bicep file (main, rg, types, agents, modules) -> ARM JSON compiles
#   2. bicep lint   every .bicep and .bicepparam file      -> linter rules in infra/bicepconfig.json
#   3. bicep build-params every params/*.bicepparam        -> parameter files match main.bicep
# Fails on any error, and on any warning except use-recent-api-versions (which only ages with time).
# Uses "az bicep" when the Azure CLI is installed (as in CI), otherwise a standalone "bicep" binary.
set -uo pipefail
cd "$(dirname "$0")" || exit 2

if [[ "${USE_STANDALONE_BICEP:-0}" != "1" ]] && command -v az >/dev/null 2>&1; then
  build()        { az bicep build --file "$1" --stdout >/dev/null; }
  lint()         { az bicep lint --file "$1"; }
  build_params() { az bicep build-params --file "$1" --stdout >/dev/null; }
  echo "Using: az bicep ($(az bicep version 2>/dev/null | head -1))"
elif command -v bicep >/dev/null 2>&1; then
  build()        { bicep build "$1" --stdout >/dev/null; }
  lint()         { bicep lint "$1"; }
  build_params() { bicep build-params "$1" --stdout >/dev/null; }
  echo "Using: $(bicep --version)"
else
  echo "Neither 'az' nor 'bicep' found. Install the Azure CLI (then 'az bicep install') or the Bicep CLI." >&2
  exit 2
fi

fail=0
run() { # run <label> <fn> <file>
  local out rc
  out=$("$2" "$3" 2>&1); rc=$?
  if [[ $rc -ne 0 ]] || grep -E ': (Error|Warning) ' <<<"$out" | grep -vq 'use-recent-api-versions'; then
    echo "FAIL  $1 $3"; printf '%s\n' "$out" | grep -E ': (Error|Warning) ' | sed 's/^/      /'; fail=1
  else
    echo "ok    $1 $3"
    grep -E 'use-recent-api-versions' <<<"$out" | sed 's/^/      (info) /' || true
  fi
}

for f in ./*.bicep modules/*.bicep; do run build build "$f"; run lint lint "$f"; done
for p in params/*.bicepparam; do run lint lint "$p"; run build-params build_params "$p"; done

if [[ $fail -ne 0 ]]; then echo "Bicep validation FAILED"; exit 1; fi
echo "Bicep validation passed"
