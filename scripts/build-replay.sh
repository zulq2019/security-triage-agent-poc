#!/usr/bin/env bash
# Builds the no-backend replay of a recorded run into replay-static/ (index.html + run.json + run.js + assets/).
# Usage: scripts/build-replay.sh [run-id]     (default: latest completed run). Open replay-static/index.html directly or serve the folder statically.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd); OUT="$ROOT/replay-static"; WWW="$ROOT/src/SecAgent.Dashboard/wwwroot"
mkdir -p "$OUT/assets"
dotnet "$ROOT/src/SecAgent.Dashboard/bin/Debug/net10.0/secagent.dll" export ${1:+--run "$1"} --out "$OUT/run.json"
cp "$WWW/app.js" "$OUT/assets/app.js"
python3 - "$WWW/index.html" "$OUT/index.html" <<'PY'
import sys
s = open(sys.argv[1]).read()
s = s.replace('<script src="app.js"></script>',
  '<script>window.SECAGENT_REPLAY = "run.json";</script>\n<script src="run.js"></script>\n<script src="assets/app.js"></script>')
s = s.replace('<title>', '<title>Replay of a recorded run · ', 1)
open(sys.argv[2], 'w').write(s)
PY
echo "replay build: $OUT/index.html"
