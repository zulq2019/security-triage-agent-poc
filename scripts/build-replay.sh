#!/usr/bin/env bash
# Builds the no-backend replay of a recorded run into replay-static/ (index.html + run.json + run.js + assets/).
# Usage: [USAGE_SAMPLE_DAYS=30] scripts/build-replay.sh [run-id]     (default: latest completed run). Open replay-static/index.html directly or serve the folder statically.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd); OUT="$ROOT/replay-static"; WWW="$ROOT/src/SecAgent.Dashboard/wwwroot"
mkdir -p "$OUT/assets"
# USAGE_SAMPLE_DAYS (default 30): add the clearly flagged SYNTHETIC usage sample to the replay Usage tab; 0 = real usage of the run only.
dotnet "$ROOT/src/SecAgent.Dashboard/bin/Debug/net10.0/secagent.dll" export ${1:+--run "$1"} --usage-sample "${USAGE_SAMPLE_DAYS:-30}" --out "$OUT/run.json"
cp "$WWW/app.js" "$OUT/assets/app.js"
# Trends tab (replay only, SAMPLE DATA): src/SecAgent.Dashboard/replay/trends.html from scripts/build-trends-sample.py, placed after Usage.
python3 "$ROOT/scripts/build-trends-sample.py" >/dev/null
python3 - "$WWW/index.html" "$OUT/index.html" "$ROOT/src/SecAgent.Dashboard/replay/trends.html" <<'PY'
import sys
s = open(sys.argv[1]).read()
frag = open(sys.argv[3]).read()
css, section = frag.split('</style>', 1); css = css[css.index('<style>'):] + '</style>'
def put(old, new):
    global s
    assert s.count(old) == 1, old
    s = s.replace(old, new)
put('<div class="tab" data-v="usage">Usage</div>', '<div class="tab" data-v="usage">Usage</div>\n      <div class="tab" data-v="trends">Trends<span class="sample-pill">sample</span></div>')
put('<section class="view" id="v-controls"></section>', section.strip() + '\n  <section class="view" id="v-controls"></section>')
put('</head>', css + '\n</head>')
s = s.replace('<script src="app.js"></script>',
  '<script>window.SECAGENT_REPLAY = "run.json";</script>\n<script src="run.js"></script>\n<script src="assets/app.js"></script>')
s = s.replace('<title>', '<title>Replay of a recorded run · ', 1)
open(sys.argv[2], 'w').write(s)
PY
echo "replay build: $OUT/index.html"
