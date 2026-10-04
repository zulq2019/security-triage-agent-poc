#!/usr/bin/env bash
# Copies replay-static/ into the demo site's /security-agent section (default /workspace/demo-deploy/security-agent) and applies the
# hosting edits: absolute /security-agent/ asset paths (the site uses trailingSlash: false) and the "local evidence store (not published)"
# label on blob:// evidence references. Does not deploy; run `vercel deploy --prod` from the demo folder afterwards.
#   scripts/publish-replay-demo.sh [demo-dir]
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd); SRC="$ROOT/replay-static"; DEST="${1:-/workspace/demo-deploy}/security-agent"
[ -f "$SRC/index.html" ] || { echo "no replay build: run scripts/build-replay.sh first" >&2; exit 1; }
rm -rf "$DEST.tmp" && mkdir -p "$DEST.tmp" && cp -r "$SRC/." "$DEST.tmp/"
python3 - "$DEST.tmp" <<'PY'
import json, sys, os
d = sys.argv[1]
p = os.path.join(d, 'index.html'); s = open(p).read()
for a, b in [('window.SECAGENT_REPLAY = "run.json"', 'window.SECAGENT_REPLAY = "/security-agent/run.json"'),
             ('<script src="run.js"></script>', '<script src="/security-agent/run.js"></script>'),
             ('<script src="assets/app.js"></script>', '<script src="/security-agent/assets/app.js"></script>')]:
    assert s.count(a) == 1, a; s = s.replace(a, b)
open(p, 'w').write(s)
for fn in ['run.json', 'run.js']:
    p = os.path.join(d, fn); t = open(p).read().replace('blob://raw/', 'local evidence store (not published) blob://raw/'); open(p, 'w').write(t)
json.load(open(os.path.join(d, 'run.json')))
t = open(os.path.join(d, 'run.js')).read(); json.loads(t[len('window.SECAGENT_RUN = '):].rstrip().rstrip(';'))
PY
rm -rf "$DEST" && mv "$DEST.tmp" "$DEST"
echo "published replay → $DEST"
