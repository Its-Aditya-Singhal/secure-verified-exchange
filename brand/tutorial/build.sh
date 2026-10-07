#!/usr/bin/env bash
# Build the "Learn how to use SVX" videos.
#
#   brand/tutorial/build.sh [CH ...]      chapters (default: all), e.g. 3-send
#   brand/tutorial/build.sh --full        also join every chapter into one video
#
# One-time setup (all free, local):
#   cd brand/tutorial && python3 -m venv .venv && .venv/bin/pip install kokoro-onnx soundfile
#   models/kokoro-v1.0.onnx, models/voices-v1.0.bin from
#     https://github.com/thewh1teagle/kokoro-onnx/releases (model-files-v1.0)
#   npm install          (puppeteer-core; uses the installed Google Chrome)
#
# Steps: the real desktop UI with a mock Tauri (out/app) -> narration
# (voice.py, af_heart) -> frames (render.mjs, 60 fps, 2 sub-frames of motion
# blur) -> soundtrack (audio.py) -> out/final/svx-learn-CH.mp4 + poster + .vtt
set -euo pipefail
cd "$(dirname "$0")"
ROOT=$(cd ../.. && pwd)
VOICE=${SVX_VOICE:-af_heart}
FULL=0
CHS=()
for a in "$@"; do [ "$a" = --full ] && FULL=1 || CHS+=("$a"); done
[ ${#CHS[@]} -gt 0 ] || CHS=($(python3 -c "import json;print(' '.join(c['id'] for c in json.load(open('script.json'))['chapters']))"))

(cd "$ROOT/apps/desktop" && npx vite build --logLevel error --config ../../brand/tutorial/app/vite.config.ts)
[ -f out/timing.json ] && [ out/timing.json -nt script.json ] || .venv/bin/python voice.py chapters "$VOICE"

# The stage loads files from the repo: serve it locally for Chrome.
if ! curl -s -o /dev/null http://127.0.0.1:8803/brand/tutorial/stage.html; then
  (cd "$ROOT" && python3 -m http.server 8803 --bind 127.0.0.1 >/dev/null 2>&1 &)
  sleep 1
fi

mkdir -p out/final
for ch in "${CHS[@]}"; do
  echo "== $ch"
  [ -n "${SVX_REUSE_VIDEO:-}" ] && [ -f "out/video/$ch.mp4" ] && [ -f "out/cues/$ch.json" ] || node render.mjs video "$ch" 60 2
  python3 audio.py "$ch"
  ffmpeg -loglevel error -y -i "out/video/$ch.mp4" -i "out/audio/$ch.wav" -map 0:v -map 1:a \
    -c:v libx264 -preset slow -crf 22 -pix_fmt yuv420p -profile:v high -movflags +faststart \
    -c:a aac -b:a 160k -shortest "out/final/svx-learn-$ch.mp4"
  # Poster: a frame from the middle of the chapter.
  mid=$(python3 -c "import json;print(json.load(open('out/timing.json'))['$ch']['duration']/2)")
  ffmpeg -loglevel error -y -ss "$mid" -i "out/final/svx-learn-$ch.mp4" -frames:v 1 -vf scale=1280:-2 -q:v 3 "out/final/svx-learn-$ch.jpg"
  python3 - "$ch" <<'PY'
import json, sys
ch = sys.argv[1]
lines = json.load(open("out/timing.json"))[ch]["lines"]
ts = lambda s: f"{int(s // 3600):02d}:{int(s % 3600 // 60):02d}:{s % 60:06.3f}"
cues = ["WEBVTT", ""]
for i, (a, b, text) in enumerate(lines):
    cues += [str(i + 1), f"{ts(a)} --> {ts(b + 0.25)}", text.replace("dot S V X", ".svx").replace("getsvx dot me", "getsvx.me"), ""]
open(f"out/final/svx-learn-{ch}.vtt", "w").write("\n".join(cues))
PY
  ls -la "out/final/svx-learn-$ch.mp4"
done

if [ $FULL = 1 ]; then
  ls out/final/svx-learn-[0-9]-*.mp4 | sort | sed "s|^|file '$PWD/|;s|$|'|" > out/final/list.txt
  ffmpeg -loglevel error -y -f concat -safe 0 -i out/final/list.txt -c copy -movflags +faststart out/final/svx-learn-full.mp4
  ls -la out/final/svx-learn-full.mp4
fi
