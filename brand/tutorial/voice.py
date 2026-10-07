#!/usr/bin/env python3
"""Narration for the "Learn how to use SVX" videos.

Each spoken line is synthesized on its own and the lines are joined with
chosen silences, so the voice breathes and pauses like a person reading,
instead of one long run-on sentence.

  .venv/bin/python voice.py samples          voice samples to choose from (out/samples/)
  .venv/bin/python voice.py chapters VOICE   every chapter from script.json -> out/voice/
                                             and out/timing.json (when each line starts)

A line in script.json is either text, or {"pause": seconds}. Text lines get a
default pause after them (PAUSE_AFTER) unless the next item is a pause.
Engine: Kokoro (Apache-2.0, kokoro-onnx), local, or "say:<macOS voice>".
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import numpy as np
import soundfile as sf

HERE = Path(__file__).resolve().parent
OUT = HERE / "out"
RATE = 24000
PAUSE_AFTER = 0.45          # between lines of the same idea
SPEED = 0.94                # a little slower than default: clearer for beginners

_kokoro = None


def kokoro():
    global _kokoro
    if _kokoro is None:
        from kokoro_onnx import Kokoro
        _kokoro = Kokoro(str(HERE / "models/kokoro-v1.0.onnx"), str(HERE / "models/voices-v1.0.bin"))
    return _kokoro


def speak(text, voice):
    """One line of speech as float32 mono at RATE, with leading/trailing silence trimmed."""
    if voice.startswith("say:"):
        with tempfile.TemporaryDirectory() as d:
            aiff, wav = Path(d) / "l.aiff", Path(d) / "l.wav"
            subprocess.run(["say", "-v", voice[4:], "-r", "172", "-o", str(aiff), text], check=True)
            subprocess.run(["ffmpeg", "-loglevel", "error", "-y", "-i", str(aiff), "-ar", str(RATE), "-ac", "1", str(wav)], check=True)
            audio, _ = sf.read(wav, dtype="float32")
    else:
        lang = "en-gb" if voice[:1] == "b" else "en-us"
        audio, sr = kokoro().create(text, voice=voice, speed=SPEED, lang=lang)
        assert sr == RATE
    return trim(np.asarray(audio, dtype=np.float32))


def trim(a, floor=0.012):
    idx = np.where(np.abs(a) > floor)[0]
    if len(idx) == 0:
        return a
    start = max(0, idx[0] - int(0.02 * RATE))
    end = min(len(a), idx[-1] + int(0.06 * RATE))
    return a[start:end]


def silence(sec):
    return np.zeros(int(sec * RATE), dtype=np.float32)


def narrate(items, voice):
    """Join the lines with pauses. Returns (audio, [(start, end, text)])."""
    parts, marks, t = [], [], 0.25
    parts.append(silence(0.25))
    for i, item in enumerate(items):
        if isinstance(item, dict):
            parts.append(silence(item["pause"]))
            t += item["pause"]
            continue
        a = speak(item, voice)
        marks.append((round(t, 3), round(t + len(a) / RATE, 3), item))
        parts.append(a)
        t += len(a) / RATE
        nxt = items[i + 1] if i + 1 < len(items) else None
        if not isinstance(nxt, dict):
            parts.append(silence(PAUSE_AFTER))
            t += PAUSE_AFTER
    parts.append(silence(0.6))
    return np.concatenate(parts), marks


def polish(src, dst):
    """Gentle cleanup so it sounds recorded, not synthetic: rumble cut, a touch
    of presence, light compression, a very small room, loudness for mixing."""
    chain = ("highpass=f=75,lowpass=f=11500,"
             "equalizer=f=220:t=q:w=1.2:g=1.2,equalizer=f=3200:t=q:w=1.4:g=1.8,"
             "acompressor=threshold=-20dB:ratio=2.2:attack=6:release=90:makeup=2,"
             "aecho=0.6:0.25:18|31:0.07|0.045,"
             "loudnorm=I=-18:TP=-2:LRA=7")
    subprocess.run(["ffmpeg", "-loglevel", "error", "-y", "-i", str(src), "-af", chain,
                    "-ar", "48000", "-ac", "1", str(dst)], check=True)


SAMPLE = [
    "Welcome to SVX.",
    {"pause": 0.6},
    "In the next few minutes, you'll learn how to send a file that only the person you choose can open.",
    {"pause": 0.7},
    "First, pick your file.",
    "Then, type the email address of the person you're sending it to.",
    {"pause": 0.6},
    "SVX locks the file right here, on your computer.",
    "And here's the best part.",
    {"pause": 0.35},
    "Even we can't open it.",
]

SAMPLE_VOICES = {
    "1-heart-female-us": "af_heart",
    "2-michael-male-us": "am_michael",
    "3-emma-female-uk": "bf_emma",
    "4-george-male-uk": "bm_george",
    "5-aman-male-india-siri": "say:Aman (English (India))",
}


def samples():
    d = OUT / "samples"
    d.mkdir(parents=True, exist_ok=True)
    for name, voice in SAMPLE_VOICES.items():
        audio, _ = narrate(SAMPLE, voice)
        raw = d / f"{name}.raw.wav"
        sf.write(raw, audio, RATE)
        polish(raw, d / f"{name}.wav")
        raw.unlink()
        subprocess.run(["ffmpeg", "-loglevel", "error", "-y", "-i", str(d / f"{name}.wav"),
                        "-c:a", "aac", "-b:a", "128k", str(d / f"{name}.m4a")], check=True)
        print(f"{name}: {len(audio) / RATE:.1f} s")


def chapters(voice):
    script = json.loads((HERE / "script.json").read_text())
    d = OUT / "voice"
    d.mkdir(parents=True, exist_ok=True)
    timing = {}
    for ch in script["chapters"]:
        audio, marks = narrate(ch["lines"], voice)
        raw = d / f"{ch['id']}.raw.wav"
        sf.write(raw, audio, RATE)
        polish(raw, d / f"{ch['id']}.wav")
        raw.unlink()
        timing[ch["id"]] = {"duration": round(len(audio) / RATE, 3), "lines": marks}
        print(f"{ch['id']}: {len(audio) / RATE:.1f} s, {len(marks)} lines")
    (OUT / "timing.json").write_text(json.dumps(timing, indent=1))


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "samples"
    if cmd == "samples":
        samples()
    elif cmd == "chapters":
        chapters(sys.argv[2])
    else:
        sys.exit(__doc__)
