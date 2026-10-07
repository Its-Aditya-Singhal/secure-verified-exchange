#!/usr/bin/env python3
"""Soundtrack for one tutorial chapter: an original, calm music bed, sound
effects at the cues the animation exported, and the narration, with the
music ducking under the voice. Everything is synthesized here (no samples,
no licences).

  python3 audio.py CH      ->  out/audio/CH.wav  (48 kHz stereo, mastered to -16 LUFS)
"""
import json
import subprocess
import sys
import wave
from pathlib import Path

import numpy as np
from scipy.signal import butter, sosfilt

HERE = Path(__file__).resolve().parent
OUT = HERE / "out"
SR = 48000


def lp(x, f, order=2):
    return sosfilt(butter(order, f, "low", fs=SR, output="sos"), x)


def hp(x, f, order=2):
    return sosfilt(butter(order, f, "high", fs=SR, output="sos"), x)


def bp(x, lo, hi, order=2):
    return sosfilt(butter(order, [lo, hi], "band", fs=SR, output="sos"), x)


def seg(d):
    return np.arange(int(d * SR)) / SR


def read_wav(p):
    with wave.open(str(p)) as w:
        a = np.frombuffer(w.readframes(w.getnframes()), dtype=np.int16).astype(np.float64) / 32768
        if w.getnchannels() == 2:
            a = a.reshape(-1, 2).mean(axis=1)
        assert w.getframerate() == SR, w.getframerate()
    return a


# ---------------------------------------------------------------- sound effects
rng = np.random.default_rng(7)


def env_ad(x, a, d):
    e = np.minimum(x / max(a, 1e-4), 1.0) * np.exp(-np.maximum(x - a, 0) / d)
    return e


def sfx_click():
    x = seg(0.06)
    n = rng.standard_normal(len(x))
    return bp(n, 1800, 6000) * env_ad(x, 0.0008, 0.008) * 0.55 + np.sin(2 * np.pi * 1300 * x) * env_ad(x, 0.0005, 0.006) * 0.25


def sfx_key():
    x = seg(0.05)
    n = rng.standard_normal(len(x))
    return bp(n, 2500, 8000) * env_ad(x, 0.0005, 0.006) * 0.35


def sfx_tick():
    x = seg(0.08)
    return np.sin(2 * np.pi * 2400 * x) * env_ad(x, 0.0005, 0.015) * 0.3


def sfx_pop():
    x = seg(0.18)
    f = 520 + 380 * np.exp(-x / 0.03)
    return np.sin(2 * np.pi * np.cumsum(f) / SR) * env_ad(x, 0.003, 0.05) * 0.4


def sfx_whoosh(d=0.75, up=True):
    x = seg(d)
    n = rng.standard_normal(len(x))
    shape = np.sin(np.pi * np.clip(x / d, 0, 1)) ** 2
    lo = bp(n, 300, 1400) * shape
    hi = hp(n, 3000) * shape * 0.35
    s = (lo + hi) * 0.32
    return s if up else s[::-1]


def sfx_swoosh():
    return sfx_whoosh(0.5) * 0.9


def sfx_drop():
    x = seg(0.35)
    thump = np.sin(2 * np.pi * (90 + 60 * np.exp(-x / 0.04)) * x) * env_ad(x, 0.002, 0.09) * 0.6
    pop = sfx_pop()
    return thump + np.pad(pop, (0, len(x) - len(pop))) * 0.4


def sfx_success():
    out = np.zeros(int(0.9 * SR))
    for i, f in enumerate([660, 880, 1320]):
        x = seg(0.6)
        tone = (np.sin(2 * np.pi * f * x) + 0.3 * np.sin(2 * np.pi * 2 * f * x)) * env_ad(x, 0.004, 0.22) * 0.18
        s = int(i * 0.09 * SR)
        out[s:s + len(tone)] += tone
    return out


def sfx_lock():
    x = seg(0.5)
    clunk = np.sin(2 * np.pi * 140 * x) * env_ad(x, 0.002, 0.07) * 0.55
    metal = bp(rng.standard_normal(len(x)), 2500, 7000) * env_ad(x, 0.001, 0.02) * 0.3
    ring = np.sin(2 * np.pi * 1760 * x) * env_ad(x, 0.003, 0.18) * 0.08
    return clunk + metal + ring


SFX = {"click": sfx_click, "key": sfx_key, "tick": sfx_tick, "pop": sfx_pop, "whoosh": sfx_whoosh,
       "swoosh": sfx_swoosh, "drop": sfx_drop, "success": sfx_success, "lock": sfx_lock}


# ---------------------------------------------------------------- music bed
def music(dur):
    """A calm, warm bed: slow chords (Am - F - C - G at 84 BPM), a soft pulse
    and a light plucked line, gently filtered so the voice sits on top."""
    N = int(round(dur * SR))
    t = np.arange(N) / SR
    bar = 60 / 84 * 4
    chords = [(110.0, [220.0, 261.63, 329.63, 440.0]), (87.31, [174.61, 220.0, 261.63, 349.23]),
              (130.81, [196.0, 261.63, 329.63, 392.0]), (98.0, [196.0, 246.94, 293.66, 392.0])]
    L = np.zeros(N); R = np.zeros(N)
    nbars = int(np.ceil(dur / bar)) + 1
    for b in range(nbars):
        bass, notes = chords[b % 4]
        s = int(b * bar * SR)
        if s >= N:
            break
        x = seg(bar * 1.15)
        e = np.minimum(x / 0.9, 1.0) * np.minimum(1, (bar * 1.15 - x) / 0.6)
        pad = np.zeros(len(x))
        for i, f in enumerate(notes):
            det = 1 + (i - 1.5) * 0.0018
            pad += np.sin(2 * np.pi * f * det * x + i) + 0.35 * np.sin(2 * np.pi * 2 * f * det * x)
        pad = lp(pad, 1800) * e * 0.05
        low = np.sin(2 * np.pi * bass * x) * e * 0.08
        end = min(N, s + len(x))
        L[s:end] += (pad * 1.0 + low)[: end - s]
        R[s:end] += (np.roll(pad, 240) * 1.0 + low)[: end - s]
        # plucked line, eighth notes, very soft
        step = bar / 8
        for k in range(8):
            if k in (1, 4, 6) or (b % 2 and k == 3):
                f = notes[(k + b) % 4] * 2
                x2 = seg(0.5)
                pl = np.sin(2 * np.pi * f * x2) * env_ad(x2, 0.003, 0.16) * 0.035
                s2 = int((b * bar + k * step) * SR)
                e2 = min(N, s2 + len(pl))
                if s2 < N:
                    pan = 0.3 if k % 2 else -0.3
                    L[s2:e2] += pl[: e2 - s2] * (1 - pan); R[s2:e2] += pl[: e2 - s2] * (1 + pan)
    # soft pulse on each beat
    beat = 60 / 84
    for k in range(int(dur / beat) + 1):
        x = seg(0.25)
        kick = np.sin(2 * np.pi * (55 + 40 * np.exp(-x / 0.03)) * x) * env_ad(x, 0.002, 0.08) * 0.07
        s = int(k * beat * SR); e = min(N, s + len(kick))
        if s < N:
            L[s:e] += kick[: e - s]; R[s:e] += kick[: e - s]
    fade = np.minimum(1, t / 1.5) * np.minimum(1, (dur - t) / 2.0)
    return L * fade, R * fade


# ---------------------------------------------------------------- mix
def mix(ch):
    cues = json.loads((OUT / "cues" / f"{ch}.json").read_text())
    voice = read_wav(OUT / "voice" / f"{ch}.wav")
    dur = len(voice) / SR
    N = len(voice)
    mL, mR = music(dur)
    # Duck the music under the voice (smoothed envelope, -9 dB when speaking).
    env = np.abs(voice)
    env = lp(env, 6, 1)
    env = env / (env.max() + 1e-9)
    duck = 1 - 0.65 * np.clip(env * 4, 0, 1)
    duck = lp(duck, 3, 1)
    mL *= duck; mR *= duck
    sL = np.zeros(N); sR = np.zeros(N)
    for t, name, gain in cues:
        s = SFX[name]()
        i = int(t * SR)
        if i >= N:
            continue
        e = min(N, i + len(s))
        pan = {"key": 0.15, "click": 0.1}.get(name, 0.0)
        sL[i:e] += s[: e - i] * gain * 0.8 * (1 - pan)
        sR[i:e] += s[: e - i] * gain * 0.8 * (1 + pan)
    L = voice * 1.0 + mL * 0.9 + sL
    R = voice * 1.0 + mR * 0.9 + sR
    st = np.stack([L, R], axis=1)
    st /= max(1.0, np.abs(st).max() / 0.95)
    (OUT / "audio").mkdir(parents=True, exist_ok=True)
    raw = OUT / "audio" / f"{ch}.raw.wav"
    with wave.open(str(raw), "wb") as w:
        w.setnchannels(2); w.setsampwidth(2); w.setframerate(SR)
        w.writeframes((st * 32767).astype(np.int16).tobytes())
    out = OUT / "audio" / f"{ch}.wav"
    subprocess.run(["ffmpeg", "-loglevel", "error", "-y", "-i", str(raw),
                    "-af", "loudnorm=I=-16:TP=-1.5:LRA=9,alimiter=limit=0.89", "-ar", str(SR), str(out)], check=True)
    raw.unlink()
    print(f"{out}  {dur:.1f} s, {len(cues)} sound cues")


if __name__ == "__main__":
    mix(sys.argv[1])
