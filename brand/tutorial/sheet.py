#!/usr/bin/env python3
"""Contact sheet of a chapter's stills: python3 sheet.py CH [cols]  ->  out/sheet-CH.png"""
import sys, glob
from PIL import Image, ImageDraw
ch = sys.argv[1]; cols = int(sys.argv[2]) if len(sys.argv) > 2 else 2
files = sorted(glob.glob(f"out/stills/{ch}/t*.png"))
w, h = 960, 540
rows = (len(files) + cols - 1) // cols
sheet = Image.new("RGB", (cols * w, rows * h), "black")
for i, f in enumerate(files):
    im = Image.open(f).convert("RGB").resize((w, h))
    ImageDraw.Draw(im).text((10, 8), f.split("/")[-1][1:-4], fill=(255, 255, 0))
    sheet.paste(im, ((i % cols) * w, (i // cols) * h))
sheet.save(f"out/sheet-{ch}.png"); print(f"out/sheet-{ch}.png", len(files))
