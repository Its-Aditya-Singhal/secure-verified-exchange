#!/usr/bin/env python3
"""Make the images for SVX's HTML emails (brand/email/). Run once after a
brand change: python3 brand/build-email-images.py

banner.png  1200x400: the app icon, "SVX" and "Secure Verified Exchange" on
            the dark surface, with a thin signal-bright line (brand/README.md).
icon.png    96x96 app icon for the small headings.
Needs Pillow and a macOS system font."""
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "brand" / "email"
ICON = ROOT / "apps" / "desktop" / "src-tauri" / "icons" / "icon.png"
DARK, BONE, SIGNAL, MUTED = "#16171B", "#F3F1EC", "#FF6A3D", "#A3A6AD"


def font(size, bold=False):
    for path, index in (
        ("/System/Library/Fonts/HelveticaNeue.ttc", 1 if bold else 0),
        ("/System/Library/Fonts/Helvetica.ttc", 1 if bold else 0),
    ):
        try:
            return ImageFont.truetype(path, size, index=index)
        except OSError:
            continue
    return ImageFont.load_default()


def banner():
    w, h = 1200, 400
    im = Image.new("RGB", (w, h), DARK)
    d = ImageDraw.Draw(im)
    # A faint grid, as on the website.
    for x in range(0, w, 60):
        d.line([(x, 0), (x, h)], fill="#1C1E23")
    for y in range(0, h, 60):
        d.line([(0, y), (w, y)], fill="#1C1E23")
    icon = Image.open(ICON).convert("RGBA").resize((176, 176), Image.LANCZOS)
    im.paste(icon, (110, (h - 176) // 2), icon)
    d.text((330, 108), "SVX", font=font(120, bold=True), fill=BONE)
    d.text((334, 252), "Secure Verified Exchange", font=font(40), fill=MUTED)
    d.rectangle([(0, h - 8), (w, h)], fill=SIGNAL)
    im.save(OUT / "banner.png", optimize=True)


def small_icon():
    icon = Image.open(ICON).convert("RGBA").resize((96, 96), Image.LANCZOS)
    icon.save(OUT / "icon.png", optimize=True)


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    banner()
    small_icon()
    for f in sorted(OUT.glob("*.png")):
        print(f"{f.relative_to(ROOT)}  {f.stat().st_size // 1024} KB")
