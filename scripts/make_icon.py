#!/usr/bin/env python3
"""Generate the BIOS Recovery Suite application icon.

Produces assets/icon.ico (multi-size Windows icon) and assets/icon.png.
Design: dark indigo->violet gradient squircle, white CPU chip with pins,
and a cyan "repair pulse" (ECG line) inside the die.
"""

import os

from PIL import Image, ImageDraw

SIZE = 1024  # master, downsampled for each ico entry


def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def gradient_bg(w, h, top, bottom):
    img = Image.new("RGB", (w, h))
    px = img.load()
    for y in range(h):
        row = lerp(top, bottom, y / max(1, h - 1))
        for x in range(w):
            px[x, y] = row
    return img


def rounded_mask(size, radius):
    m = Image.new("L", (size, size), 0)
    d = ImageDraw.Draw(m)
    d.rounded_rectangle([0, 0, size - 1, size - 1], radius=radius, fill=255)
    return m


def build_master() -> Image.Image:
    s = SIZE
    top = (79, 70, 229)      # indigo 600
    bottom = (124, 58, 237)  # violet 600
    base = gradient_bg(s, s, top, bottom)

    icon = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    # squircle background with 22% corner radius
    mask = rounded_mask(s, int(s * 0.225))
    icon.paste(base, (0, 0), mask)

    d = ImageDraw.Draw(icon)

    # subtle top sheen (very low alpha white ellipse, clipped by mask)
    sheen = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    sd = ImageDraw.Draw(sheen)
    sd.ellipse([s * 0.05, -s * 0.45, s * 0.95, s * 0.35], fill=(255, 255, 255, 26))
    icon = Image.composite(Image.alpha_composite(icon, sheen), icon, mask)
    d = ImageDraw.Draw(icon)

    white = (255, 255, 255, 255)
    soft = (224, 231, 255, 235)   # indigo-50
    cyan = (34, 211, 238, 255)    # cyan-400

    # ---- CPU chip ----
    chip_w = int(s * 0.46)
    cx = cy = s // 2
    chip_l, chip_t = cx - chip_w // 2, cy - chip_w // 2
    chip_r, chip_b = cx + chip_w // 2, cy + chip_w // 2

    # pins (4 per side), drawn under the body
    pin_len = int(s * 0.055)
    pin_w = int(s * 0.026)
    gap = chip_w // 5
    for i in range(4):
        off = chip_l + gap // 2 + i * gap + gap // 2 - pin_w // 2
        # top / bottom
        d.rounded_rectangle([off, chip_t - pin_len, off + pin_w, chip_t], radius=pin_w // 2, fill=soft)
        d.rounded_rectangle([off, chip_b, off + pin_w, chip_b + pin_len], radius=pin_w // 2, fill=soft)
        # left / right
        d.rounded_rectangle([chip_l - pin_len, off, chip_l, off + pin_w], radius=pin_w // 2, fill=soft)
        d.rounded_rectangle([chip_r, off, chip_r + pin_len, off + pin_w], radius=pin_w // 2, fill=soft)

    # body + inner die
    d.rounded_rectangle([chip_l, chip_t, chip_r, chip_b], radius=int(s * 0.035), fill=white)
    inset = int(s * 0.055)
    d.rounded_rectangle([chip_l + inset, chip_t + inset, chip_r - inset, chip_b - inset],
                        radius=int(s * 0.02), fill=(30, 41, 59, 255))  # slate-800

    # ---- repair pulse (ECG line) inside the die ----
    lw = int(s * 0.028)
    inner_l, inner_t = chip_l + inset, chip_t + inset
    inner_r, inner_b = chip_r - inset, chip_b - inset
    iw, ih = inner_r - inner_l, inner_b - inner_t
    mid_y = inner_t + ih // 2

    pts = [
        (inner_l + iw * 0.08, mid_y + ih * 0.10),
        (inner_l + iw * 0.26, mid_y + ih * 0.10),
        (inner_l + iw * 0.34, mid_y - ih * 0.22),
        (inner_l + iw * 0.44, mid_y + ih * 0.30),
        (inner_l + iw * 0.52, mid_y - ih * 0.02),
        (inner_l + iw * 0.62, mid_y + ih * 0.10),
        (inner_l + iw * 0.92, mid_y + ih * 0.10),
    ]
    d.line([(x, y) for x, y in pts], fill=cyan, width=lw, joint="curve")
    # round caps
    r = lw // 2
    for x, y in (pts[0], pts[-1]):
        d.ellipse([x - r, y - r, x + r, y + r], fill=cyan)

    return icon


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    assets = os.path.join(root, "assets")
    os.makedirs(assets, exist_ok=True)

    master = build_master()

    png_path = os.path.join(assets, "icon.png")
    master.resize((256, 256), Image.LANCZOS).save(png_path)

    ico_sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    ico_path = os.path.join(assets, "icon.ico")
    master.save(ico_path, format="ICO", sizes=ico_sizes)

    print("wrote", png_path, "and", ico_path)


if __name__ == "__main__":
    main()
