"""Build the logo PNGs and the Windows .ico from the source logo image.

Usage: python tools/make_assets.py <logo image>
Writes netmanage/assets/logo_{32,48,64,128,256}.png and netmanage/assets/icon.ico.
Pillow is needed only here (build time), not at runtime.
"""
from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image, ImageDraw

OUT = Path(__file__).resolve().parent.parent / "netmanage" / "assets"


def rounded(img: Image.Image, radius_ratio: float = 0.22) -> Image.Image:
    size = img.size[0]
    mask = Image.new("L", (size * 4, size * 4), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, size * 4 - 1, size * 4 - 1),
                                           radius=int(size * 4 * radius_ratio), fill=255)
    out = img.convert("RGBA")
    out.putalpha(mask.resize((size, size), Image.LANCZOS))
    return out


def main(src: str) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    img = Image.open(src).convert("RGB")
    w, h = img.size
    # badge occupies roughly the middle 72% of the square source image
    side = int(min(w, h) * 0.74)
    cx, cy = int(w * 0.515), int(h * 0.52)
    crop = img.crop((cx - side // 2, cy - side // 2, cx + side // 2, cy + side // 2))
    master = rounded(crop.resize((512, 512), Image.LANCZOS))
    for size in (32, 48, 64, 128, 256):
        master.resize((size, size), Image.LANCZOS).save(OUT / f"logo_{size}.png")
    master.save(OUT / "icon.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    buttons()
    print("aset dibuat di", OUT)


# rounded button skins (9-slice images used by the ttk theme)
BUTTONS = {
    "light": {"normal": "#2563EB", "hover": "#1D4ED8", "pressed": "#1E40AF", "disabled": "#BFD3F6"},
    "dark": {"normal": "#3B82F6", "hover": "#60A5FA", "pressed": "#2563EB", "disabled": "#28406B"},
}
GHOST = {
    "light": {"normal": "#E2E8F0", "hover": "#CBD5E1", "pressed": "#94A3B8", "disabled": "#F1F5F9"},
    "dark": {"normal": "#2D2D2D", "hover": "#3A3A3A", "pressed": "#4A4A4A", "disabled": "#232323"},
    "header": {"normal": "#16294A", "hover": "#1F3A66", "pressed": "#284A80", "disabled": "#12213B"},
}


def _pill(color: str, w: int = 40, h: int = 34, r: int = 12, scale: int = 4) -> Image.Image:
    img = Image.new("RGBA", (w * scale, h * scale), (0, 0, 0, 0))
    ImageDraw.Draw(img).rounded_rectangle((0, 0, w * scale - 1, h * scale - 1), radius=r * scale, fill=color)
    return img.resize((w, h), Image.LANCZOS)


def buttons() -> None:
    for kind, table in (("btn", BUTTONS), ("ghost", GHOST)):
        for theme, states in table.items():
            for state, color in states.items():
                _pill(color).save(OUT / f"{kind}_{theme}_{state}.png")


if __name__ == "__main__":
    main(sys.argv[1])
