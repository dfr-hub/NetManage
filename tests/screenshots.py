"""Render every tab in light/dark and ID/EN to PNG files (visual check, needs Pillow).

Usage: python tests/screenshots.py <output folder>
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from PIL import ImageGrab  # noqa: E402

from netmanage import gui, settings, speedtest  # noqa: E402


def shot(root, path: Path) -> None:
    root.update()
    root.after(500)
    root.update()
    x, y = root.winfo_rootx(), root.winfo_rooty()
    ImageGrab.grab((x, y, x + root.winfo_width(), y + root.winfo_height())).save(path)


def main(out: str) -> None:
    folder = Path(out)
    folder.mkdir(parents=True, exist_ok=True)
    for theme_name, lang in (("light", "id"), ("dark", "en"), ("dark", "id")):
        settings.load = lambda t=theme_name, lg=lang: {"theme": t, "lang": lg}
        settings.save = lambda data: None
        root = gui.create_root()
        root.geometry("1400x860+20+20")
        root.attributes("-topmost", True)
        app = gui.App(root)
        app.conv.load(str(ROOT / "samples" / "R1-cisco.cfg"))
        app.conv._modified()
        app.conv.run()
        app.topo.add_paths([str(p) for p in sorted((ROOT / "samples").glob("R*"))])
        app.speed.small["ping"].configure(text="12.4")
        app.speed.small["jitter"].configure(text="1.8")
        app.speed.down_gauge.set(245.3)
        app.speed.up_gauge.set(87.6)
        app.speed._add_history(speedtest.SpeedResult("Internet (Cloudflare)", "speed.cloudflare.com", 12.4, 1.8,
                                                     245.3, 87.6))
        for i, key in enumerate(("conv", "coll", "topo", "ping", "speed")):
            app.nb.select(i)
            for _ in range(20):
                root.update()
                root.after(30)
            shot(root, folder / f"{theme_name}_{lang}_{i + 1}_{key}.png")
        root.destroy()
    print("ok", folder)


if __name__ == "__main__":
    main(sys.argv[1])
