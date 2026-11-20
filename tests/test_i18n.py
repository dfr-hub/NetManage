"""Every _() literal in the UI and report code must have an English translation
with the same {placeholders}."""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from netmanage.i18n import EN  # noqa: E402

FILES = ("netmanage/gui.py", "netmanage/gui_tools.py", "netmanage/converter.py")


def main() -> int:
    missing, bad = [], []
    for f in FILES:
        for node in ast.walk(ast.parse((ROOT / f).read_text(encoding="utf-8"))):
            if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "_" and node.args \
                    and isinstance(node.args[0], ast.Constant):
                text = node.args[0].value
                if text not in EN:
                    missing.append(f"{f}: {text!r}")
                elif set(re.findall(r"\{(\w+)\}", text)) != set(re.findall(r"\{(\w+)\}", EN[text])):
                    bad.append(f"{f}: placeholder beda: {text!r}")
    for m in missing + bad:
        print("FAIL", m)
    print(f"{len(missing)} terjemahan hilang, {len(bad)} placeholder salah")
    return 1 if missing or bad else 0


if __name__ == "__main__":
    sys.exit(main())
