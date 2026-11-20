"""Build the GUI without mainloop and drive each tab once."""
from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import tkinter as tk  # noqa: E402

from netmanage import gui  # noqa: E402
from netmanage.model import VENDORS  # noqa: E402


def main() -> int:
    root = gui.TkinterDnD.Tk() if gui.HAS_DND else tk.Tk()
    root.withdraw()
    msgs = []
    nb = gui.ttk.Notebook(root)
    conv = gui.ConvertTab(nb, msgs.append)
    topo = gui.TopologyTab(nb, msgs.append)
    coll = gui.CollectorTab(nb, msgs.append, topo.add_paths)

    conv.load(str(ROOT / "samples" / "R4-huawei.cfg"))
    conv._modified()
    conv.dst.set(VENDORS["vyos"])
    with mock.patch.object(gui.messagebox, "showerror", side_effect=AssertionError):
        conv.run()
    out = conv.out.get("1.0", "end")
    assert "set system host-name 'R4-HUAWEI'" in out, out[:300]
    conv.reverse()
    conv.run()
    assert "sysname R4-HUAWEI" in conv.out.get("1.0", "end")
    print("convert tab ok:", msgs[-1])

    topo.add_paths([str(p) for p in sorted((ROOT / "samples").iterdir())])
    assert topo.topo and len(topo.topo.links) >= 11
    print("topology tab ok:", msgs[-1])

    coll.cmd_vendor.set(VENDORS["nokia_sros"])
    coll._show_commands()
    assert "admin display-config" in coll.cmd_box.get("1.0", "end")
    print("collector tab ok")
    root.destroy()

    # full app: theme toggle and language switch keep the user's input
    from netmanage import collector, i18n, settings
    settings.load = lambda: {"theme": "light", "lang": "id"}
    settings.save = lambda data: None
    root = gui.create_root()
    root.withdraw()
    app = gui.App(root)
    app.conv.load(str(ROOT / "samples" / "R2-juniper.cfg"))
    app.coll.targets.append(collector.Target(host="SW1", ip="10.0.0.9", vendor="arista_eos"))
    app.coll._refresh()
    app.toggle_theme()
    assert gui.theme.mode() == "dark"
    app.set_language("en")
    assert i18n.lang() == "en"
    assert "R2-JUNIPER" in app.conv.inp.get("1.0", "end"), "input hilang setelah ganti bahasa"
    assert [t.ip for t in app.coll.targets] == ["10.0.0.9"], "inventory hilang setelah ganti bahasa"
    assert app.theme_btn.cget("text").endswith("Light mode")
    assert app.conv.src.get() in ("Auto-detect", VENDORS["juniper_junos"])
    app.set_language("id")
    app.toggle_theme()
    print("app: tema + ganti bahasa ok")
    root.destroy()
    return 0


if __name__ == "__main__":
    sys.exit(main())
