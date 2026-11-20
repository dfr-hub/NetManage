"""Entry point for NetManage (used by PyInstaller).

NetManage.exe --selftest  converts every bundled sample to every vendor and writes
output/selftest.txt, then exits. Used to check a fresh build.
"""
import sys


def selftest() -> int:
    from pathlib import Path

    from netmanage import parsers, topology
    from netmanage.converter import convert
    from netmanage.model import VENDORS
    from netmanage.paths import output_dir, resource_dir

    samples = resource_dir().parent / "samples"
    lines, failures = [], 0
    devices = []
    for path in sorted(samples.iterdir()):
        text = path.read_text(encoding="utf-8")
        devices.append(parsers.parse(text, source=path.name))
        for dst in VENDORS:
            try:
                res = convert(text, dst)
                back = parsers.parse(res.output, dst)
                src = devices[-1]
                acl_ok = not src.policy.acls or any(a.rules() for a in back.policy.acls.values())
                ok = (back.hostname == src.hostname and acl_ok
                      and len(back.policy.route_maps) >= len(src.policy.route_maps))
            except Exception as exc:  # noqa: BLE001
                ok = False
                lines.append(f"ERROR {path.name} -> {dst}: {exc}")
            failures += not ok
            lines.append(f"{'OK  ' if ok else 'FAIL'} {path.name} -> {dst}")
    topo = topology.build(devices)
    lines.append(f"topology: {len(topo.nodes)} node, {len(topo.links)} link")
    try:
        import pybatfish  # noqa: F401
        lines.append("pybatfish: ok")
    except ImportError as exc:
        lines.append(f"pybatfish: {exc}")
        failures += 1
    from netmanage import bulkping, speedtest
    pr = bulkping.ping_host("127.0.0.1", count=2, timeout_ms=1000)
    lines.append(f"ping 127.0.0.1: {pr.status} {pr.received}/{pr.sent} {pr.error}")
    failures += pr.status != "UP"
    srv = speedtest.LanServer(host="127.0.0.1", port=5295)
    srv.start()
    sr = speedtest.lan_test("127.0.0.1", 5295, duration=2, streams=2)
    srv.stop()
    lines.append(f"speedtest LAN loopback: down {sr.download_mbps} up {sr.upload_mbps} {sr.error}")
    failures += bool(sr.error) or not sr.download_mbps
    try:  # GUI: theme files, logo and both languages are bundled
        from netmanage import gui, settings, theme
        settings.load = lambda: {"theme": "light", "lang": "id"}
        settings.save = lambda data: None
        root = gui.create_root()
        root.withdraw()
        app = gui.App(root)
        app.toggle_theme()
        app.set_language("en")
        ok_gui = theme.mode() == "dark" and app.theme_btn.cget("text").endswith("Light mode")
        root.destroy()
        lines.append(f"gui: {'ok' if ok_gui else 'FAIL'}")
        failures += not ok_gui
    except Exception as exc:  # noqa: BLE001
        lines.append(f"gui: ERROR {exc}")
        failures += 1
    lines.append(f"failures: {failures}")
    Path(output_dir() / "selftest.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 1 if failures else 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except (AttributeError, OSError):
            pass
    from netmanage.gui import main

    main()
