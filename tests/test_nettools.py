"""Bulk ping and speed test checks (loopback only, plus GUI tabs without mainloop)."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from netmanage import bulkping, speedtest  # noqa: E402

FAKE_ID = """Ping ke 10.9.9.9 dengan 32 byte data:
Balasan dari 10.9.9.9: byte=32 waktu=12ms TTL=60
Balasan dari 10.9.9.9: byte=32 waktu<1ms TTL=60
Waktu permintaan habis.

Statistik ping untuk 10.9.9.9:
"""


def fake_runner(cmd, **_):
    return subprocess.CompletedProcess(cmd, 0, stdout=FAKE_ID, stderr="")


def main() -> int:
    fails = 0

    def check(name, cond):
        nonlocal fails
        print(("OK   " if cond else "FAIL ") + name)
        fails += not cond

    t = bulkping.parse_targets("10.0.0.0/30\n10.1.1.1-3, 10.2.2.2\nR1,10.255.0.1\n# komentar\nhost.lab\n10.0.0.1")
    check("parse_targets", [a for a, _ in t] == ["10.0.0.1", "10.0.0.2", "10.1.1.1", "10.1.1.2", "10.1.1.3",
                                                  "10.2.2.2", "10.255.0.1", "host.lab"] and t[6][1] == "R1")
    try:
        bulkping.parse_targets("10.0.0.0/8")
        check("subnet terlalu besar ditolak", False)
    except ValueError:
        check("subnet terlalu besar ditolak", True)

    r = bulkping.ping_host("10.9.9.9", count=3, runner=fake_runner)
    check("parse output Windows bahasa Indonesia", r.received == 2 and r.status == "PARTIAL" and r.ttl == 60
          and r.rtts == [12.0, 0.5])
    real = bulkping.run([("127.0.0.1", ""), ("192.0.2.123", "")], count=1, timeout_ms=500)
    status = {x.target: x.status for x in real}
    check("ping nyata loopback UP / TEST-NET DOWN", status == {"127.0.0.1": "UP", "192.0.2.123": "DOWN"})
    check("export CSV", bulkping.to_csv(real).count("\n") == 3)

    srv = speedtest.LanServer(host="127.0.0.1", port=5298)
    srv.start()
    res = speedtest.lan_test("127.0.0.1", 5298, duration=3, streams=2)
    srv.stop()
    check(f"speed test LAN loopback (down {res.download_mbps:.0f} / up {res.upload_mbps:.0f} Mbps)",
          not res.error and res.download_mbps > 50 and res.upload_mbps > 50 and res.ping_ms is not None)
    bad = speedtest.lan_test("127.0.0.1", 5297, duration=2)
    check("server mati -> pesan error", bool(bad.error))

    # internet_test against a local HTTP server: download, form upload, redirect
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    seen = {"form": False}

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path.startswith("/redir"):
                self.send_response(307)
                self.send_header("Location", "/file")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = b"x" * (2_000_000 if self.path.startswith("/file") else 10)
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            data = self.rfile.read(int(self.headers["Content-Length"]))
            seen["form"] |= data.startswith(b"content1=")
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    ok = speedtest.internet_test(speedtest.Endpoint("ookla", "lokal", f"{base}/file", f"{base}/up", f"{base}/ping",
                                                    form=True), duration=2, streams=2)
    check("internet_test download+upload form", not ok.error and ok.download_mbps > 1 and ok.upload_mbps > 1
          and seen["form"])
    red = speedtest.internet_test(speedtest.custom_endpoint(f"{base}/redir"), duration=2, streams=1)
    check("redirect -> error, bukan hasil palsu", "307" in red.error and "/file" in red.error)
    httpd.shutdown()

    import tkinter as tk
    from netmanage import gui, gui_tools
    root = gui.TkinterDnD.Tk() if gui.HAS_DND else tk.Tk()
    root.withdraw()
    msgs = []
    nb = gui.ttk.Notebook(root)
    ping = gui_tools.PingTab(nb, msgs.append, lambda: [("127.0.0.1", "LOCAL")])
    speed = gui_tools.SpeedTab(nb, msgs.append)
    ping.targets.delete("1.0", "end")
    ping.from_inventory()
    ping.count.set(1)
    ping.start()
    for _ in range(100):
        root.update()
        if not ping.running:
            break
        root.after(50)
    check("tab Bulk Ping jalan", "127.0.0.1" in ping.results and ping.results["127.0.0.1"].status == "UP")
    # internet providers: lists and custom endpoint wiring (no network needed)
    speed.mode.set("Internet")
    speed._mode_changed(autoload=False)
    speed.provider.set("Mirror file (download saja)")
    speed._provider_changed(autoload=False)
    check("daftar mirror tampil", len(speed.server_box["values"]) == len(speedtest.MIRRORS))
    speed.server_box.current(2)
    check("endpoint mirror terpilih", speed._endpoint().down == speedtest.MIRRORS[2].down)
    speed.provider.set("Kustom (URL sendiri)")
    speed._provider_changed(autoload=False)
    speed.url.set("files.lab.local/100MB.bin")
    speed.up_url.set("http://files.lab.local/empty.php")
    ep = speed._endpoint()
    check("endpoint kustom", ep.down == "http://files.lab.local/100MB.bin" and ep.up.endswith("empty.php"))
    speed.mode.set("LAN ke NetManage lain")
    speed._mode_changed()
    speed.srv_port.set(5296)
    speed.toggle_server()
    speed.lan_host.set("127.0.0.1")
    speed.lan_port.set(5296)
    speed.duration.set(3)
    speed.start()
    for _ in range(400):
        root.update()
        if not speed.running:
            break
        root.after(50)
    speed.shutdown()
    check("tab Speed Test jalan", bool(speed.history) and speed.history[0].download_mbps)
    root.destroy()
    print("OK" if not fails else f"{fails} gagal")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
