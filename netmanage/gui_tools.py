"""GUI tabs for Bulk Ping and Speed Test, plus the circular gauge widget."""
from __future__ import annotations

import math
import queue
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from . import APP_NAME, bulkping, speedtest, theme
from .i18n import _
from .paths import output_dir

try:
    from tkinterdnd2 import DND_FILES
    HAS_DND = True
except Exception:  # noqa: BLE001
    HAS_DND = False

MONO = ("Consolas", 10)
_SCALES = (10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 25000, 50000, 100000)


def _spin(parent, var, lo, hi, width=6):
    return ttk.Spinbox(parent, from_=lo, to=hi, textvariable=var, width=width)


def _int(var: tk.Variable, default: int, lo: int, hi: int) -> int:
    try:
        return max(lo, min(hi, int(var.get())))
    except (ValueError, tk.TclError):
        return default


# =================================================================== Gauge
class Gauge(tk.Canvas):
    """Circular progress gauge (270 degree arc) with an animated value and auto scale."""

    START, SWEEP = 225, -270

    def __init__(self, master, title: str, unit: str, color_key: str = "accent", size: int = 200):
        super().__init__(master, width=size, height=size, highlightthickness=0, borderwidth=0)
        self.size, self.title, self.unit, self.color_key = size, title, unit, color_key
        self.value = 0.0
        self.shown = 0.0
        self.maximum = _SCALES[2]
        self.active = False
        self._job = None
        theme.on_change(self.redraw)
        self.redraw()

    def destroy(self) -> None:
        if self._job is not None:
            self.after_cancel(self._job)
            self._job = None
        super().destroy()

    def set(self, value: float | None, active: bool = True) -> None:
        self.value = max(0.0, value or 0.0)
        self.active = active
        while self.value > self.maximum and self.maximum < _SCALES[-1]:
            self.maximum = next(s for s in _SCALES if s > self.maximum)
        if self._job is None:
            self._animate()

    def reset(self) -> None:
        self.value = self.shown = 0.0
        self.maximum = _SCALES[2]
        self.active = False
        self.redraw()

    def _animate(self) -> None:
        diff = self.value - self.shown
        self.shown += diff * 0.25
        if abs(diff) < max(0.05, self.value * 0.002):
            self.shown = self.value
            self._job = None
        else:
            self._job = self.after(30, self._animate)
        self.redraw()

    def redraw(self) -> None:
        self.delete("all")
        p = theme.PALETTE[theme.mode()]
        self.configure(background=p["card"])
        s, pad, w = self.size, 16, 14
        box = (pad, pad, s - pad, s - pad)
        self.create_arc(*box, start=self.START, extent=self.SWEEP, style="arc", width=w, outline=p["track"])
        frac = min(1.0, self.shown / self.maximum) if self.maximum else 0
        color = p[self.color_key]
        if frac > 0.002:
            self.create_arc(*box, start=self.START, extent=self.SWEEP * frac, style="arc", width=w, outline=color)
            # rounded cap at the end of the value arc
            ang = math.radians(self.START + self.SWEEP * frac)
            r = (s - 2 * pad) / 2
            cx, cy = s / 2 + r * math.cos(ang), s / 2 - r * math.sin(ang)
            self.create_oval(cx - w / 2, cy - w / 2, cx + w / 2, cy + w / 2, fill=color, outline="")
        for frac_tick, label in ((0, "0"), (1, self._fmt_scale(self.maximum))):
            ang = math.radians(self.START + self.SWEEP * frac_tick)
            r = (s - 2 * pad) / 2 + 2
            self.create_text(s / 2 + r * math.cos(ang) * 0.82, s / 2 - r * math.sin(ang) * 0.82 + 16,
                             text=label, fill=p["muted"], font=("Segoe UI", 8))
        self.create_text(s / 2, s / 2 - 30, text=self.title, fill=p["muted"], font=("Segoe UI Semibold", 9))
        value = "-" if not self.shown and not self.active else self._fmt(self.shown)
        self.create_text(s / 2, s / 2 + 2, text=value, fill=p["text"], font=("Segoe UI Semibold", 26))
        self.create_text(s / 2, s / 2 + 32, text=self.unit, fill=p["muted"], font=("Segoe UI", 9))

    @staticmethod
    def _fmt(v: float) -> str:
        return f"{v:.0f}" if v >= 100 else f"{v:.1f}"

    @staticmethod
    def _fmt_scale(v: float) -> str:
        return f"{v / 1000:g}G" if v >= 1000 else f"{v:g}"


# =================================================================== Bulk Ping
class PingTab(ttk.Frame):
    def __init__(self, master, status, get_inventory):
        super().__init__(master, padding=10)
        self.status = status
        self.get_inventory = get_inventory
        self.events: queue.Queue = queue.Queue()
        self.stop_event = threading.Event()
        self.running = False
        self.results: dict[str, bulkping.PingResult] = {}
        self.round = 0
        self.sort_key = ("", False)
        self.filters = {_("Semua"): "", "UP": "UP", "DOWN": "DOWN", "PARTIAL": "PARTIAL", "ERROR": "ERROR"}
        self.cols = (("target", _("Target"), 130), ("label", _("Nama"), 140), ("status", "Status", 70),
                     ("sent", _("Kirim"), 50), ("recv", _("Terima"), 55), ("loss", "Loss %", 60),
                     ("min", "Min ms", 60), ("avg", "Avg ms", 60), ("max", "Max ms", 60), ("ttl", "TTL", 45),
                     ("info", _("Keterangan"), 260))

        panes = ttk.PanedWindow(self, orient="horizontal")
        panes.pack(fill="both", expand=True)
        left = ttk.Frame(panes)
        right = ttk.Frame(panes)
        panes.add(left, weight=1)
        panes.add(right, weight=4)

        tf = ttk.LabelFrame(left, text=f" {_('Target')} ", padding=6)
        tf.pack(fill="both", expand=True)
        bar = ttk.Frame(tf)
        bar.pack(fill="x", pady=(0, 6))
        ttk.Button(bar, text=_("Buka file..."), command=self.open_file).pack(side="left")
        ttk.Button(bar, text=_("Dari inventory"), command=self.from_inventory).pack(side="left", padx=6)
        ttk.Button(bar, text=_("Bersihkan"), style="Ghost.TButton",
                   command=lambda: self.targets.delete("1.0", "end")).pack(side="left")
        frame = ttk.Frame(tf)
        frame.pack(fill="both", expand=True)
        self.targets = tk.Text(frame, width=30, height=16, font=MONO)
        theme.register(self.targets, "text")
        ys = ttk.Scrollbar(frame, orient="vertical", command=self.targets.yview)
        self.targets.configure(yscrollcommand=ys.set)
        self.targets.pack(side="left", fill="both", expand=True)
        ys.pack(side="right", fill="y")
        self.targets.insert("1.0", _("# satu target per baris, contoh:") + "\n# 8.8.8.8\n# router1.lab.local\n"
                                   "# 192.168.1.0/28\n# 10.0.0.1-20\n# CORE-SW,10.0.0.2\n")
        if HAS_DND:
            self.targets.drop_target_register(DND_FILES)
            self.targets.dnd_bind("<<Drop>>", self._drop)

        of = ttk.LabelFrame(left, text=f" {_('Opsi')} ", padding=8)
        of.pack(fill="x", pady=(8, 0))
        self.count = tk.IntVar(value=4)
        self.timeout = tk.IntVar(value=1000)
        self.size = tk.IntVar(value=32)
        self.workers = tk.IntVar(value=50)
        self.repeat = tk.BooleanVar(value=False)
        self.interval = tk.IntVar(value=10)
        self.resolve = tk.BooleanVar(value=False)
        rows = ((_("Jumlah ping"), self.count, 1, 100), (_("Timeout (ms)"), self.timeout, 100, 10000),
                (_("Ukuran (byte)"), self.size, 1, 65500), (_("Paralel"), self.workers, 1, 256))
        for r, (label, var, lo, hi) in enumerate(rows):
            ttk.Label(of, text=label).grid(row=r, column=0, sticky="w", pady=2)
            _spin(of, var, lo, hi, 8).grid(row=r, column=1, sticky="w", padx=6)
        ttk.Checkbutton(of, text=_("Ulangi tiap (detik)"), variable=self.repeat).grid(row=4, column=0, sticky="w")
        _spin(of, self.interval, 2, 3600, 8).grid(row=4, column=1, sticky="w", padx=6)
        ttk.Checkbutton(of, text=_("Cari nama (reverse DNS)"), variable=self.resolve).grid(
            row=5, column=0, columnspan=2, sticky="w")

        run = ttk.Frame(right)
        run.pack(fill="x", pady=(0, 8))
        self.start_btn = ttk.Button(run, text=_("Mulai ping"), command=self.start)
        self.start_btn.pack(side="left")
        self.stop_btn = ttk.Button(run, text=_("Stop"), command=self.stop, state="disabled")
        self.stop_btn.pack(side="left", padx=6)
        ttk.Button(run, text=_("Export CSV..."), command=self.export).pack(side="left")
        ttk.Label(run, text=_("Tampilkan:")).pack(side="left", padx=(16, 6))
        self.filter = ttk.Combobox(run, state="readonly", width=10, values=list(self.filters))
        self.filter.set(_("Semua"))
        self.filter.pack(side="left")
        self.filter.bind("<<ComboboxSelected>>", lambda _e: self._refresh())
        self.progress = ttk.Progressbar(run, mode="determinate", length=180)
        self.progress.pack(side="right")

        cards = ttk.Frame(right)
        cards.pack(fill="x", pady=(0, 8))
        self.card_values = {}
        for key, title in (("UP", "UP"), ("DOWN", "DOWN"), ("PARTIAL", "PARTIAL"), ("total", _("Total"))):
            box = theme.card(cards, 16, 8)
            box.pack(side="left", fill="x", expand=True, padx=(0, 8))
            theme.card_label(box, title, "title").pack(anchor="w")
            val = theme.card_label(box, "0", "value")
            val.pack(anchor="w")
            self.card_values[key] = val
        self.summary = ttk.Label(right, text=_("Belum ada hasil."), style="Muted.TLabel")
        self.summary.pack(anchor="w", pady=(0, 6))

        tv = ttk.Frame(right)
        tv.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(tv, columns=[c[0] for c in self.cols], show="headings")
        for key, label, width in self.cols:
            self.tree.heading(key, text=label, command=lambda k=key: self._sort(k))
            self.tree.column(key, width=width, anchor="w" if key in ("target", "label", "info") else "center")
        ys2 = ttk.Scrollbar(tv, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=ys2.set)
        self.tree.pack(side="left", fill="both", expand=True)
        ys2.pack(side="right", fill="y")
        theme.on_change(self.apply_theme)
        self.apply_theme()

    def apply_theme(self):
        for tag, key in (("UP", "ok"), ("DOWN", "err"), ("PARTIAL", "warn"), ("ERROR", "purple")):
            self.tree.tag_configure(tag, foreground=theme.c(key))
            if tag in self.card_values:
                self.card_values[tag].configure(foreground=theme.c(key))

    def get_state(self) -> dict:
        return {"text": self.targets.get("1.0", "end-1c")}

    def set_state(self, st: dict) -> None:
        self.targets.delete("1.0", "end")
        self.targets.insert("1.0", st.get("text", ""))

    # ------------------------------------------------------------ targets
    def _drop(self, event):
        for p in self.tk.splitlist(event.data):
            if Path(p).is_file():
                self._load(p)
        return event.action

    def _load(self, path: str):
        text = Path(path).read_text(encoding="utf-8-sig", errors="replace")
        self.targets.insert("end", ("\n" if self.targets.get("1.0", "end").strip() else "") + text)

    def open_file(self):
        path = filedialog.askopenfilename(filetypes=[(_("Teks/CSV"), "*.txt *.csv"), (_("Semua file"), "*.*")])
        if path:
            self._load(path)

    def from_inventory(self):
        items = self.get_inventory()
        if not items:
            messagebox.showinfo(APP_NAME, _("Inventory di tab Log Collector masih kosong."))
            return
        self.targets.insert("end", "\n" + "\n".join(f"{label},{ip}" for ip, label in items) + "\n")

    # ---------------------------------------------------------------- run
    def start(self):
        if self.running:
            return
        try:
            targets = bulkping.parse_targets(self.targets.get("1.0", "end"))
        except ValueError as exc:
            messagebox.showerror(APP_NAME, str(exc))
            return
        if not targets:
            messagebox.showinfo(APP_NAME, _("Isi minimal satu target."))
            return
        self.results = {}
        self.round = 0
        self.tree.delete(*self.tree.get_children())
        self.stop_event.clear()
        self.running = True
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        opts = dict(count=_int(self.count, 4, 1, 100), timeout_ms=_int(self.timeout, 1000, 100, 10000),
                    size=_int(self.size, 32, 1, 65500), workers=_int(self.workers, 50, 1, 256),
                    resolve=self.resolve.get())
        repeat, interval = self.repeat.get(), _int(self.interval, 10, 2, 3600)

        def work():
            while True:
                self.events.put(("round", len(targets)))
                bulkping.run(targets, on_result=lambda r: self.events.put(("result", r)),
                             stop=self.stop_event, **opts)
                self.events.put(("round_done", None))
                if not repeat or self.stop_event.wait(interval):
                    break
            self.events.put(("finished", None))

        threading.Thread(target=work, daemon=True).start()
        self.status(_("Ping {count} target...").format(count=len(targets)))
        self.after(100, self._poll)

    def stop(self):
        self.stop_event.set()

    def _poll(self):
        try:
            while True:
                kind, data = self.events.get_nowait()
                if kind == "round":
                    self.round += 1
                    self.progress.configure(maximum=data, value=0)
                elif kind == "result":
                    self.results[data.target] = data
                    self.progress.step(1)
                    self._upsert(data)
                    self._cards()
                elif kind == "round_done":
                    self._summary()
                elif kind == "finished":
                    self.running = False
                    self.start_btn.configure(state="normal")
                    self.stop_btn.configure(state="disabled")
                    self._summary()
                    return
        except queue.Empty:
            pass
        self.after(150, self._poll)

    # --------------------------------------------------------------- view
    @staticmethod
    def _values(r: bulkping.PingResult):
        def ms(v):
            return "" if v is None else ("<1" if v < 1 else f"{v:.0f}")
        return (r.target, r.label, r.status, r.sent, r.received, f"{r.loss:.0f}", ms(r.stat("min")),
                ms(r.stat("avg")), ms(r.stat("max")), r.ttl if r.ttl is not None else "", r.error)

    def _visible(self, r) -> bool:
        f = self.filters.get(self.filter.get(), "")
        return not f or r.status == f

    def _upsert(self, r):
        if not self._visible(r):
            if self.tree.exists(r.target):
                self.tree.delete(r.target)
            return
        if self.tree.exists(r.target):
            self.tree.item(r.target, values=self._values(r), tags=(r.status,))
        else:
            self.tree.insert("", "end", iid=r.target, values=self._values(r), tags=(r.status,))

    def _refresh(self):
        self.tree.delete(*self.tree.get_children())
        for r in self._sorted():
            self._upsert(r)

    def _sorted(self):
        key, rev = self.sort_key
        items = list(self.results.values())
        if not key:
            return items
        idx = [c[0] for c in self.cols].index(key)

        def k(r):
            v = self._values(r)[idx]
            try:
                return (0, float(str(v).replace("<", "")))
            except ValueError:
                return (1, str(v))
        return sorted(items, key=k, reverse=rev)

    def _sort(self, key):
        self.sort_key = (key, not self.sort_key[1] if self.sort_key[0] == key else False)
        self._refresh()

    def _counts(self):
        res = list(self.results.values())
        return {s: sum(1 for r in res if r.status == s) for s in ("UP", "DOWN", "PARTIAL", "ERROR")}, len(res)

    def _cards(self):
        counts, total = self._counts()
        for key in ("UP", "DOWN", "PARTIAL"):
            self.card_values[key].configure(text=str(counts[key]))
        self.card_values["total"].configure(text=str(total))

    def _summary(self):
        counts, total = self._counts()
        self._cards()
        text = _("Putaran {round}  |  UP {up}  |  DOWN {down}  |  PARTIAL {partial}  |  ERROR {error}  |  "
                 "total {total}  |  {time}").format(round=self.round, up=counts["UP"], down=counts["DOWN"],
                                                   partial=counts["PARTIAL"], error=counts["ERROR"],
                                                   total=total, time=time.strftime("%H:%M:%S"))
        self.summary.configure(text=text)
        self.status(text)

    def export(self):
        if not self.results:
            return
        path = filedialog.asksaveasfilename(initialdir=str(output_dir()), defaultextension=".csv",
                                            initialfile=f"bulkping_{time.strftime('%Y%m%d-%H%M%S')}.csv")
        if path:
            Path(path).write_text(bulkping.to_csv(self._sorted()), encoding="utf-8")
            self.status(_("Disimpan: {path}").format(path=path))


# ================================================================== Speed Test
class SpeedTab(ttk.Frame):
    def __init__(self, master, status):
        super().__init__(master, padding=10)
        self.status = status
        self.modes = {_("Internet"): "internet", _("LAN ke NetManage lain"): "lan"}
        self.providers = {_("Cloudflare (otomatis terdekat)"): "cloudflare",
                          _("Speedtest.net (Ookla)"): "ookla",
                          _("LibreSpeed"): "librespeed",
                          _("Mirror file (download saja)"): "mirror",
                          _("Kustom (URL sendiri)"): "custom"}
        self.servers: dict[str, list[speedtest.Endpoint]] = {
            "cloudflare": [speedtest.CLOUDFLARE_EP], "mirror": list(speedtest.MIRRORS),
            "ookla": [], "librespeed": []}
        self.events: queue.Queue = queue.Queue()
        self.srv_msgs: queue.Queue = queue.Queue()
        self.list_msgs: queue.Queue = queue.Queue()
        self.stop_event = threading.Event()
        self.running = False
        self.loading = False
        self.history: list[speedtest.SpeedResult] = []
        self.server: speedtest.LanServer | None = None

        top = ttk.Frame(self)
        top.pack(fill="x")
        cfg = ttk.LabelFrame(top, text=f" {_('Pengaturan tes')} ", padding=10)
        cfg.pack(side="left", fill="both", expand=True)
        cfg.columnconfigure(1, weight=1)
        self.mode = tk.StringVar(value=next(iter(self.modes)))
        radios = ttk.Frame(cfg)
        radios.grid(row=0, column=0, columnspan=3, sticky="w")
        for label in self.modes:
            ttk.Radiobutton(radios, text=label, value=label, variable=self.mode,
                            command=self._mode_changed).pack(side="left", padx=(0, 18))

        self.provider = tk.StringVar(value=next(iter(self.providers)))
        self.server_var = tk.StringVar()
        self.search = tk.StringVar()
        self.url = tk.StringVar(value="http://")
        self.up_url = tk.StringVar()
        self.lan_host = tk.StringVar()
        self.lan_port = tk.IntVar(value=speedtest.LAN_PORT)
        self.duration = tk.IntVar(value=10)
        self.streams = tk.IntVar(value=4)
        self.upload = tk.BooleanVar(value=True)

        self.rows: dict[str, list[tk.Widget]] = {}

        def row(key, r, label, widget):
            lab = ttk.Label(cfg, text=label)
            lab.grid(row=r, column=0, sticky="w", pady=3, padx=(0, 10))
            widget.grid(row=r, column=1, columnspan=2, sticky="we", pady=3)
            self.rows[key] = [lab, widget]

        self.provider_box = ttk.Combobox(cfg, textvariable=self.provider, state="readonly",
                                         values=list(self.providers), width=34)
        self.provider_box.bind("<<ComboboxSelected>>", lambda _e: self._provider_changed())
        row("provider", 1, _("Provider"), self.provider_box)
        sv = ttk.Frame(cfg)
        self.server_box = ttk.Combobox(sv, textvariable=self.server_var, state="readonly", width=58)
        self.server_box.pack(side="left", fill="x", expand=True)
        self.search_entry = ttk.Entry(sv, textvariable=self.search, width=16)
        self.search_entry.bind("<Return>", lambda _e: self.load_servers())
        self.load_btn = ttk.Button(sv, text=_("Muat server"), command=self.load_servers)
        self.load_btn.pack(side="right", padx=(6, 0))
        self.search_entry.pack(side="right", padx=(6, 0))
        self.search_hint = ttk.Label(sv, text=_("kota/ISP:"), style="Muted.TLabel")
        self.search_hint.pack(side="right", padx=(10, 0))
        row("server", 2, _("Server"), sv)
        row("down", 3, _("URL download"), ttk.Entry(cfg, textvariable=self.url))
        row("up", 4, _("URL upload (opsional)"), ttk.Entry(cfg, textvariable=self.up_url))
        lan = ttk.Frame(cfg)
        self.lan_entry = ttk.Entry(lan, textvariable=self.lan_host, width=22)
        self.lan_entry.pack(side="left")
        ttk.Label(lan, text=_("Port")).pack(side="left", padx=(10, 6))
        _spin(lan, self.lan_port, 1, 65535, 7).pack(side="left")
        row("lan", 5, _("Server LAN (IP)"), lan)

        opt = ttk.Frame(cfg)
        opt.grid(row=6, column=0, columnspan=3, sticky="w", pady=(8, 0))
        ttk.Label(opt, text=_("Durasi per arah (detik)")).pack(side="left")
        _spin(opt, self.duration, 3, 60, 5).pack(side="left", padx=(6, 14))
        ttk.Label(opt, text=_("Stream paralel")).pack(side="left")
        _spin(opt, self.streams, 1, 16, 4).pack(side="left", padx=(6, 14))
        ttk.Checkbutton(opt, text=_("Tes upload"), variable=self.upload).pack(side="left")
        self.note = ttk.Label(cfg, style="Muted.TLabel", wraplength=720, justify="left")
        self.note.grid(row=7, column=0, columnspan=3, sticky="w", pady=(8, 0))
        btns = ttk.Frame(cfg)
        btns.grid(row=8, column=0, columnspan=3, sticky="w", pady=(10, 0))
        self.start_btn = ttk.Button(btns, text=_("Mulai speed test"), command=self.start)
        self.start_btn.pack(side="left")
        self.stop_btn = ttk.Button(btns, text=_("Stop"), command=self.stop_event.set, state="disabled")
        self.stop_btn.pack(side="left", padx=6)

        srv = ttk.LabelFrame(top, text=f" {_('Mode server LAN (laptop ini)')} ", padding=10)
        srv.pack(side="left", fill="y", padx=(10, 0))
        self.srv_port = tk.IntVar(value=speedtest.LAN_PORT)
        prow = ttk.Frame(srv)
        prow.pack(anchor="w")
        ttk.Label(prow, text=_("Port")).pack(side="left")
        _spin(prow, self.srv_port, 1, 65535, 7).pack(side="left", padx=6)
        self.srv_btn = ttk.Button(srv, text=_("Jalankan server"), command=self.toggle_server)
        self.srv_btn.pack(anchor="w", pady=(8, 6))
        ips = ", ".join(speedtest.local_ips()) or "-"
        ttk.Label(srv, text=_("IP laptop ini: {ips}").format(ips=ips), wraplength=240, justify="left").pack(anchor="w")
        self.srv_log = ttk.Label(srv, text=_("Server mati."), style="Muted.TLabel", wraplength=240, justify="left")
        self.srv_log.pack(anchor="w", pady=(6, 0))

        meters = ttk.Frame(self, padding=(0, 10))
        meters.pack(fill="x")
        meters.columnconfigure((0, 1, 2, 3), weight=1, uniform="m")
        self.small = {}
        for col, key, title in ((0, "ping", "PING"), (3, "jitter", "JITTER")):
            box = theme.card(meters, 18, 12)
            box.grid(row=0, column=col, sticky="nsew", padx=6)
            inner = tk.Frame(box)
            theme.register(inner, "cardfill")
            inner.place(relx=0.5, rely=0.5, anchor="center")
            theme.card_label(inner, title, "title").pack()
            val = theme.card_label(inner, "-", "value")
            val.pack(pady=(4, 0))
            theme.card_label(inner, "ms", "unit").pack()
            self.small[key] = val
        gbox1 = theme.card(meters, 8, 6)
        gbox1.grid(row=0, column=1, padx=6, sticky="nsew")
        self.down_gauge = Gauge(gbox1, "DOWNLOAD", "Mbps", "accent")
        self.down_gauge.pack()
        gbox2 = theme.card(meters, 8, 6)
        gbox2.grid(row=0, column=2, padx=6, sticky="nsew")
        self.up_gauge = Gauge(gbox2, "UPLOAD", "Mbps", "accent2")
        self.up_gauge.pack()
        self.phase = ttk.Label(self, text="", style="Accent.TLabel")
        self.phase.pack(anchor="w")
        self.bar = ttk.Progressbar(self, mode="determinate")
        self.bar.pack(fill="x", pady=(4, 10))

        hist = ttk.LabelFrame(self, text=f" {_('Riwayat')} ", padding=6)
        hist.pack(fill="both", expand=True)
        hb = ttk.Frame(hist)
        hb.pack(fill="x", pady=(0, 6))
        ttk.Button(hb, text=_("Export CSV..."), command=self.export).pack(side="left")
        cols = (("when", _("Waktu"), 140), ("mode", _("Mode"), 170), ("server", "Server", 300),
                ("ping", "Ping ms", 70), ("jitter", "Jitter ms", 70), ("down", "Download Mbps", 110),
                ("up", "Upload Mbps", 100), ("err", _("Keterangan"), 260))
        self.tree = ttk.Treeview(hist, columns=[c[0] for c in cols], show="headings", height=4)
        for key, label, width in cols:
            self.tree.heading(key, text=label)
            self.tree.column(key, width=width, anchor="w" if key in ("mode", "server", "err") else "center")
        self.tree.pack(fill="both", expand=True)
        self._mode_changed()
        self._srv_job = self.after(500, self._srv_poll)

    def destroy(self) -> None:
        if getattr(self, "_srv_job", None):
            self.after_cancel(self._srv_job)
            self._srv_job = None
        super().destroy()

    # --------------------------------------------------------------- state
    def get_state(self) -> dict:
        return {"history": list(self.history), "url": self.url.get(), "up_url": self.up_url.get(),
                "lan_host": self.lan_host.get(), "mode": self.modes[self.mode.get()],
                "provider": self.providers[self.provider.get()], "server": self.server_box.current(),
                "search": self.search.get(), "lists": {k: list(v) for k, v in self.servers.items()}}

    def set_state(self, st: dict) -> None:
        self.url.set(st.get("url", "http://"))
        self.up_url.set(st.get("up_url", ""))
        self.lan_host.set(st.get("lan_host", ""))
        self.search.set(st.get("search", ""))
        self.servers.update(st.get("lists", {}))
        for label, key in self.modes.items():
            if key == st.get("mode"):
                self.mode.set(label)
        for label, key in self.providers.items():
            if key == st.get("provider"):
                self.provider.set(label)
        self._mode_changed(autoload=False)
        idx = st.get("server", 0)
        if isinstance(idx, int) and 0 <= idx < len(self.server_box["values"]):
            self.server_box.current(idx)
        for r in reversed(st.get("history", [])):
            self._add_history(r)

    def _srv_poll(self):
        try:
            while True:
                self.srv_log.configure(text=self.srv_msgs.get_nowait())
        except queue.Empty:
            pass
        try:
            while True:
                kind, provider, data = self.list_msgs.get_nowait()
                self.loading = False
                self.load_btn.configure(state="normal")
                if kind == "ok":
                    self.servers[provider] = data
                    if self.providers[self.provider.get()] == provider:
                        self._fill_servers()
                    self.status(_("{count} server dimuat.").format(count=len(data)))
                else:
                    messagebox.showerror(APP_NAME, _("Gagal memuat daftar server (butuh internet):\n{error}")
                                         .format(error=data))
        except queue.Empty:
            pass
        self._srv_job = self.after(500, self._srv_poll)

    # ---------------------------------------------------------------- layout
    def _show(self, key: str, visible: bool) -> None:
        for w in self.rows[key]:
            if visible:
                w.grid()
            else:
                w.grid_remove()

    def _mode_changed(self, autoload: bool = True):
        internet = self.modes[self.mode.get()] == "internet"
        self._show("provider", internet)
        self._show("lan", not internet)
        if internet:
            self._provider_changed(autoload)
        else:
            for key in ("server", "down", "up"):
                self._show(key, False)
            self.note.configure(text=_("Offline. Jalankan 'Mode server LAN' di NetManage laptop lain, lalu isi "
                                       "IP laptop itu. Cocok untuk mengukur throughput link antar site/VLAN."))

    def _provider_changed(self, autoload: bool = True):
        p = self.providers[self.provider.get()]
        custom = p == "custom"
        self._show("server", not custom)
        self._show("down", custom)
        self._show("up", custom)
        for w in (self.load_btn, self.search_entry, self.search_hint):
            w.pack_forget()
        if p in ("ookla", "librespeed"):  # side=right: first packed sits rightmost
            self.load_btn.pack(side="right", padx=(6, 0))
        if p == "ookla":
            self.search_entry.pack(side="right", padx=(6, 0))
            self.search_hint.pack(side="right", padx=(10, 0))
        self._fill_servers()
        if autoload and p in ("ookla", "librespeed") and not self.servers[p]:
            self.load_servers()
        self.note.configure(text={
            "cloudflare": _("Butuh internet. Server Cloudflare terdekat dipilih otomatis. Download dan upload."),
            "ookla": _("Butuh internet. Server Speedtest.net (Ookla) terdekat, atau cari per kota/ISP "
                       "(contoh: Jakarta, Surabaya, Telkom, Biznet). Download dan upload; sebagian server "
                       "menolak upload, coba server lain jika terjadi."),
            "librespeed": _("Butuh internet. Server LibreSpeed publik (open source). Download dan upload."),
            "mirror": _("Butuh internet. File 100 MB di data center publik. Hanya mengukur download."),
            "custom": _("URL download: file besar di server Anda (HTTP/HTTPS). URL upload opsional, server harus "
                        "menerima POST (contoh: empty.php LibreSpeed)."),
        }[p] + " " + _("Data yang dikirim hanya byte acak."))

    def _fill_servers(self):
        p = self.providers[self.provider.get()]
        items = self.servers.get(p, [])
        self.server_box.configure(values=[e.label for e in items])
        if items:
            self.server_box.current(0)
        else:
            self.server_var.set(_("(klik Muat server)") if p in ("ookla", "librespeed") else "")

    def load_servers(self):
        p = self.providers[self.provider.get()]
        if self.loading or p not in ("ookla", "librespeed"):
            return
        self.loading = True
        self.load_btn.configure(state="disabled")
        self.server_var.set(_("Memuat daftar server..."))
        search = self.search.get()

        def work():
            try:
                data = speedtest.ookla_servers(search) if p == "ookla" else speedtest.librespeed_servers()
                if not data:
                    raise ValueError(_("tidak ada server yang cocok"))
                self.list_msgs.put(("ok", p, data))
            except Exception as exc:  # noqa: BLE001 - network errors shown to the user
                self.list_msgs.put(("err", p, f"{type(exc).__name__}: {exc}"))

        threading.Thread(target=work, daemon=True).start()

    def _endpoint(self) -> speedtest.Endpoint | None:
        p = self.providers[self.provider.get()]
        if p == "custom":
            url = self.url.get().strip()
            if url in ("", "http://", "https://"):
                messagebox.showinfo(APP_NAME, _("Isi URL file untuk diunduh."))
                return None
            return speedtest.custom_endpoint(url, self.up_url.get())
        items = self.servers.get(p, [])
        idx = self.server_box.current()
        if not items or idx < 0:
            messagebox.showinfo(APP_NAME, _("Pilih server dulu (klik Muat server)."))
            return None
        return items[idx]

    # -------------------------------------------------------------- server
    def toggle_server(self):
        if self.server and self.server.running:
            self.server.stop()
            self.server = None
            self.srv_btn.configure(text=_("Jalankan server"))
            self.srv_log.configure(text=_("Server mati."))
            return
        port = _int(self.srv_port, speedtest.LAN_PORT, 1, 65535)
        self.server = speedtest.LanServer(port=port, log=self.srv_msgs.put)
        try:
            self.server.start()
        except OSError as exc:
            self.server = None
            messagebox.showerror(APP_NAME, _("Server gagal jalan di port {port}:\n{error}").format(port=port, error=exc))
            return
        self.srv_btn.configure(text=_("Hentikan server"))
        self.status(_("Server speed test LAN aktif di port {port}. Izinkan di Windows Firewall jika diminta.")
                    .format(port=port))

    # ----------------------------------------------------------------- run
    def start(self):
        if self.running:
            return
        mode = self.modes[self.mode.get()]
        host = self.lan_host.get().strip()
        endpoint = None
        if mode == "lan" and not host:
            messagebox.showinfo(APP_NAME, _("Isi IP laptop yang menjalankan server LAN NetManage."))
            return
        if mode == "internet":
            endpoint = self._endpoint()
            if endpoint is None:
                return
        duration = _int(self.duration, 10, 3, 60)
        streams = _int(self.streams, 4, 1, 16)
        port = _int(self.lan_port, speedtest.LAN_PORT, 1, 65535)  # Tk variables: read on the UI thread only
        upload = self.upload.get()
        for v in self.small.values():
            v.configure(text="-")
        self.down_gauge.reset()
        self.up_gauge.reset()
        self.stop_event.clear()
        self.running = True
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.bar.configure(maximum=duration * (2 if upload else 1) + 2, value=0)
        self.t0 = time.perf_counter()

        def progress(phase, mbps, elapsed):
            self.events.put(("progress", (phase, mbps)))

        def work():
            if mode == "lan":
                r = speedtest.lan_test(host, port, duration, streams, progress, self.stop_event)
                if not upload:
                    r.upload_mbps = None
            else:
                r = speedtest.internet_test(endpoint, duration, streams, upload, progress, self.stop_event)
            self.events.put(("done", r))

        threading.Thread(target=work, daemon=True).start()
        self.phase.configure(text=_("Mengukur latency..."))
        self.after(100, self._poll)

    def _poll(self):
        self.bar.configure(value=min(self.bar.cget("maximum"), time.perf_counter() - self.t0))
        try:
            while True:
                kind, data = self.events.get_nowait()
                if kind == "progress":
                    phase, value = data
                    if phase == "ping":
                        self.small["ping"].configure(text=f"{value:.1f}")
                        self.phase.configure(text=_("Mengukur download..."))
                    elif phase == "download":
                        self.down_gauge.set(value)
                        self.phase.configure(text=_("Mengukur download..."))
                    else:
                        self.up_gauge.set(value)
                        self.phase.configure(text=_("Mengukur upload..."))
                elif kind == "done":
                    self._finish(data)
                    return
        except queue.Empty:
            pass
        self.after(150, self._poll)

    @staticmethod
    def _fmt(v):
        return f"{v:.1f}" if isinstance(v, float) else "-"

    def _finish(self, r: speedtest.SpeedResult):
        self.running = False
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.bar.configure(value=self.bar.cget("maximum"))
        self.small["ping"].configure(text=self._fmt(r.ping_ms))
        self.small["jitter"].configure(text=self._fmt(r.jitter_ms))
        self.down_gauge.set(r.download_mbps, active=r.download_mbps is not None)
        self.up_gauge.set(r.upload_mbps, active=r.upload_mbps is not None)
        self.phase.configure(text=_("Selesai.") if not r.error else _("Selesai dengan catatan: {error}").format(error=r.error))
        self._add_history(r)
        self.status(_("Speed test: download {down} Mbps, upload {up} Mbps, ping {ping} ms").format(
            down=self._fmt(r.download_mbps), up=self._fmt(r.upload_mbps), ping=self._fmt(r.ping_ms)))

    def _add_history(self, r: speedtest.SpeedResult):
        self.history.insert(0, r)
        f = self._fmt
        self.tree.insert("", 0, values=(r.when, r.mode, r.server, f(r.ping_ms), f(r.jitter_ms),
                                        f(r.download_mbps), f(r.upload_mbps), r.error))

    def export(self):
        if not self.history:
            return
        path = filedialog.asksaveasfilename(initialdir=str(output_dir()), defaultextension=".csv",
                                            initialfile=f"speedtest_{time.strftime('%Y%m%d-%H%M%S')}.csv")
        if path:
            Path(path).write_text(speedtest.history_csv(self.history), encoding="utf-8")
            self.status(_("Disimpan: {path}").format(path=path))

    def shutdown(self):
        if self.server:
            self.server.stop()
            self.server = None
