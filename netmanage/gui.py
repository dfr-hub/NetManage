"""NetManage desktop GUI (Tkinter + sv-ttk). Tabs: Convert, Log Collector, Topology, Bulk Ping, Speed Test."""
from __future__ import annotations

import os
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from . import APP_NAME, __version__, collector, i18n, parsers, settings, theme, topology
from .converter import convert
from .gui_tools import PingTab, SpeedTab
from .i18n import _
from .model import VENDORS
from .paths import output_dir

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    HAS_DND = True
except Exception:  # noqa: BLE001 - app still works without drag & drop
    HAS_DND = False

VENDOR_KEYS = list(VENDORS)
VENDOR_LABELS = [VENDORS[k] for k in VENDOR_KEYS]
LABEL_TO_KEY = {v: k for k, v in VENDORS.items()}
ENGINE_KEYS = ("builtin", "auto", "batfish")
MONO = ("Consolas", 10)
LANGS = {"Bahasa Indonesia": "id", "English": "en"}


def auto_label() -> str:
    return _("Deteksi otomatis")


def engine_labels() -> dict[str, str]:
    return {_("Parser bawaan (semua vendor)"): "builtin",
            _("Batfish jika tersedia, lalu bawaan"): "auto",
            _("Batfish saja (Cisco/Arista/Juniper/Fortinet)"): "batfish"}


def read_text(path: str) -> str:
    raw = Path(path).read_bytes()
    for enc in ("utf-8-sig", "utf-16", "cp1252", "latin-1"):
        try:
            text = raw.decode(enc)
            if "\x00" not in text:
                return text
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1", errors="replace")


def drop_paths(widget: tk.Misc, data: str) -> list[str]:
    return [p for p in widget.tk.splitlist(data) if os.path.isfile(p)]


def open_folder(path: Path) -> None:
    try:
        os.startfile(str(path))  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        messagebox.showinfo(APP_NAME, str(path))


def text_box(parent: tk.Misc, height: int = 10, readonly: bool = False, width: int = 80) -> tk.Text:
    frame = ttk.Frame(parent)
    frame.pack(fill="both", expand=True)
    box = tk.Text(frame, height=height, width=width, wrap="none", font=MONO, undo=True)
    theme.register(box, "readonly" if readonly else "text")
    ys = ttk.Scrollbar(frame, orient="vertical", command=box.yview)
    xs = ttk.Scrollbar(frame, orient="horizontal", command=box.xview)
    box.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
    box.grid(row=0, column=0, sticky="nsew")
    ys.grid(row=0, column=1, sticky="ns")
    xs.grid(row=1, column=0, sticky="ew")
    frame.rowconfigure(0, weight=1)
    frame.columnconfigure(0, weight=1)
    if readonly:
        box.configure(state="disabled")
    return box


def set_text(box: tk.Text, text: str) -> None:
    state = box.cget("state")
    box.configure(state="normal")
    box.delete("1.0", "end")
    box.insert("1.0", text)
    box.configure(state=state)


def section(parent, title: str, **kw) -> ttk.LabelFrame:
    return ttk.LabelFrame(parent, text=f" {title} ", padding=kw.pop("padding", 6), **kw)


# ====================================================================== Convert
class ConvertTab(ttk.Frame):
    def __init__(self, master, status):
        super().__init__(master, padding=10)
        self.status = status
        self.src_path = ""
        self.engines = engine_labels()

        bar = ttk.Frame(self)
        bar.pack(fill="x")
        ttk.Label(bar, text=_("Sumber:")).pack(side="left")
        self.src = ttk.Combobox(bar, state="readonly", width=24, values=[auto_label()] + VENDOR_LABELS)
        self.src.set(auto_label())
        self.src.pack(side="left", padx=(6, 6))
        ttk.Button(bar, text="⇄", width=3, command=self.swap).pack(side="left")
        ttk.Label(bar, text=_("Tujuan:")).pack(side="left", padx=(6, 0))
        self.dst = ttk.Combobox(bar, state="readonly", width=24, values=VENDOR_LABELS)
        self.dst.set(VENDORS["juniper_junos"])
        self.dst.pack(side="left", padx=6)
        ttk.Label(bar, text=_("Parser:")).pack(side="left", padx=(12, 0))
        self.engine = ttk.Combobox(bar, state="readonly", width=36, values=list(self.engines))
        self.engine.set(next(iter(self.engines)))
        self.engine.pack(side="left", padx=6)
        ttk.Button(bar, text=_("Convert"), command=self.run).pack(side="right")

        bar2 = ttk.Frame(self)
        bar2.pack(fill="x", pady=(8, 6))
        ttk.Button(bar2, text=_("Buka file..."), command=self.open_file).pack(side="left")
        ttk.Button(bar2, text=_("Bersihkan"), command=lambda: set_text(self.inp, "")).pack(side="left", padx=6)
        ttk.Button(bar2, text=_("Output jadi input (balik)"), command=self.reverse).pack(side="left")
        ttk.Button(bar2, text=_("Simpan output..."), command=self.save).pack(side="right")
        ttk.Button(bar2, text=_("Salin output"), command=self.copy).pack(side="right", padx=6)
        ttk.Button(bar2, text=_("Convert banyak file..."), command=self.batch).pack(side="right")
        self.detected = ttk.Label(bar2, text="", style="Accent.TLabel")
        self.detected.pack(side="left", padx=10)

        panes = ttk.PanedWindow(self, orient="horizontal")
        panes.pack(fill="both", expand=True)
        left = section(panes, _("Konfigurasi sumber  (paste, buka, atau drop file di sini)"))
        right = section(panes, _("Hasil konversi"))
        panes.add(left, weight=1)
        panes.add(right, weight=1)
        self.inp = text_box(left)
        out_panes = ttk.PanedWindow(right, orient="vertical")
        out_panes.pack(fill="both", expand=True)
        f1, f2 = ttk.Frame(out_panes), section(out_panes, _("Laporan konversi"))
        out_panes.add(f1, weight=3)
        out_panes.add(f2, weight=2)
        self.out = text_box(f1)
        self.rep = text_box(f2, height=8, readonly=True)
        self.inp.bind("<<Modified>>", self._modified)
        if HAS_DND:
            self.inp.drop_target_register(DND_FILES)
            self.inp.dnd_bind("<<Drop>>", self._drop)

    def get_state(self) -> dict:
        return {"text": self.inp.get("1.0", "end-1c"), "src_path": self.src_path,
                "src": LABEL_TO_KEY.get(self.src.get(), ""), "dst": LABEL_TO_KEY.get(self.dst.get(), "")}

    def set_state(self, st: dict) -> None:
        set_text(self.inp, st.get("text", ""))
        self.src_path = st.get("src_path", "")
        if st.get("src") in VENDORS:
            self.src.set(VENDORS[st["src"]])
        if st.get("dst") in VENDORS:
            self.dst.set(VENDORS[st["dst"]])

    def _modified(self, _event=None):
        if not self.inp.edit_modified():
            return
        self.inp.edit_modified(False)
        text = self.inp.get("1.0", "end")
        vendor = parsers.detect(text) if text.strip() else ""
        self.detected.configure(text=_("Terdeteksi: {vendor}").format(vendor=VENDORS[vendor]) if vendor else
                                (_("Vendor belum dikenali") if text.strip() else ""))

    def _drop(self, event):
        paths = drop_paths(self, event.data)
        if paths:
            self.load(paths[0])
        return event.action

    def load(self, path: str):
        set_text(self.inp, read_text(path))
        self.src_path = path
        self.status(_("Dibuka: {path}").format(path=path))

    def open_file(self):
        path = filedialog.askopenfilename(title=_("Buka konfigurasi"),
                                          filetypes=[(_("Konfigurasi"), "*.cfg *.conf *.txt *.rsc *.log *.set"),
                                                     (_("Semua file"), "*.*")])
        if path:
            self.load(path)

    def _src_key(self, text: str) -> str:
        label = self.src.get()
        return "" if label == auto_label() else LABEL_TO_KEY[label]

    def run(self):
        text = self.inp.get("1.0", "end")
        try:
            res = convert(text, LABEL_TO_KEY[self.dst.get()], self._src_key(text),
                          self.engines[self.engine.get()], self.src_path)
        except Exception as exc:  # noqa: BLE001 - show every parser error to the user
            messagebox.showerror(APP_NAME, _("Konversi gagal:\n{error}").format(error=exc))
            return
        set_text(self.out, res.output)
        set_text(self.rep, res.report())
        self.status(_("Selesai: {src} -> {dst}, {warn} peringatan, {skip} baris tidak dikonversi").format(
            src=VENDORS[res.src_vendor], dst=VENDORS[res.dst_vendor], warn=len(res.warnings),
            skip=len(res.unparsed)))

    def swap(self):
        src = self.src.get()
        if src == auto_label():
            vendor = parsers.detect(self.inp.get("1.0", "end"))
            src = VENDORS.get(vendor, VENDORS["cisco_ios"])
        self.src.set(self.dst.get())
        self.dst.set(src)

    def reverse(self):
        """Put the output back as input and swap vendors, for a round-trip check."""
        out = self.out.get("1.0", "end").strip()
        if not out:
            return
        self.swap()
        set_text(self.inp, out + "\n")
        set_text(self.out, "")
        set_text(self.rep, "")

    def copy(self):
        self.clipboard_clear()
        self.clipboard_append(self.out.get("1.0", "end"))
        self.status(_("Output disalin ke clipboard"))

    def save(self):
        out = self.out.get("1.0", "end").strip()
        if not out:
            return
        dst = LABEL_TO_KEY[self.dst.get()]
        stem = Path(self.src_path).stem if self.src_path else "config"
        path = filedialog.asksaveasfilename(initialdir=str(output_dir()), initialfile=f"{stem}_{dst}.cfg",
                                            defaultextension=".cfg")
        if path:
            Path(path).write_text(out + "\n", encoding="utf-8")
            report = self.rep.get("1.0", "end").strip()
            if report:
                Path(path).with_suffix(".report.txt").write_text(report + "\n", encoding="utf-8")
            self.status(_("Disimpan: {path}").format(path=path))

    def batch(self):
        paths = filedialog.askopenfilenames(title=_("Pilih banyak konfigurasi"))
        if not paths:
            return
        dst = LABEL_TO_KEY[self.dst.get()]
        folder = output_dir() / f"convert_{dst}"
        folder.mkdir(parents=True, exist_ok=True)
        ok, errors = 0, []
        for p in paths:
            try:
                text = read_text(p)
                res = convert(text, dst, self._src_key(text), self.engines[self.engine.get()], p)
                (folder / f"{Path(p).stem}_{dst}.cfg").write_text(res.output, encoding="utf-8")
                (folder / f"{Path(p).stem}_{dst}.report.txt").write_text(res.report() + "\n", encoding="utf-8")
                ok += 1
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{Path(p).name}: {exc}")
        messagebox.showinfo(APP_NAME, _("{count} file berhasil dikonversi ke:\n{folder}").format(
            count=ok, folder=folder) + (("\n\n" + _("Gagal:") + "\n" + "\n".join(errors)) if errors else ""))
        open_folder(folder)


# ================================================================ Log collector
class DeviceDialog(tk.Toplevel):
    def __init__(self, master, target: collector.Target | None = None):
        super().__init__(master)
        self.title(_("Device"))
        self.resizable(False, False)
        self.configure(background=theme.c("bg"))
        self.result: collector.Target | None = None
        t = target or collector.Target(host="", ip="", vendor="cisco_ios")
        self.vars = {k: tk.StringVar(value=str(getattr(t, k))) for k in
                     ("host", "ip", "port", "username", "password", "secret")}
        self.vendor = tk.StringVar(value=VENDORS.get(t.vendor, VENDOR_LABELS[0]))
        self.proto = tk.StringVar(value=t.protocol)
        frm = ttk.Frame(self, padding=16)
        frm.pack()
        rows = [(_("Nama"), "host"), (_("IP / host"), "ip"), (_("Port"), "port"), ("Username", "username"),
                ("Password", "password"), ("Enable secret", "secret")]
        for r, (label, key) in enumerate(rows):
            ttk.Label(frm, text=label).grid(row=r, column=0, sticky="w", pady=3)
            ttk.Entry(frm, textvariable=self.vars[key], width=32,
                      show="•" if key in ("password", "secret") else "").grid(row=r, column=1, pady=3)
        ttk.Label(frm, text="Vendor").grid(row=6, column=0, sticky="w")
        ttk.Combobox(frm, textvariable=self.vendor, values=VENDOR_LABELS, state="readonly",
                     width=30).grid(row=6, column=1, pady=3)
        ttk.Label(frm, text=_("Protokol")).grid(row=7, column=0, sticky="w")
        ttk.Combobox(frm, textvariable=self.proto, values=["ssh", "telnet"], state="readonly",
                     width=30).grid(row=7, column=1, pady=3)
        ttk.Label(frm, text=_("Username/password kosong = pakai kredensial default."),
                  style="Muted.TLabel").grid(row=8, column=0, columnspan=2, pady=(8, 0))
        btns = ttk.Frame(frm)
        btns.grid(row=9, column=0, columnspan=2, pady=(12, 0))
        ttk.Button(btns, text=_("Simpan"), command=self.ok).pack(side="left", padx=4)
        ttk.Button(btns, text=_("Batal"), style="Ghost.TButton", command=self.destroy).pack(side="left")
        self.transient(master)
        theme.dark_titlebar(self, theme.mode() == "dark")
        self.grab_set()
        self.wait_window()

    def ok(self):
        v = {k: var.get().strip() for k, var in self.vars.items()}
        if not v["ip"]:
            messagebox.showwarning(APP_NAME, _("IP wajib diisi."), parent=self)
            return
        proto = self.proto.get()
        port = int(v["port"]) if v["port"].isdigit() else (23 if proto == "telnet" else 22)
        self.result = collector.Target(host=v["host"] or v["ip"], ip=v["ip"], vendor=LABEL_TO_KEY[self.vendor.get()],
                                       port=port, protocol=proto, username=v["username"],
                                       password=v["password"], secret=v["secret"])
        self.destroy()


class CollectorTab(ttk.Frame):
    COLS = ("host", "ip", "vendor", "proto", "status")

    def __init__(self, master, status, send_to_topology):
        super().__init__(master, padding=10)
        self.status = status
        self.send_to_topology = send_to_topology
        self.targets: list[collector.Target] = []
        self.commands = collector.load_commands()
        self.events: queue.Queue = queue.Queue()
        self.stop_event = threading.Event()
        self.running = False
        self.last_run: Path | None = None

        panes = ttk.PanedWindow(self, orient="horizontal")
        panes.pack(fill="both", expand=True)
        left = ttk.Frame(panes)
        right = ttk.Frame(panes)
        panes.add(left, weight=3)
        panes.add(right, weight=2)

        inv = section(left, _("Daftar device"))
        inv.pack(fill="both", expand=True)
        bar = ttk.Frame(inv)
        bar.pack(fill="x", pady=(0, 6))
        for text, cmd in ((_("Tambah"), self.add), (_("Edit"), self.edit), (_("Hapus"), self.remove),
                          (_("Import CSV..."), self.import_csv), (_("Export CSV..."), self.export_csv)):
            ttk.Button(bar, text=text, command=cmd).pack(side="left", padx=(0, 6))
        self.tree = ttk.Treeview(inv, columns=self.COLS, show="headings", selectmode="extended", height=10)
        for col, label, width in (("host", _("Nama"), 140), ("ip", "IP", 120), ("vendor", "Vendor", 160),
                                  ("proto", _("Protokol"), 70), ("status", "Status", 260)):
            self.tree.heading(col, text=label)
            self.tree.column(col, width=width, anchor="w")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<Double-1>", lambda _e: self.edit())
        ttk.Label(inv, style="Muted.TLabel", wraplength=820, justify="left",
                  text=_("Format CSV: host,ip,vendor,port,protocol,username,password") +
                  "  (vendor: " + ", ".join(VENDOR_KEYS) + ")").pack(anchor="w", pady=(6, 0))

        cred = section(left, _("Kredensial default & opsi"))
        cred.pack(fill="x", pady=(8, 0))
        self.user = tk.StringVar()
        self.pwd = tk.StringVar()
        self.workers = tk.IntVar(value=5)
        self.timeout = tk.IntVar(value=60)
        ttk.Label(cred, text="Username").grid(row=0, column=0, sticky="w")
        ttk.Entry(cred, textvariable=self.user, width=18).grid(row=0, column=1, padx=6)
        ttk.Label(cred, text="Password").grid(row=0, column=2, sticky="w")
        ttk.Entry(cred, textvariable=self.pwd, width=18, show="•").grid(row=0, column=3, padx=6)
        ttk.Label(cred, text=_("Paralel")).grid(row=0, column=4, sticky="w", padx=(8, 0))
        ttk.Spinbox(cred, from_=1, to=50, textvariable=self.workers, width=4).grid(row=0, column=5, padx=6)
        ttk.Label(cred, text=_("Timeout/command (s)")).grid(row=0, column=6, sticky="w", padx=(8, 0))
        ttk.Spinbox(cred, from_=10, to=900, textvariable=self.timeout, width=5).grid(row=0, column=7, padx=6)

        run = ttk.Frame(left)
        run.pack(fill="x", pady=8)
        self.start_btn = ttk.Button(run, text=_("Mulai ambil log"), command=self.start)
        self.start_btn.pack(side="left")
        self.stop_btn = ttk.Button(run, text=_("Stop"), command=self.stop, state="disabled")
        self.stop_btn.pack(side="left", padx=6)
        ttk.Button(run, text=_("Buka folder hasil"), command=self.open_results).pack(side="left")
        ttk.Button(run, text=_("Kirim config ke Topologi"), command=self.to_topology).pack(side="left", padx=6)
        self.progress = ttk.Progressbar(run, mode="determinate", length=180)
        self.progress.pack(side="right")

        logf = section(left, _("Aktivitas"))
        logf.pack(fill="both", expand=True)
        self.log = text_box(logf, height=8, readonly=True)

        cmdf = section(right, _("Command per vendor (satu baris satu command)"))
        cmdf.pack(fill="both", expand=True)
        top = ttk.Frame(cmdf)
        top.pack(fill="x", pady=(0, 6))
        self.cmd_vendor = ttk.Combobox(top, state="readonly", values=VENDOR_LABELS, width=26)
        self.cmd_vendor.set(VENDOR_LABELS[0])
        self.cmd_vendor.pack(side="left")
        self.cmd_vendor.bind("<<ComboboxSelected>>", lambda _e: self._show_commands())
        ttk.Button(top, text=_("Simpan"), command=self.save_commands).pack(side="right")
        ttk.Button(top, text=_("Default"), style="Ghost.TButton", command=self.reset_commands).pack(side="right", padx=6)
        self.cmd_box = text_box(cmdf, height=20)
        self._current_vendor = VENDOR_KEYS[0]
        self._show_commands(store=False)
        theme.on_change(self.apply_theme)
        self.apply_theme()

    def apply_theme(self):
        self.tree.tag_configure("ok", foreground=theme.c("ok"))
        self.tree.tag_configure("err", foreground=theme.c("err"))
        self.tree.tag_configure("run", foreground=theme.c("run"))

    def get_state(self) -> dict:
        return {"targets": list(self.targets), "user": self.user.get(), "pwd": self.pwd.get()}

    def set_state(self, st: dict) -> None:
        self.targets = list(st.get("targets", []))
        self.user.set(st.get("user", ""))
        self.pwd.set(st.get("pwd", ""))
        self._refresh()

    # ---------------------------------------------------------- inventory
    def _refresh(self):
        self.tree.delete(*self.tree.get_children())
        for idx, t in enumerate(self.targets):
            self.tree.insert("", "end", iid=str(idx),
                             values=(t.host, t.ip, VENDORS.get(t.vendor, t.vendor or "?"), t.protocol, ""))

    def _selected(self) -> list[int]:
        return sorted(int(i) for i in self.tree.selection())

    def add(self):
        dlg = DeviceDialog(self)
        if dlg.result:
            self.targets.append(dlg.result)
            self._refresh()

    def edit(self):
        sel = self._selected()
        if not sel:
            return
        dlg = DeviceDialog(self, self.targets[sel[0]])
        if dlg.result:
            self.targets[sel[0]] = dlg.result
            self._refresh()

    def remove(self):
        for idx in reversed(self._selected()):
            del self.targets[idx]
        self._refresh()

    def import_csv(self):
        path = filedialog.askopenfilename(filetypes=[("CSV", "*.csv"), (_("Semua file"), "*.*")])
        if not path:
            return
        try:
            items = collector.load_inventory(path)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror(APP_NAME, _("Gagal membaca CSV:\n{error}").format(error=exc))
            return
        bad = [t.label for t in items if t.vendor not in collector.PROFILES]
        self.targets += items
        self._refresh()
        self.status(_("{count} device diimport").format(count=len(items)))
        if bad:
            messagebox.showwarning(APP_NAME, _("Vendor tidak dikenal untuk: {names}\nEdit device tersebut dan pilih vendor.")
                                   .format(names=", ".join(bad)))

    def export_csv(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv", initialfile="inventory.csv")
        if path:
            collector.save_inventory(path, self.targets)
            self.status(_("Inventory disimpan (tanpa password): {path}").format(path=path))

    # ----------------------------------------------------------- commands
    def _store_commands(self):
        lines = [ln.strip() for ln in self.cmd_box.get("1.0", "end").split("\n") if ln.strip()]
        self.commands[self._current_vendor] = lines

    def _show_commands(self, store: bool = True):
        if store:
            self._store_commands()
        self._current_vendor = LABEL_TO_KEY[self.cmd_vendor.get()]
        set_text(self.cmd_box, "\n".join(self.commands.get(self._current_vendor, [])) + "\n")

    def save_commands(self):
        self._store_commands()
        path = collector.save_commands(self.commands)
        self.status(_("Command disimpan: {path}").format(path=path))

    def reset_commands(self):
        self.commands[self._current_vendor] = list(collector.PROFILES[self._current_vendor]["commands"])
        set_text(self.cmd_box, "\n".join(self.commands[self._current_vendor]) + "\n")

    # ---------------------------------------------------------------- run
    def _append(self, line: str):
        self.log.configure(state="normal")
        self.log.insert("end", line + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def start(self):
        if self.running:
            return
        if not self.targets:
            messagebox.showinfo(APP_NAME, _("Tambahkan device atau import CSV dulu."))
            return
        bad = [t.label for t in self.targets if t.vendor not in collector.PROFILES]
        if bad:
            messagebox.showwarning(APP_NAME, _("Pilih vendor untuk: {names}").format(names=", ".join(bad)))
            return
        self._store_commands()
        user, pwd = self.user.get().strip(), self.pwd.get()
        jobs = [collector.Target(**{**t.__dict__, "username": t.username or user, "password": t.password or pwd})
                for t in self.targets]
        missing = [t.label for t in jobs if not t.username]
        if missing:
            messagebox.showwarning(APP_NAME, _("Username kosong untuk: {names}").format(names=", ".join(missing)))
            return
        self.index = {t.label: str(i) for i, t in enumerate(self.targets)}
        for iid in self.tree.get_children():
            self.tree.set(iid, "status", _("menunggu"))
            self.tree.item(iid, tags=())
        self.last_run = collector.new_run_dir(output_dir())
        self.progress.configure(maximum=len(jobs), value=0)
        self.stop_event.clear()
        self.running = True
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self._append(_("== Mulai {count} device -> {path}").format(count=len(jobs), path=self.last_run))
        commands = {k: list(v) for k, v in self.commands.items()}
        workers, timeout = self.workers.get(), self.timeout.get()

        def work():
            collector.collect(jobs, commands, self.last_run, workers, timeout,
                              lambda kind, t, msg: self.events.put((kind, t.label, msg)), self.stop_event)
            self.events.put(("finished", "", ""))

        threading.Thread(target=work, daemon=True).start()
        self.after(150, self._poll)

    def _poll(self):
        try:
            while True:
                kind, label, msg = self.events.get_nowait()
                iid = self.index.get(label)
                if kind == "finished":
                    self.running = False
                    self.start_btn.configure(state="normal")
                    self.stop_btn.configure(state="disabled")
                    self._append(_("== Selesai. Hasil: {path}").format(path=self.last_run))
                    self.status(_("Pengambilan log selesai: {path}").format(path=self.last_run))
                    return
                if kind == "connect":
                    self._append(f"[{label}] " + _("konek {target}").format(target=msg))
                    if iid:
                        self.tree.set(iid, "status", _("konek..."))
                        self.tree.item(iid, tags=("run",))
                elif kind == "command":
                    if iid:
                        self.tree.set(iid, "status", f"> {msg}")
                elif kind == "done":
                    self._append(f"[{label}] OK -> {Path(msg).name}")
                    self.progress.step(1)
                    if iid:
                        self.tree.set(iid, "status", _("selesai"))
                        self.tree.item(iid, tags=("ok",))
                elif kind == "error":
                    self._append(f"[{label}] " + _("GAGAL: {error}").format(error=msg))
                    self.progress.step(1)
                    if iid:
                        self.tree.set(iid, "status", msg)
                        self.tree.item(iid, tags=("err",))
        except queue.Empty:
            pass
        self.after(150, self._poll)

    def stop(self):
        self.stop_event.set()
        self._append(_("== Stop diminta, menunggu command yang sedang jalan selesai..."))

    def open_results(self):
        open_folder(self.last_run or (output_dir() / "logs"))

    def to_topology(self):
        folder = (self.last_run / "configs") if self.last_run else None
        if not folder or not folder.exists():
            messagebox.showinfo(APP_NAME, _("Belum ada config hasil pengambilan log.\n"
                                            "Pastikan command config (mis. 'show running-config') ada di daftar."))
            return
        self.send_to_topology([str(p) for p in sorted(folder.glob("*.cfg"))])


# ===================================================================== Topology
class TopologyTab(ttk.Frame):
    def __init__(self, master, status):
        super().__init__(master, padding=10)
        self.status = status
        self.files: list[str] = []
        self.devices = []
        self.topo: topology.Topology | None = None
        self.scale = 1.0
        self.drag: tuple[str, float, float] | None = None

        bar = ttk.Frame(self)
        bar.pack(fill="x", pady=(0, 8))
        ttk.Button(bar, text=_("Tambah config..."), command=self.add_files).pack(side="left")
        ttk.Button(bar, text=_("Tambah folder..."), command=self.add_folder).pack(side="left", padx=6)
        ttk.Button(bar, text=_("Reset"), style="Ghost.TButton", command=self.clear).pack(side="left")
        self.ext = tk.BooleanVar(value=True)
        self.stub = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text=_("Peer BGP eksternal"), variable=self.ext, command=self.rebuild).pack(side="left", padx=(14, 0))
        ttk.Checkbutton(bar, text=_("Subnet LAN (stub)"), variable=self.stub, command=self.rebuild).pack(side="left", padx=8)
        ttk.Button(bar, text=_("Atur ulang layout"), command=self.relayout).pack(side="left", padx=6)
        ttk.Button(bar, text=_("Export draw.io..."), command=lambda: self.export("drawio")).pack(side="right")
        ttk.Button(bar, text=_("Export SVG..."), command=lambda: self.export("svg")).pack(side="right", padx=6)
        ttk.Button(bar, text=_("Export CSV link..."), command=lambda: self.export("csv")).pack(side="right")

        panes = ttk.PanedWindow(self, orient="horizontal")
        panes.pack(fill="both", expand=True)
        cf = ttk.Frame(panes)
        side = ttk.Frame(panes)
        panes.add(cf, weight=4)
        panes.add(side, weight=1)
        self.canvas = tk.Canvas(cf)
        theme.register(self.canvas, "canvas")
        self.canvas.pack(fill="both", expand=True)
        self.canvas.bind("<ButtonPress-1>", self._press)
        self.canvas.bind("<B1-Motion>", self._move)
        self.canvas.bind("<ButtonRelease-1>", lambda _e: setattr(self, "drag", None))
        self.canvas.bind("<MouseWheel>", self._zoom)
        self.canvas.bind("<ButtonPress-3>", lambda e: self.canvas.scan_mark(e.x, e.y))
        self.canvas.bind("<B3-Motion>", lambda e: self.canvas.scan_dragto(e.x, e.y, gain=1))
        self.canvas.bind("<Configure>", self._on_configure)
        self._auto = True  # re-layout to the canvas size until the user drags or zooms
        self._size = (0, 0)
        if HAS_DND:
            self.canvas.drop_target_register(DND_FILES)
            self.canvas.dnd_bind("<<Drop>>", self._drop)

        lf = section(side, _("File dimuat"))
        lf.pack(fill="both", expand=True)
        self.listbox = tk.Listbox(lf, height=10, width=34, font=("Segoe UI", 9), activestyle="none")
        theme.register(self.listbox, "list")
        self.listbox.pack(fill="both", expand=True)
        ttk.Button(lf, text=_("Hapus terpilih"), command=self.remove_selected).pack(fill="x", pady=(6, 0))
        info = section(side, _("Detail"))
        info.pack(fill="both", expand=True, pady=(8, 0))
        self.info = text_box(info, height=12, readonly=True, width=36)
        self.offset = (0.0, 0.0)
        theme.on_change(self.draw)
        self.draw()

    def get_state(self) -> dict:
        return {"files": list(self.files)}

    def set_state(self, st: dict) -> None:
        self.files = list(st.get("files", []))
        if self.files:
            self.rebuild()

    # ------------------------------------------------------------- files
    def _drop(self, event):
        paths = []
        for p in self.tk.splitlist(event.data):
            if os.path.isdir(p):
                paths += [str(x) for x in sorted(Path(p).iterdir()) if x.is_file()]
            elif os.path.isfile(p):
                paths.append(p)
        self.add_paths(paths)
        return event.action

    def add_files(self):
        self.add_paths(list(filedialog.askopenfilenames(title=_("Pilih konfigurasi router"))))

    def add_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.add_paths([str(x) for x in sorted(Path(folder).iterdir()) if x.is_file()])

    def add_paths(self, paths: list[str]):
        new = [p for p in paths if p not in self.files]
        if not new:
            return
        self.files += new
        self.rebuild()

    def remove_selected(self):
        for idx in reversed(self.listbox.curselection()):
            del self.files[idx]
        self.rebuild()

    def clear(self):
        self.files = []
        self.rebuild()

    # ------------------------------------------------------------- build
    def rebuild(self):
        self.devices, errors = [], []
        self.listbox.delete(0, "end")
        for path in self.files:
            name = Path(path).name
            try:
                dev = parsers.parse(read_text(path), source=path)
                self.devices.append(dev)
                self.listbox.insert("end", f"{dev.hostname or name}  [{VENDORS[dev.vendor]}]")
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{name}: {exc}")
                self.listbox.insert("end", f"{name}  [{_('GAGAL')}]")
                self.listbox.itemconfig("end", foreground=theme.c("err"))
        self.topo = topology.build(self.devices, self.ext.get(), self.stub.get()) if self.devices else None
        self._auto = True
        self._autolayout()
        if self.topo:
            l3 = sum(1 for lk in self.topo.links if lk.kind in ("l3", "lan"))
            text = _("{dev} device, {l3} link IP, {bgp} sesi BGP").format(
                dev=len(self.devices), l3=l3, bgp=sum(1 for lk in self.topo.links if lk.kind == "bgp")) + "\n\n"
            text += "\n".join(f"- {n}" for n in self.topo.notes + errors)
            set_text(self.info, text)
            self.status(_("Topologi: {dev} device, {links} link").format(dev=len(self.devices),
                                                                        links=len(self.topo.links)))
        else:
            set_text(self.info, "\n".join(errors))

    def _on_configure(self, event):
        size = (event.width, event.height)
        if abs(size[0] - self._size[0]) < 8 and abs(size[1] - self._size[1]) < 8:
            return
        self._size = size
        if self.topo and self._auto:
            self._autolayout()
        else:
            self.draw()

    def _autolayout(self):
        cw, ch = self.canvas.winfo_width(), self.canvas.winfo_height()
        if self.topo and cw > 200 and ch > 150:
            topology.layout(self.topo, width=cw, height=ch)
        self.fit()

    def fit(self):
        """Scale and center the diagram inside the visible canvas."""
        self.scale, self.offset = 1.0, (0.0, 0.0)
        if self.topo and self.topo.nodes:
            self.update_idletasks()
            cw, ch = max(self.canvas.winfo_width(), 400), max(self.canvas.winfo_height(), 300)
            xs = [n.x for n in self.topo.nodes.values()]
            ys = [n.y for n in self.topo.nodes.values()]
            w, h = max(xs) - min(xs) + 160, max(ys) - min(ys) + 90
            self.scale = max(0.3, min(1.6, cw / w, ch / h))
            self.offset = (cw / 2 - (min(xs) + max(xs)) / 2 * self.scale,
                           ch / 2 - (min(ys) + max(ys)) / 2 * self.scale)
        self.draw()

    def relayout(self):
        if self.topo:
            self._auto = True
            self._autolayout()

    # -------------------------------------------------------------- draw
    def draw(self):
        c = self.canvas
        c.delete("all")
        txt, muted = theme.c("canvas_text"), theme.c("muted")
        if not self.topo:
            w, h = max(c.winfo_width(), 400), max(c.winfo_height(), 300)
            c.create_text(w / 2, h / 2, fill=muted, font=("Segoe UI", 13), justify="center",
                          text=_("Drop file konfigurasi router di sini\n(Cisco, Juniper, MikroTik, Huawei, "
                                 "Fortinet,\nArista, H3C, Nokia, VyOS, Aruba)\n\natau klik 'Tambah config...'"))
            return
        s = self.scale
        ox, oy = self.offset
        c.delete("all")
        c.configure(scrollregion=(0, 0, 0, 0))

        def X(v):
            return v * s + ox

        def Y(v):
            return v * s + oy
        for lk in self.topo.links:
            a, b = self.topo.nodes[lk.a], self.topo.nodes[lk.b]
            color, dash = topology.LINK_STYLE[lk.kind]
            if theme.mode() == "dark" and lk.kind in ("l3", "lan"):
                color = "#94A3B8"
            c.create_line(X(a.x), Y(a.y), X(b.x), Y(b.y), fill=color, width=2,
                          dash=tuple(int(x) for x in dash.split(",")) if dash else None, tags=("link",))
            if lk.label:
                c.create_text(X((a.x + b.x) / 2), Y((a.y + b.y) / 2) - 8, text=lk.label, fill=muted,
                              font=("Segoe UI", 8), tags=("link",))
            for frac, text in ((0.2, " ".join(filter(None, (lk.a_if, lk.a_ip)))),
                               (0.8, " ".join(filter(None, (lk.b_if, lk.b_ip))))):
                if text and lk.kind != "bgp":
                    x = X(a.x + (b.x - a.x) * frac)
                    y = Y(a.y + (b.y - a.y) * frac) + 10
                    c.create_text(x, y, text=text, fill=txt, font=("Segoe UI", 8), tags=("link",))
        for node in self.topo.nodes.values():
            x, y = X(node.x), Y(node.y)
            tag = f"node:{node.id}"
            if node.kind == "router":
                color = topology.VENDOR_COLORS.get(node.vendor, topology.VENDOR_COLORS[""])
                self._round_rect(x - 64, y - 21, x + 64, y + 21, 10, fill=color, outline="", tags=(tag,))
                fg = "#FFFFFF"
            elif node.kind == "lan":
                c.create_oval(x - 62, y - 18, x + 62, y + 18, fill=theme.c("canvas_lan"), outline=muted, tags=(tag,))
                fg = txt
            else:
                c.create_rectangle(x - 56, y - 20, x + 56, y + 20, fill=theme.c("canvas_ext"),
                                   outline=theme.c("purple"), dash=(4, 3), tags=(tag,))
                fg = theme.c("purple")
            c.create_text(x, y, text=node.label, fill=fg, font=("Segoe UI Semibold", 9), justify="center",
                          tags=(tag,))

    def _round_rect(self, x1, y1, x2, y2, r, **kw):
        pts = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2, x2 - r, y2, x1 + r, y2,
               x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
        return self.canvas.create_polygon(pts, smooth=True, **kw)

    def _node_at(self, event) -> str:
        x, y = self.canvas.canvasx(event.x), self.canvas.canvasy(event.y)
        for item in reversed(self.canvas.find_overlapping(x - 1, y - 1, x + 1, y + 1)):
            for tag in self.canvas.gettags(item):
                if tag.startswith("node:"):
                    return tag[5:]
        return ""

    def _press(self, event):
        node_id = self._node_at(event)
        if not node_id or not self.topo:
            return
        self.drag = (node_id, self.canvas.canvasx(event.x), self.canvas.canvasy(event.y))
        node = self.topo.nodes[node_id]
        lines = [node.label.replace("\n", " "), node.detail, ""]
        for lk in self.topo.links:
            if node_id in (lk.a, lk.b):
                me_if, me_ip = (lk.a_if, lk.a_ip) if lk.a == node_id else (lk.b_if, lk.b_ip)
                other = lk.b if lk.a == node_id else lk.a
                lines.append(f"{me_if or '-'} {me_ip}  ->  {other}  ({lk.kind}{', ' + lk.label if lk.label else ''})")
        set_text(self.info, "\n".join(lines))

    def _move(self, event):
        if not self.drag or not self.topo:
            return
        node_id, lx, ly = self.drag
        x, y = self.canvas.canvasx(event.x), self.canvas.canvasy(event.y)
        node = self.topo.nodes[node_id]
        node.x += (x - lx) / self.scale
        node.y += (y - ly) / self.scale
        self._auto = False
        self.drag = (node_id, x, y)
        self.draw()

    def _zoom(self, event):
        if not self.topo:
            return
        factor = 1.1 if event.delta > 0 else 0.9
        new = max(0.2, min(3.0, self.scale * factor))
        factor = new / self.scale
        mx, my = self.canvas.canvasx(event.x), self.canvas.canvasy(event.y)
        ox, oy = self.offset
        self.offset = (mx - (mx - ox) * factor, my - (my - oy) * factor)  # zoom around the mouse
        self._auto = False
        self.scale = new
        self.draw()

    def export(self, kind: str):
        if not self.topo:
            messagebox.showinfo(APP_NAME, _("Belum ada topologi."))
            return
        ext = {"svg": ".svg", "drawio": ".drawio", "csv": ".csv"}[kind]
        path = filedialog.asksaveasfilename(initialdir=str(output_dir()), initialfile=f"topology{ext}",
                                            defaultextension=ext)
        if not path:
            return
        data = {"svg": topology.to_svg, "drawio": topology.to_drawio, "csv": topology.to_csv}[kind](self.topo)
        Path(path).write_text(data, encoding="utf-8")
        self.status(_("Diexport: {path}").format(path=path))


# ========================================================================= App
class App:
    TABS = (("conv", "Convert Config"), ("coll", "Log Collector"), ("topo", "Topology Mapper"),
            ("ping", "Bulk Ping"), ("speed", "Speed Test"))

    def __init__(self, root: tk.Tk):
        self.root = root
        self.prefs = settings.load()
        i18n.set_lang(self.prefs["lang"])
        root.title(f"{APP_NAME} {__version__}")
        root.geometry("1400x860")
        root.minsize(1060, 660)
        try:
            root.tk.call("tk", "scaling", root.winfo_fpixels("1i") / 72.0)
        except tk.TclError:
            pass
        theme.apply(root, self.prefs["theme"])
        try:
            root.iconphoto(True, theme.image("logo_64.png"), theme.image("logo_32.png"))
        except tk.TclError:
            pass
        self.build()
        root.protocol("WM_DELETE_WINDOW", self.on_close)

    # ---------------------------------------------------------------- layout
    def build(self, state: dict | None = None) -> None:
        for child in self.root.winfo_children():
            child.destroy()
        theme.reset_listeners()
        self._header()
        self.status_var = tk.StringVar(value=_("Siap. Semua fitur berjalan offline."))
        ttk.Label(self.root, textvariable=self.status_var, style="Status.TLabel", anchor="w").pack(
            fill="x", side="bottom")
        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill="both", expand=True, padx=10, pady=(10, 6))
        status = self.status_var.set
        self.conv = ConvertTab(self.nb, status)
        self.topo = TopologyTab(self.nb, status)
        self.coll = CollectorTab(self.nb, status, self._send_to_topology)
        self.ping = PingTab(self.nb, status, lambda: [(t.ip, t.host) for t in self.coll.targets])
        self.speed = SpeedTab(self.nb, status)
        for key, label in self.TABS:
            self.nb.add(getattr(self, key), text=f"  {label}  ")
        if not HAS_DND:
            status(_("Drag & drop tidak tersedia (tkinterdnd2 tidak ditemukan). Gunakan tombol Buka file."))
        if state:
            for key, _label in self.TABS:
                if key in state:
                    getattr(self, key).set_state(state[key])
            self.nb.select(state.get("tab", 0))
        theme.apply(self.root, theme.mode())
        self._update_header()

    def _header(self) -> None:
        hdr = tk.Frame(self.root, background=theme.HEADER_BG, height=68)
        hdr.pack(fill="x", side="top")
        hdr.pack_propagate(False)
        tk.Label(hdr, image=theme.image("logo_48.png"), background=theme.HEADER_BG).pack(side="left", padx=(16, 10))
        names = tk.Frame(hdr, background=theme.HEADER_BG)
        names.pack(side="left", fill="y", pady=10)
        tk.Label(names, text=APP_NAME, font=("Segoe UI Semibold", 17), foreground=theme.HEADER_FG,
                 background=theme.HEADER_BG).pack(anchor="w")
        tk.Label(names, text=_("Toolkit jaringan multi-vendor  •  v{version}").format(version=__version__),
                 font=("Segoe UI", 9), foreground=theme.HEADER_SUB, background=theme.HEADER_BG).pack(anchor="w")
        right = tk.Frame(hdr, background=theme.HEADER_BG)
        right.pack(side="right", padx=16)
        self.lang_box = ttk.Combobox(right, state="readonly", width=17, values=list(LANGS))
        self.lang_box.set(next(k for k, v in LANGS.items() if v == i18n.lang()))
        self.lang_box.bind("<<ComboboxSelected>>", lambda _e: self.set_language(LANGS[self.lang_box.get()]))
        self.lang_box.pack(side="right")
        tk.Label(right, text="🌐", font=("Segoe UI Symbol", 12), foreground=theme.HEADER_SUB,
                 background=theme.HEADER_BG).pack(side="right", padx=(12, 4))
        self.theme_btn = ttk.Button(right, style="Header.TButton", command=self.toggle_theme)
        self.theme_btn.pack(side="right")

    def _update_header(self) -> None:
        dark = theme.mode() == "dark"
        self.theme_btn.configure(text=("☀  " + _("Mode terang")) if dark else ("☾  " + _("Mode malam")))

    # --------------------------------------------------------------- actions
    def _send_to_topology(self, paths: list[str]) -> None:
        self.topo.add_paths(paths)
        self.nb.select(self.topo)

    def toggle_theme(self) -> None:
        new = "light" if theme.mode() == "dark" else "dark"
        theme.apply(self.root, new)
        self.prefs["theme"] = new
        settings.save(self.prefs)
        self._update_header()

    def busy(self) -> bool:
        return self.coll.running or self.ping.running or self.speed.running

    def set_language(self, lang: str) -> None:
        if lang == i18n.lang():
            return
        if self.busy():
            messagebox.showinfo(APP_NAME, _("Tunggu proses yang sedang berjalan selesai sebelum mengganti bahasa."))
            self.lang_box.set(next(k for k, v in LANGS.items() if v == i18n.lang()))
            return
        state = {key: getattr(self, key).get_state() for key, _label in self.TABS}
        state["tab"] = self.nb.index(self.nb.select())
        self.speed.shutdown()
        i18n.set_lang(lang)
        self.prefs["lang"] = lang
        settings.save(self.prefs)
        self.build(state)
        self.status_var.set(_("Bahasa diganti ke Bahasa Indonesia.") if lang == "id" else _("Bahasa diganti ke English."))

    def on_close(self) -> None:
        if self.coll.running and not messagebox.askyesno(APP_NAME, _("Pengambilan log masih berjalan. Keluar?")):
            return
        self.ping.stop()
        self.speed.stop_event.set()
        self.speed.shutdown()
        self.root.destroy()


def create_root() -> tk.Tk:
    return TkinterDnD.Tk() if HAS_DND else tk.Tk()


def main() -> None:
    root = create_root()
    App(root)
    root.mainloop()
