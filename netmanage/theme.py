"""Light / dark theme: sv-ttk base, rounded blue buttons, and colors for plain Tk widgets."""
from __future__ import annotations

import ctypes
import sys
import tkinter as tk
from tkinter import ttk
from typing import Callable

from .paths import resource_dir

PALETTE = {
    "light": {
        "bg": "#F5F7FA", "surface": "#FFFFFF", "text": "#0F172A", "muted": "#64748B", "border": "#D7DFEA",
        "accent": "#2563EB", "accent2": "#F59E0B", "select": "#BFDBFE", "select_fg": "#0F172A",
        "ok": "#15803D", "err": "#DC2626", "warn": "#B45309", "run": "#2563EB", "purple": "#7C3AED",
        "track": "#E2E8F0", "status": "#E8EEF6", "card": "#FFFFFF",
        "canvas_text": "#334155", "canvas_lan": "#E2E8F0", "canvas_ext": "#F5F3FF",
    },
    "dark": {
        "bg": "#1C1C1C", "surface": "#242424", "text": "#E5E7EB", "muted": "#9CA3AF", "border": "#3A3A3A",
        "accent": "#3B82F6", "accent2": "#F59E0B", "select": "#264F78", "select_fg": "#F8FAFC",
        "ok": "#4ADE80", "err": "#F87171", "warn": "#FBBF24", "run": "#60A5FA", "purple": "#C4B5FD",
        "track": "#333333", "status": "#202020", "card": "#262626",
        "canvas_text": "#D1D5DB", "canvas_lan": "#333333", "canvas_ext": "#2E1065",
    },
}
HEADER_BG = "#0B1A33"  # brand color, same in both themes (matches the logo background)
HEADER_FG = "#F8FAFC"
HEADER_SUB = "#7DD3FC"

_mode = "light"
_root: tk.Misc | None = None
_images: dict[str, tk.PhotoImage] = {}
_elements: set[tuple[str, str]] = set()
_widgets: list[tuple[tk.Misc, str]] = []
_listeners: list[Callable[[], None]] = []


def mode() -> str:
    return _mode


def c(key: str) -> str:
    """Color of the current theme."""
    return PALETTE[_mode][key]


def asset(name: str) -> str:
    return str(resource_dir() / "assets" / name)


def image(name: str) -> tk.PhotoImage:
    if name not in _images:
        _images[name] = tk.PhotoImage(file=asset(name))
    return _images[name]


def register(widget: tk.Misc, kind: str) -> tk.Misc:
    """Plain Tk widget that follows the theme. kind: text | readonly | list | canvas."""
    _widgets.append((widget, kind))
    _style_widget(widget, kind)
    return widget


def card(parent: tk.Misc, padx: int = 14, pady: int = 10) -> tk.Frame:
    """Bordered surface panel that follows the theme."""
    frame = tk.Frame(parent, padx=padx, pady=pady)
    register(frame, "card")
    return frame


def card_label(parent: tk.Misc, text: str, role: str = "value") -> tk.Label:
    """Label inside a card. role: title | value | unit."""
    label = tk.Label(parent, text=text, borderwidth=0)
    register(label, f"cardlabel:{role}")
    return label


def on_change(callback: Callable[[], None]) -> None:
    _listeners.append(callback)


def reset_listeners() -> None:
    _widgets.clear()
    _listeners.clear()


def _style_widget(w: tk.Misc, kind: str) -> None:
    p = PALETTE[_mode]
    try:
        if kind in ("text", "readonly"):
            w.configure(background=p["surface"] if kind == "text" else p["bg"], foreground=p["text"],
                        insertbackground=p["text"], selectbackground=p["select"],
                        selectforeground=p["select_fg"], highlightthickness=1,
                        highlightbackground=p["border"], highlightcolor=p["accent"], relief="flat",
                        borderwidth=0, padx=6, pady=4)
        elif kind == "list":
            w.configure(background=p["surface"], foreground=p["text"], selectbackground=p["select"],
                        selectforeground=p["select_fg"], highlightthickness=1,
                        highlightbackground=p["border"], relief="flat", borderwidth=0)
        elif kind == "canvas":
            w.configure(background=p["surface"], highlightthickness=1, highlightbackground=p["border"])
        elif kind == "cardfill":
            w.configure(background=p["card"])
        elif kind.startswith("cardlabel:"):
            role = kind.split(":", 1)[1]
            w.configure(background=p["card"], foreground=p["muted"] if role in ("title", "unit") else p["text"],
                        font={"title": ("Segoe UI Semibold", 9), "unit": ("Segoe UI", 9),
                              "value": ("Segoe UI Semibold", 22)}[role])
        elif kind == "card":
            w.configure(background=p["card"], highlightthickness=1, highlightbackground=p["border"],
                        highlightcolor=p["border"], borderwidth=0)
    except tk.TclError:
        pass


def _button_element(style: ttk.Style, kind: str, skin: str) -> str:
    """Rounded 9-slice image element; created once per ttk theme."""
    name = f"NM{kind}.{skin}.border"
    key = (style.theme_use(), name)
    if key not in _elements:
        imgs = {s: image(f"{kind}_{skin}_{s}.png") for s in ("normal", "hover", "pressed", "disabled")}
        style.element_create(name, "image", imgs["normal"], ("disabled", imgs["disabled"]),
                             ("pressed", imgs["pressed"]), ("active", imgs["hover"]),
                             border=12, padding=(12, 5), sticky="nsew")
        _elements.add(key)
    return name


def _layout(element: str) -> list:
    return [(element, {"sticky": "nsew", "children": [
        ("Button.padding", {"sticky": "nsew", "children": [("Button.label", {"sticky": "nsew"})]})]})]


def apply(root: tk.Tk, new_mode: str) -> None:
    global _mode, _root
    _mode = new_mode if new_mode in PALETTE else "light"
    if _root is not root:  # images and elements belong to one Tk interpreter
        _images.clear()
        _elements.clear()
        _root = root
    try:
        import sv_ttk
        sv_ttk.set_theme(_mode)
    except Exception:  # noqa: BLE001 - fall back to the stock theme
        pass
    p = PALETTE[_mode]
    style = ttk.Style(root)
    font = ("Segoe UI Semibold", 9)
    style.configure(".", background=p["bg"], foreground=p["text"])
    for name in ("TFrame", "TLabel", "TLabelframe", "TLabelframe.Label", "TCheckbutton", "TRadiobutton",
                 "TPanedwindow"):
        style.configure(name, background=p["bg"])
    style.configure("TLabelframe.Label", foreground=p["muted"], font=("Segoe UI Semibold", 9))
    blue = _button_element(style, "btn", _mode)
    for name in ("TButton", "Accent.TButton"):
        style.layout(name, _layout(blue))
        style.configure(name, foreground="#FFFFFF", font=font, padding=(4, 1), anchor="center")
        style.map(name, foreground=[("disabled", "#E2E8F0" if _mode == "light" else "#7B8BA8")])
    ghost = _button_element(style, "ghost", _mode)
    style.layout("Ghost.TButton", _layout(ghost))
    style.configure("Ghost.TButton", foreground=p["text"], font=font, padding=(8, 1), anchor="center")
    header = _button_element(style, "ghost", "header")
    style.layout("Header.TButton", _layout(header))
    style.configure("Header.TButton", foreground=HEADER_FG, font=font, padding=(6, 2), anchor="center")
    style.configure("Muted.TLabel", foreground=p["muted"])
    style.configure("Accent.TLabel", foreground=p["accent"])
    style.configure("Status.TLabel", background=p["status"], foreground=p["muted"], padding=(10, 4))
    style.configure("Card.TFrame", background=p["card"])
    style.configure("CardTitle.TLabel", background=p["card"], foreground=p["muted"],
                    font=("Segoe UI Semibold", 9))
    style.configure("CardValue.TLabel", background=p["card"], foreground=p["text"],
                    font=("Segoe UI Semibold", 22))
    style.configure("CardUnit.TLabel", background=p["card"], foreground=p["muted"])
    style.configure("Treeview", rowheight=26)
    style.configure("TNotebook.Tab", padding=(14, 6))
    root.configure(background=p["bg"])
    for w, kind in list(_widgets):
        _style_widget(w, kind)
    for cb in list(_listeners):
        try:
            cb()
        except tk.TclError:
            pass
    dark_titlebar(root, _mode == "dark")


def dark_titlebar(root: tk.Tk, dark: bool) -> None:
    """Windows 10/11: match the title bar to the theme."""
    if sys.platform != "win32":
        return
    try:
        root.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
        value = ctypes.c_int(1 if dark else 0)
        for attr in (20, 19):  # DWMWA_USE_IMMERSIVE_DARK_MODE (new / old builds)
            if ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, attr, ctypes.byref(value),
                                                          ctypes.sizeof(value)) == 0:
                break
        root.wm_attributes("-alpha", 0.999)  # force the frame to repaint
        root.wm_attributes("-alpha", 1.0)
    except (AttributeError, OSError, tk.TclError):
        pass
