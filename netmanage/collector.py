"""Multi-device, multi-vendor log collector (SSH/Telnet through netmiko)."""
from __future__ import annotations

import csv
import json
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable

from .paths import app_dir

# vendor -> netmiko types, command that prints the config, default command set
PROFILES: dict[str, dict] = {
    "cisco_ios": {
        "ssh": "cisco_ios", "telnet": "cisco_ios_telnet", "config": "show running-config",
        "commands": ["show version", "show running-config", "show ip interface brief",
                     "show interfaces description", "show ip route", "show ip ospf neighbor",
                     "show ip bgp summary", "show cdp neighbors", "show logging"],
    },
    "juniper_junos": {
        "ssh": "juniper_junos", "telnet": "juniper_junos_telnet",
        "config": "show configuration | display set",
        "commands": ["show version", "show configuration | display set", "show interfaces terse",
                     "show route", "show ospf neighbor", "show bgp summary", "show lldp neighbors",
                     "show log messages | last 200"],
    },
    "mikrotik_ros": {
        "ssh": "mikrotik_routeros", "telnet": None, "config": "/export",
        "commands": ["/system resource print", "/export", "/interface print", "/ip address print",
                     "/ip route print", "/routing ospf neighbor print", "/routing bgp session print",
                     "/log print"],
    },
    "huawei_vrp": {
        "ssh": "huawei", "telnet": "huawei_telnet", "config": "display current-configuration",
        "commands": ["display version", "display current-configuration", "display ip interface brief",
                     "display interface description", "display ip routing-table",
                     "display ospf peer brief", "display bgp peer", "display lldp neighbor brief",
                     "display logbuffer"],
    },
    "fortinet_fortios": {
        "ssh": "fortinet", "telnet": None, "config": "show",
        "commands": ["get system status", "show", "get system interface physical",
                     "get router info routing-table all", "get router info ospf neighbor",
                     "get router info bgp summary", "execute log display"],
    },
    "arista_eos": {
        "ssh": "arista_eos", "telnet": "arista_eos_telnet", "config": "show running-config",
        "commands": ["show version", "show running-config", "show ip interface brief",
                     "show interfaces description", "show ip route", "show ip ospf neighbor",
                     "show ip bgp summary", "show lldp neighbors", "show logging"],
    },
    "h3c_comware": {
        "ssh": "hp_comware", "telnet": "hp_comware_telnet", "config": "display current-configuration",
        "commands": ["display version", "display current-configuration", "display ip interface brief",
                     "display interface brief", "display ip routing-table", "display ospf peer",
                     "display bgp peer ipv4", "display lldp neighbor-information list",
                     "display logbuffer"],
    },
    "nokia_sros": {
        "ssh": "nokia_sros", "telnet": "nokia_sros_telnet", "config": "admin display-config",
        "commands": ["show version", "admin display-config", "show router interface", "show port",
                     "show router route-table", "show router ospf neighbor",
                     "show router bgp summary", "show log log-id 99"],
    },
    "vyos": {
        "ssh": "vyos", "telnet": None, "config": "show configuration commands",
        "commands": ["show version", "show configuration commands", "show interfaces",
                     "show ip route", "show ip ospf neighbor", "show ip bgp summary",
                     "show log tail 200"],
    },
    "aruba_aoscx": {
        "ssh": "aruba_aoscx", "telnet": None, "config": "show running-config",
        "commands": ["show version", "show running-config", "show ip interface brief",
                     "show interface brief", "show ip route", "show ip ospf neighbors",
                     "show bgp ipv4 unicast summary", "show lldp neighbor-info",
                     "show logging -r -n 200"],
    },
}

INVENTORY_FIELDS = ["host", "ip", "vendor", "port", "protocol", "username", "password"]
COMMANDS_FILE = "commands.json"


@dataclass
class Target:
    host: str
    ip: str
    vendor: str
    port: int = 22
    protocol: str = "ssh"
    username: str = ""
    password: str = ""
    secret: str = ""

    @property
    def label(self) -> str:
        return self.host or self.ip


# ------------------------------------------------------------------ commands
def default_commands() -> dict[str, list[str]]:
    return {v: list(p["commands"]) for v, p in PROFILES.items()}


def load_commands() -> dict[str, list[str]]:
    """Command sets: defaults overridden by commands.json next to the EXE."""
    commands = default_commands()
    path = app_dir() / COMMANDS_FILE
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            for vendor, cmds in data.items():
                if vendor in commands and isinstance(cmds, list):
                    commands[vendor] = [str(c) for c in cmds if str(c).strip()]
        except (OSError, ValueError):
            pass
    return commands


def save_commands(commands: dict[str, list[str]]) -> Path:
    path = app_dir() / COMMANDS_FILE
    path.write_text(json.dumps(commands, indent=2), encoding="utf-8")
    return path


# ----------------------------------------------------------------- inventory
def load_inventory(path: str | Path) -> list[Target]:
    targets: list[Target] = []
    with open(path, newline="", encoding="utf-8-sig") as fh:
        sample = fh.read(2048)
        fh.seek(0)
        delimiter = ";" if sample.count(";") > sample.count(",") else ","
        for row in csv.DictReader(fh, delimiter=delimiter):
            row = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
            ip = row.get("ip") or row.get("address") or row.get("host", "")
            if not ip:
                continue
            vendor = row.get("vendor", "")
            protocol = (row.get("protocol") or "ssh").lower()
            port = row.get("port", "")
            targets.append(Target(
                host=row.get("host") or row.get("hostname") or ip, ip=ip, vendor=vendor,
                port=int(port) if port.isdigit() else (23 if protocol == "telnet" else 22),
                protocol=protocol, username=row.get("username", ""), password=row.get("password", ""),
                secret=row.get("secret", "")))
    return targets


def save_inventory(path: str | Path, targets: list[Target]) -> None:
    """Passwords are never written to disk."""
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=INVENTORY_FIELDS)
        writer.writeheader()
        for t in targets:
            writer.writerow({"host": t.host, "ip": t.ip, "vendor": t.vendor, "port": t.port,
                             "protocol": t.protocol, "username": t.username, "password": ""})


# ------------------------------------------------------------------- collect
def _safe(name: str) -> str:
    return re.sub(r"[^\w.\-]+", "_", name).strip("_") or "device"


def _netmiko_connect(**kwargs):
    from netmiko import ConnectHandler
    return ConnectHandler(**kwargs)


def _friendly(exc: Exception) -> str:
    name = type(exc).__name__
    text = str(exc).strip().split("\n")[0]
    if "Authentication" in name:
        return "Login gagal (username/password salah)"
    if "Timeout" in name or "timed out" in text.lower():
        return "Timeout: device tidak merespon (cek IP, port, firewall)"
    if "refused" in text.lower():
        return "Koneksi ditolak (port tertutup atau SSH/Telnet belum aktif)"
    return f"{name}: {text}"[:200]


def collect_one(target: Target, commands: list[str], out_dir: Path, timeout: int = 60,
                on_event: Callable[[str, Target, str], None] | None = None,
                stop: threading.Event | None = None, connect=_netmiko_connect) -> Path:
    """Run every command on one device and write the log file. Raises on connection errors."""
    emit = on_event or (lambda *_: None)
    profile = PROFILES.get(target.vendor)
    if profile is None:
        raise ValueError(f"Vendor tidak dikenal: {target.vendor!r}")
    device_type = profile.get(target.protocol)
    if not device_type:
        raise ValueError(f"{target.vendor} tidak mendukung {target.protocol}")
    emit("connect", target, f"{target.protocol.upper()} {target.ip}:{target.port}")
    conn = connect(device_type=device_type, host=target.ip, port=target.port,
                   username=target.username, password=target.password,
                   secret=target.secret or target.password, conn_timeout=15, banner_timeout=20,
                   auth_timeout=20, fast_cli=False)
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sections = [f"# Device : {target.label} ({target.ip})", f"# Vendor : {target.vendor}",
                f"# Waktu  : {stamp}", ""]
    config_text = ""
    try:
        if target.secret:
            try:
                conn.enable()
            except Exception:  # noqa: BLE001 - not every platform has enable mode
                pass
        for cmd in commands:
            if stop is not None and stop.is_set():
                sections.append("# Dibatalkan oleh user")
                break
            emit("command", target, cmd)
            try:
                output = conn.send_command(cmd, read_timeout=timeout, strip_prompt=True,
                                           strip_command=True)
            except Exception as exc:  # noqa: BLE001 - prompt detection can fail per command
                try:
                    output = conn.send_command_timing(cmd, read_timeout=timeout)
                except Exception:  # noqa: BLE001
                    output = f"!! GAGAL: {_friendly(exc)}"
            sections += [f"{'=' * 20} {cmd} {'=' * 20}", str(output).rstrip(), ""]
            if cmd.strip() == profile["config"]:
                config_text = str(output)
    finally:
        try:
            conn.disconnect()
        except Exception:  # noqa: BLE001
            pass
    out_dir.mkdir(parents=True, exist_ok=True)
    base = _safe(f"{target.label}_{target.ip}" if target.label != target.ip else target.ip)
    path = out_dir / f"{base}.log"
    path.write_text("\n".join(sections), encoding="utf-8")
    if config_text.strip():
        cfg_dir = out_dir / "configs"
        cfg_dir.mkdir(exist_ok=True)
        (cfg_dir / f"{_safe(target.label)}.cfg").write_text(config_text, encoding="utf-8")
    return path


def collect(targets: list[Target], commands: dict[str, list[str]], out_dir: Path, workers: int = 5,
            timeout: int = 60, on_event: Callable[[str, Target, str], None] | None = None,
            stop: threading.Event | None = None, connect=_netmiko_connect) -> dict[str, str]:
    """Collect from many devices in parallel. Returns {label: 'ok' | error text}."""
    emit = on_event or (lambda *_: None)
    results: dict[str, str] = {}

    def job(target: Target) -> None:
        if stop is not None and stop.is_set():
            results[target.label] = "dibatalkan"
            emit("error", target, "Dibatalkan")
            return
        try:
            path = collect_one(target, commands.get(target.vendor, []), out_dir, timeout,
                               on_event, stop, connect)
            results[target.label] = "ok"
            emit("done", target, str(path))
        except Exception as exc:  # noqa: BLE001 - one device must not stop the batch
            results[target.label] = _friendly(exc)
            emit("error", target, results[target.label])

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        list(pool.map(job, targets))
    return results


def new_run_dir(base: Path) -> Path:
    path = base / "logs" / datetime.now().strftime("%Y%m%d-%H%M%S")
    path.mkdir(parents=True, exist_ok=True)
    return path
