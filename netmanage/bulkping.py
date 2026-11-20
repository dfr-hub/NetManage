"""Bulk ping: many targets in parallel through the system 'ping' command.

The system command is used (not raw ICMP sockets) so the app needs no administrator
rights. Reply lines are detected by 'TTL=', which works for every Windows language.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable

MAX_TARGETS = 4096
_RTT = re.compile(r"[=<]\s*(\d+(?:[.,]\d+)?)\s*ms", re.I)
_TTL = re.compile(r"ttl[=:]\s*(\d+)", re.I)
_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0


@dataclass
class PingResult:
    target: str
    label: str = ""
    sent: int = 0
    received: int = 0
    rtts: list[float] = field(default_factory=list)
    ttl: int | None = None
    error: str = ""

    @property
    def loss(self) -> float:
        return 100.0 * (self.sent - self.received) / self.sent if self.sent else 100.0

    @property
    def status(self) -> str:
        if self.error and not self.received:
            return "ERROR"
        if self.received == 0:
            return "DOWN"
        return "UP" if self.received == self.sent else "PARTIAL"

    def stat(self, kind: str) -> float | None:
        if not self.rtts:
            return None
        if kind == "min":
            return min(self.rtts)
        if kind == "max":
            return max(self.rtts)
        return sum(self.rtts) / len(self.rtts)


def parse_targets(text: str) -> list[tuple[str, str]]:
    """Targets from free text. Returns [(address, label)].

    Accepts one item per line or separated by comma/space:
      10.0.0.1 | router1.lab | 10.0.0.0/28 | 10.0.0.1-20 | 10.0.0.1-10.0.0.20 | 'NAME,10.0.0.1' (CSV)
    """
    out: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(addr: str, label: str = "") -> None:
        if addr not in seen:
            seen.add(addr)
            out.append((addr, label))
        if len(out) > MAX_TARGETS:
            raise ValueError(f"Lebih dari {MAX_TARGETS} target. Persempit range/subnet.")

    for raw in text.replace("\r", "").split("\n"):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        cells = [c.strip() for c in re.split(r"[;,\t]", line) if c.strip()]
        # CSV row "name,ip,..." -> use the first cell that looks like an address
        if len(cells) > 1 and not _looks_like_target(cells[0]) and any(_is_ip(c) for c in cells[1:]):
            ip = next(c for c in cells[1:] if _is_ip(c))
            add(ip, cells[0])
            continue
        for item in (cells if len(cells) > 1 else line.split()):
            _expand(item, add)
    return out


def _is_ip(text: str) -> bool:
    try:
        ipaddress.IPv4Address(text)
        return True
    except ValueError:
        return False


def _looks_like_target(text: str) -> bool:
    return _is_ip(text) or "/" in text or bool(re.match(r"^\d+\.\d+\.\d+\.\d+-", text))


def _expand(item: str, add) -> None:
    item = item.strip()
    if not item or item.lower() in ("host", "ip", "address", "hostname"):
        return
    if "/" in item:
        net = ipaddress.ip_network(item, strict=False)
        if net.num_addresses > MAX_TARGETS + 2:
            raise ValueError(f"Subnet {item} terlalu besar (maks /{32 - MAX_TARGETS.bit_length() + 1}).")
        hosts = list(net.hosts()) if net.prefixlen < 31 else list(net)
        for h in hosts:
            add(str(h))
        return
    m = re.match(r"^(\d+\.\d+\.\d+\.)(\d+)-(\d+)$", item)
    if m:
        a, b = int(m.group(2)), int(m.group(3))
        for n in range(min(a, b), min(max(a, b), 255) + 1):
            add(f"{m.group(1)}{n}")
        return
    m = re.match(r"^(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)$", item)
    if m:
        a, b = int(ipaddress.IPv4Address(m.group(1))), int(ipaddress.IPv4Address(m.group(2)))
        if abs(b - a) > MAX_TARGETS:
            raise ValueError(f"Range {item} terlalu besar.")
        for n in range(min(a, b), max(a, b) + 1):
            add(str(ipaddress.IPv4Address(n)))
        return
    if re.fullmatch(r"[A-Za-z0-9._\-]+", item):
        add(item)
        return
    raise ValueError(f"Target tidak dikenali: {item}")


def _command(target: str, count: int, timeout_ms: int, size: int) -> list[str]:
    if sys.platform == "win32":
        return ["ping", "-n", str(count), "-w", str(timeout_ms), "-l", str(size), target]
    return ["ping", "-c", str(count), "-W", str(max(1, timeout_ms // 1000)), "-s", str(size), target]


def ping_host(target: str, count: int = 4, timeout_ms: int = 1000, size: int = 32, label: str = "",
              stop: threading.Event | None = None, runner=subprocess.run) -> PingResult:
    res = PingResult(target=target, label=label, sent=count)
    try:
        proc = runner(_command(target, count, timeout_ms, size), capture_output=True, text=True,
                      stdin=subprocess.DEVNULL,  # windowed EXE has no valid console stdin
                      timeout=count * (timeout_ms / 1000 + 1) + 5, creationflags=_NO_WINDOW,
                      encoding="utf-8", errors="replace")
        output = proc.stdout or ""
    except subprocess.TimeoutExpired:
        res.error = "timeout proses ping"
        return res
    except OSError as exc:
        res.error = str(exc)
        return res
    for line in output.splitlines():
        ttl = _TTL.search(line)
        if not ttl:
            continue
        res.received += 1
        res.ttl = int(ttl.group(1))
        rtt = _RTT.search(line)
        if rtt:
            value = float(rtt.group(1).replace(",", "."))
            res.rtts.append(value / 2 if "<" in rtt.group(0) else value)  # 'time<1ms' -> 0.5
    res.received = min(res.received, count)
    # no IP anywhere in the output = the name did not resolve (any Windows language)
    if not res.received and output.strip() and not re.search(r"\d+\.\d+\.\d+\.\d+", output):
        res.error = output.strip().splitlines()[-1][:120]
    if not output.strip():
        res.error = "tidak ada output dari perintah ping"
    return res


def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return ""


def run(targets: list[tuple[str, str]], count: int = 4, timeout_ms: int = 1000, size: int = 32,
        workers: int = 50, on_result: Callable[[PingResult], None] | None = None,
        stop: threading.Event | None = None, resolve: bool = False, runner=subprocess.run) -> list[PingResult]:
    results: list[PingResult] = []
    lock = threading.Lock()

    def job(item):
        addr, label = item
        if stop is not None and stop.is_set():
            return
        r = ping_host(addr, count, timeout_ms, size, label, stop, runner)
        if resolve and not r.label and _is_ip(addr) and r.received:
            r.label = reverse_dns(addr)
        with lock:
            results.append(r)
        if on_result:
            on_result(r)

    with ThreadPoolExecutor(max_workers=max(1, min(workers, 256))) as pool:
        list(pool.map(job, targets))
    return results


def to_csv(results: list[PingResult]) -> str:
    rows = ["target,nama,status,sent,received,loss_pct,min_ms,avg_ms,max_ms,ttl,error"]
    for r in results:
        vals = [r.target, r.label, r.status, r.sent, r.received, f"{r.loss:.0f}",
                *(f"{r.stat(k):.1f}" if r.stat(k) is not None else "" for k in ("min", "avg", "max")),
                r.ttl if r.ttl is not None else "", r.error]
        rows.append(",".join(f'"{v}"' for v in vals))
    return "\n".join(rows) + "\n"
