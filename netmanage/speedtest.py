"""Speed test: Internet (Cloudflare or a custom HTTP URL) and LAN (NetManage server <-> client).

Every test reports latency, jitter, download and upload in Mbps. Progress is sent through a
callback: on_progress(phase, mbps_now, elapsed_seconds).
"""
from __future__ import annotations

import http.client
import os
import socket
import ssl
import statistics
import threading
import time
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlsplit

CLOUDFLARE = "speed.cloudflare.com"
LAN_PORT = 5201
_CHUNK = 64 * 1024
_PAYLOAD = os.urandom(_CHUNK)
_MAGIC = b"NMSPEED1"


@dataclass
class SpeedResult:
    mode: str
    server: str
    ping_ms: float | None = None
    jitter_ms: float | None = None
    download_mbps: float | None = None
    upload_mbps: float | None = None
    download_bytes: int = 0
    upload_bytes: int = 0
    when: str = field(default_factory=lambda: time.strftime("%Y-%m-%d %H:%M:%S"))
    error: str = ""


Progress = Callable[[str, float, float], None]


def _noop(*_):
    pass


def _latency(samples: list[float]) -> tuple[float | None, float | None]:
    if not samples:
        return None, None
    jitter = statistics.mean(abs(a - b) for a, b in zip(samples, samples[1:])) if len(samples) > 1 else 0.0
    return statistics.median(samples), jitter


class _Meter:
    """Thread-safe byte counter with a live Mbps reading."""

    WARMUP = 1.0  # seconds not counted: TCP slow start and socket buffers filling

    def __init__(self, phase: str, on_progress: Progress):
        self.total = 0
        self.lock = threading.Lock()
        self.start = time.perf_counter() + self.WARMUP
        self.phase = phase
        self.on_progress = on_progress
        self._last = self.start
        self.end: float | None = None

    def finish(self) -> None:
        self.end = time.perf_counter()

    def add(self, n: int) -> None:
        with self.lock:
            now = time.perf_counter()
            if now < self.start:
                return
            self.total += n
            if now - self._last >= 0.25:
                self._last = now
                self.on_progress(self.phase, self.mbps(), now - self.start)

    def mbps(self) -> float:
        elapsed = max(min(time.perf_counter(), self.end or time.perf_counter()) - self.start, 1e-6)
        return self.total * 8 / elapsed / 1e6


def _run_streams(target, streams: int, duration: float, stop: threading.Event | None) -> list[str]:
    deadline = time.perf_counter() + duration
    errors: list[str] = []

    def worker():
        try:
            target(deadline, stop)
        except Exception as exc:  # noqa: BLE001 - one stream failing must not hide the others
            errors.append(f"{type(exc).__name__}: {exc}")

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(max(1, streams))]
    for t in threads:
        t.start()
    for t in threads:
        t.join(duration + 30)
    return errors


def _stopped(deadline: float, stop) -> bool:
    return time.perf_counter() >= deadline or (stop is not None and stop.is_set())


# ------------------------------------------------------------------ HTTP (Internet)
def _conn(host: str, port: int | None, https: bool, timeout: float = 10):
    if https:
        return http.client.HTTPSConnection(host, port or 443, timeout=timeout,
                                           context=ssl.create_default_context())
    return http.client.HTTPConnection(host, port or 80, timeout=timeout)


def http_test(url: str = "", duration: float = 10, streams: int = 4, do_upload: bool = True,
              on_progress: Progress = _noop, stop: threading.Event | None = None) -> SpeedResult:
    """Cloudflare speed test when url is empty, otherwise download from a custom URL.

    A custom URL measures download, and upload only when the server accepts POST."""
    cloudflare = not url
    if cloudflare:
        host, port, https = CLOUDFLARE, None, True
        down_path, up_path, ping_path = "/__down?bytes=25000000", "/__up", "/__down?bytes=0"
    else:
        u = urlsplit(url if "://" in url else f"http://{url}")
        host, port, https = u.hostname or "", u.port, u.scheme == "https"
        down_path = (u.path or "/") + (f"?{u.query}" if u.query else "")
        up_path = ping_path = down_path
    res = SpeedResult(mode="Internet (Cloudflare)" if cloudflare else "HTTP URL",
                      server=CLOUDFLARE if cloudflare else url)
    try:
        # latency: request time on a kept-alive connection (first one includes TCP/TLS setup)
        samples = []
        c = _conn(host, port, https)
        for i in range(8):
            if stop is not None and stop.is_set():
                break
            t0 = time.perf_counter()
            c.request("GET", ping_path, headers={} if cloudflare else {"Range": "bytes=0-0"})
            r = c.getresponse()
            r.read()
            if i:
                samples.append((time.perf_counter() - t0) * 1000)
        c.close()
        res.ping_ms, res.jitter_ms = _latency(samples)
        on_progress("ping", res.ping_ms or 0, 0)

        meter = _Meter("download", on_progress)

        def down(deadline, stop):
            conn = _conn(host, port, https, 15)
            try:
                while not _stopped(deadline, stop):
                    conn.request("GET", down_path)
                    resp = conn.getresponse()
                    if resp.status >= 400:
                        raise RuntimeError(f"HTTP {resp.status} dari server")
                    finished = True
                    while True:
                        if _stopped(deadline, stop):
                            finished = False
                            break
                        chunk = resp.read(_CHUNK)
                        if not chunk:
                            break
                        meter.add(len(chunk))
                    if not finished:
                        break
            finally:
                conn.close()

        errors = _run_streams(down, streams, duration, stop)
        meter.finish()
        res.download_bytes, res.download_mbps = meter.total, meter.mbps()
        if errors and not meter.total:
            raise RuntimeError(errors[0])

        if do_upload and not (stop and stop.is_set()):
            meter = _Meter("upload", on_progress)
            size = 8 * 1024 * 1024

            def up(deadline, stop):
                conn = _conn(host, port, https, 15)
                try:
                    while not _stopped(deadline, stop):
                        conn.putrequest("POST", up_path)
                        conn.putheader("Content-Type", "application/octet-stream")
                        conn.putheader("Content-Length", str(size))
                        conn.endheaders()
                        sent = 0
                        while sent < size and not _stopped(deadline, stop):
                            conn.send(_PAYLOAD)
                            sent += len(_PAYLOAD)
                            meter.add(len(_PAYLOAD))
                        if sent < size:
                            break
                        resp = conn.getresponse()
                        resp.read()
                        if resp.status >= 400:
                            raise RuntimeError(f"HTTP {resp.status}")
                finally:
                    conn.close()

            errors = _run_streams(up, streams, duration, stop)
            meter.finish()
            res.upload_bytes, res.upload_mbps = meter.total, meter.mbps()
            if errors and not cloudflare:
                res.upload_mbps = None
                res.error = "Upload tidak didukung server URL ini (POST ditolak)."
    except (OSError, http.client.HTTPException, RuntimeError, ssl.SSLError) as exc:
        res.error = f"{type(exc).__name__}: {exc}"
    return res


# ------------------------------------------------------------------ LAN server/client
class LanServer:
    """Minimal speed-test server. Start on one laptop, run the LAN client from another."""

    def __init__(self, host: str = "0.0.0.0", port: int = LAN_PORT, log: Callable[[str], None] = _noop):
        self.host, self.port, self.log = host, port, log
        self.sock: socket.socket | None = None
        self.running = False

    def start(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(32)
        self.running = True
        threading.Thread(target=self._accept, daemon=True).start()
        self.log(f"Server speed test aktif di port {self.port}")

    def stop(self) -> None:
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
        self.log("Server speed test berhenti")

    def _accept(self) -> None:
        while self.running:
            try:
                conn, addr = self.sock.accept()
            except OSError:
                break
            threading.Thread(target=self._serve, args=(conn, addr), daemon=True).start()

    def _serve(self, conn: socket.socket, addr) -> None:
        with conn:
            try:
                conn.settimeout(30)
                parts = _recv_line(conn).split()
                if len(parts) < 2 or parts[0].encode() != _MAGIC:
                    return
                mode = parts[1]
                if mode == "ping":
                    while True:
                        data = conn.recv(64)
                        if not data:
                            break
                        conn.sendall(data)
                elif mode == "down":
                    end = time.perf_counter() + min(float(parts[2]), 120)
                    while time.perf_counter() < end:
                        conn.sendall(_PAYLOAD)
                elif mode == "up":
                    total = 0
                    while True:
                        data = conn.recv(_CHUNK)
                        if not data:
                            break
                        total += len(data)
                    self.log(f"Upload dari {addr[0]}: {total * 8 / 1e6:.1f} Mbit diterima")
            except (OSError, ValueError):
                pass


def _recv_line(conn: socket.socket) -> str:
    buf = b""
    while not buf.endswith(b"\n") and len(buf) < 256:
        ch = conn.recv(1)
        if not ch:
            break
        buf += ch
    return buf.decode(errors="replace").strip()


def lan_test(server: str, port: int = LAN_PORT, duration: float = 10, streams: int = 4,
             on_progress: Progress = _noop, stop: threading.Event | None = None) -> SpeedResult:
    res = SpeedResult(mode="LAN (NetManage)", server=f"{server}:{port}")
    try:
        with socket.create_connection((server, port), timeout=5) as s:
            s.sendall(_MAGIC + b" ping\n")
            samples = []
            for _ in range(10):
                t0 = time.perf_counter()
                s.sendall(b"x" * 32)
                got = 0
                while got < 32:
                    data = s.recv(64)
                    if not data:
                        raise ConnectionError("server menutup koneksi")
                    got += len(data)
                samples.append((time.perf_counter() - t0) * 1000)
        res.ping_ms, res.jitter_ms = _latency(samples)
        on_progress("ping", res.ping_ms or 0, 0)

        meter = _Meter("download", on_progress)

        def down(deadline, stop):
            with socket.create_connection((server, port), timeout=10) as s:
                s.sendall(_MAGIC + f" down {duration}\n".encode())
                while not _stopped(deadline, stop):
                    data = s.recv(_CHUNK)
                    if not data:
                        break
                    meter.add(len(data))

        errors = _run_streams(down, streams, duration, stop)
        meter.finish()
        res.download_bytes, res.download_mbps = meter.total, meter.mbps()
        if errors and not meter.total:
            raise ConnectionError(errors[0])

        if not (stop and stop.is_set()):
            meter = _Meter("upload", on_progress)

            def up(deadline, stop):
                with socket.create_connection((server, port), timeout=10) as s:
                    s.sendall(_MAGIC + b" up\n")
                    while not _stopped(deadline, stop):
                        s.sendall(_PAYLOAD)
                        meter.add(len(_PAYLOAD))

            _run_streams(up, streams, duration, stop)
            meter.finish()
            res.upload_bytes, res.upload_mbps = meter.total, meter.mbps()
    except OSError as exc:
        res.error = f"{type(exc).__name__}: {exc}"
    return res


def local_ips() -> list[str]:
    ips = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(info[4][0])
    except OSError:
        pass
    return sorted(ip for ip in ips if not ip.startswith("127."))


def history_csv(results: list[SpeedResult]) -> str:
    rows = ["waktu,mode,server,ping_ms,jitter_ms,download_mbps,upload_mbps,error"]

    def f(v):
        return f"{v:.2f}" if isinstance(v, float) else ""

    for r in results:
        rows.append(",".join(f'"{x}"' for x in (r.when, r.mode, r.server, f(r.ping_ms), f(r.jitter_ms),
                                                 f(r.download_mbps), f(r.upload_mbps), r.error)))
    return "\n".join(rows) + "\n"
