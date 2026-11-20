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
_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NetManage-SpeedTest"


@dataclass
class Endpoint:
    """One internet speed-test target.

    down: URL fetched repeatedly for download. up: URL for upload (POST), empty = download only.
    ping: small URL for latency (empty = 1-byte range request on the download URL).
    form: upload body sent as 'content1=...' form data (legacy Speedtest.net servers)."""
    provider: str
    name: str
    down: str
    up: str = ""
    ping: str = ""
    form: bool = False
    location: str = ""

    @property
    def label(self) -> str:
        return f"{self.name} ({self.location})" if self.location else self.name


CLOUDFLARE_EP = Endpoint("cloudflare", "Cloudflare", f"https://{CLOUDFLARE}/__down?bytes=25000000",
                         f"https://{CLOUDFLARE}/__up", f"https://{CLOUDFLARE}/__down?bytes=0",
                         location="auto")

# download-only public test files (checked reachable; 100 MB each)
MIRRORS = [
    Endpoint("mirror", "Vultr", "https://sgp-ping.vultr.com/vultr.com.100MB.bin", location="Singapore"),
    Endpoint("mirror", "Hetzner", "https://sin-speed.hetzner.com/100MB.bin", location="Singapore"),
    Endpoint("mirror", "Vultr", "https://hnd-jp-ping.vultr.com/vultr.com.100MB.bin", location="Tokyo"),
    Endpoint("mirror", "Vultr", "https://syd-au-ping.vultr.com/vultr.com.100MB.bin", location="Sydney"),
    Endpoint("mirror", "Vultr", "https://fra-de-ping.vultr.com/vultr.com.100MB.bin", location="Frankfurt"),
    Endpoint("mirror", "Hetzner", "https://nbg1-speed.hetzner.com/100MB.bin", location="Nuremberg"),
    Endpoint("mirror", "OVH", "https://proof.ovh.net/files/100Mb.dat", location="Roubaix, France"),
    Endpoint("mirror", "Hetzner", "https://ash-speed.hetzner.com/100MB.bin", location="Ashburn, USA"),
]

OOKLA_API = "https://www.speedtest.net/api/js/servers?engine=js&limit={limit}&https_functional=true"
LIBRESPEED_LIST = "https://librespeed.org/backend-servers/servers.php"


def _get_json(url: str, timeout: float = 10):
    import json
    from urllib.request import Request, urlopen
    with urlopen(Request(url, headers={"User-Agent": _UA}), timeout=timeout,
                 context=ssl.create_default_context()) as r:
        return json.loads(r.read(2_000_000).decode("utf-8", errors="replace"))


def ookla_servers(search: str = "", limit: int = 30) -> list[Endpoint]:
    """Speedtest.net servers: nearest to this connection, or matching a city / ISP name."""
    from urllib.parse import quote
    url = OOKLA_API.format(limit=limit) + (f"&search={quote(search.strip())}" if search.strip() else "")
    out = []
    for s in _get_json(url):
        up = s.get("url", "")
        if not up.endswith("upload.php"):
            continue
        base = up[: -len("upload.php")]
        dist = s.get("distance")
        where = ", ".join(x for x in (s.get("name", ""), s.get("country", "")) if x)
        if dist is not None:
            where += f" - {dist} km"
        out.append(Endpoint("ookla", s.get("sponsor", "?"), base + "random4000x4000.jpg", up,
                            base + "latency.txt", form=True, location=where))
    return out


def librespeed_servers() -> list[Endpoint]:
    """Public LibreSpeed servers (open source speed-test backends)."""
    out = []
    for s in _get_json(LIBRESPEED_LIST):
        server = s.get("server", "")
        if not server:
            continue
        if server.startswith("//"):
            server = "https:" + server
        base = server if server.endswith("/") else server + "/"
        name = s.get("name", server)
        place, _, host = name.partition(" (")
        out.append(Endpoint("librespeed", host.rstrip(")") or name,
                            base + s.get("dlURL", "garbage.php") + "?ckSize=100",
                            base + s.get("ulURL", "empty.php"), base + s.get("pingURL", "empty.php"),
                            location=place))
    return sorted(out, key=lambda e: e.location)


def custom_endpoint(down: str, up: str = "") -> Endpoint:
    def norm(u):
        u = u.strip()
        return u if not u or "://" in u else "http://" + u
    return Endpoint("custom", norm(down), norm(down), norm(up))


class _Url:
    def __init__(self, url: str):
        u = urlsplit(url)
        self.https = u.scheme == "https"
        self.host = u.hostname or ""
        self.port = u.port
        self.path = (u.path or "/") + (f"?{u.query}" if u.query else "")

    def conn(self, timeout: float = 15):
        return _conn(self.host, self.port, self.https, timeout)


def _conn(host: str, port: int | None, https: bool, timeout: float = 10):
    if https:
        return http.client.HTTPSConnection(host, port or 443, timeout=timeout,
                                           context=ssl.create_default_context())
    return http.client.HTTPConnection(host, port or 80, timeout=timeout)


def _bust(path: str) -> str:
    """Cache-busting query parameter so proxies cannot answer from cache."""
    return path + ("&" if "?" in path else "?") + f"nm={time.time_ns()}"


def internet_test(ep: Endpoint, duration: float = 10, streams: int = 4, do_upload: bool = True,
                  on_progress: Progress = _noop, stop: threading.Event | None = None) -> SpeedResult:
    names = {"cloudflare": "Internet (Cloudflare)", "ookla": "Internet (Speedtest.net)",
             "librespeed": "Internet (LibreSpeed)", "mirror": "Internet (mirror)", "custom": "HTTP URL"}
    res = SpeedResult(mode=names.get(ep.provider, "Internet"), server=ep.label)
    headers = {"User-Agent": _UA}
    try:
        down = _Url(ep.down)
        # latency: request time on a kept-alive connection (first one includes TCP/TLS setup)
        ping = _Url(ep.ping) if ep.ping else down
        ping_headers = headers if ep.ping else {**headers, "Range": "bytes=0-0"}
        samples = []
        c = ping.conn(10)
        for i in range(8):
            if stop is not None and stop.is_set():
                break
            t0 = time.perf_counter()
            c.request("GET", _bust(ping.path) if ep.provider != "mirror" else ping.path, headers=ping_headers)
            r = c.getresponse()
            r.read()
            if r.status >= 400:
                raise RuntimeError(f"HTTP {r.status} dari {ping.host}")
            if i:
                samples.append((time.perf_counter() - t0) * 1000)
            if r.will_close:
                c.close()
                c = ping.conn(10)
        c.close()
        res.ping_ms, res.jitter_ms = _latency(samples)
        on_progress("ping", res.ping_ms or 0, 0)

        meter = _Meter("download", on_progress)

        def download(deadline, stop):
            conn = down.conn()
            try:
                while not _stopped(deadline, stop):
                    path = down.path if ep.provider == "mirror" else _bust(down.path)
                    conn.request("GET", path, headers=headers)
                    resp = conn.getresponse()
                    if resp.status >= 400:
                        raise RuntimeError(f"HTTP {resp.status} dari server")
                    while True:
                        if _stopped(deadline, stop):
                            return
                        chunk = resp.read(_CHUNK)
                        if not chunk:
                            break
                        meter.add(len(chunk))
                    if resp.will_close:
                        conn.close()
                        conn = down.conn()
            finally:
                conn.close()

        errors = _run_streams(download, streams, duration, stop)
        meter.finish()
        res.download_bytes, res.download_mbps = meter.total, meter.mbps()
        if errors and not meter.total:
            raise RuntimeError(errors[0])

        if do_upload and ep.up and not (stop and stop.is_set()):
            up = _Url(ep.up)
            meter = _Meter("upload", on_progress)
            size = 8 * 1024 * 1024 if ep.provider == "cloudflare" else 4 * 1024 * 1024
            prefix = b"content1=" if ep.form else b""
            body_type = "application/x-www-form-urlencoded" if ep.form else "application/octet-stream"
            filler = (b"A" * _CHUNK) if ep.form else _PAYLOAD

            def upload(deadline, stop):
                conn = up.conn()
                try:
                    while not _stopped(deadline, stop):
                        conn.putrequest("POST", _bust(up.path))
                        conn.putheader("User-Agent", _UA)
                        conn.putheader("Content-Type", body_type)
                        conn.putheader("Content-Length", str(len(prefix) + size))
                        conn.endheaders()
                        if prefix:
                            conn.send(prefix)
                        sent = 0
                        while sent < size and not _stopped(deadline, stop):
                            part = filler[: min(len(filler), size - sent)]
                            conn.send(part)
                            sent += len(part)
                            meter.add(len(part))
                        if sent < size:
                            break
                        resp = conn.getresponse()
                        resp.read()
                        if resp.status >= 400:
                            raise RuntimeError(f"HTTP {resp.status}")
                        if resp.will_close:
                            conn.close()
                            conn = up.conn()
                finally:
                    conn.close()

            errors = _run_streams(upload, streams, duration, stop)
            meter.finish()
            res.upload_bytes, res.upload_mbps = meter.total, meter.mbps()
            if errors and meter.total < 1_000_000:
                res.upload_mbps = None
                res.error = f"Upload ditolak server ({errors[0][:80]}). Coba server lain."
        elif do_upload and not ep.up:
            res.error = "Server ini hanya untuk download (tanpa tes upload)."
    except (OSError, http.client.HTTPException, RuntimeError, ssl.SSLError) as exc:
        res.error = f"{type(exc).__name__}: {exc}"
    return res


def http_test(url: str = "", duration: float = 10, streams: int = 4, do_upload: bool = True,
              on_progress: Progress = _noop, stop: threading.Event | None = None) -> SpeedResult:
    """Cloudflare when url is empty, otherwise download (and POST upload) against a custom URL."""
    ep = CLOUDFLARE_EP if not url else custom_endpoint(url, url)
    return internet_test(ep, duration, streams, do_upload, on_progress, stop)


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
