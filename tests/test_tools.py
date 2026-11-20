"""Checks for the topology mapper and the log collector (fake connection, no real device)."""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from netmanage import collector, parsers, topology  # noqa: E402


class FakeConn:
    def __init__(self, **kwargs):
        if kwargs["password"] == "wrong":
            raise type("NetmikoAuthenticationException", (Exception,), {})("auth failed")
        self.kwargs = kwargs

    def enable(self):
        pass

    def send_command(self, cmd, **_):
        return f"output of {cmd} on {self.kwargs['host']}"

    def send_command_timing(self, cmd, **_):
        return self.send_command(cmd)

    def disconnect(self):
        pass


def main() -> int:
    failures = 0
    devices = [parsers.parse(p.read_text(encoding="utf-8"), source=p.name)
               for p in sorted((ROOT / "samples").iterdir())]
    topo = topology.build(devices)
    pairs = {frozenset((lk.a, lk.b)) for lk in topo.links if lk.kind == "l3"}
    ring = ["R1-CISCO", "R2-JUNIPER", "R3-MIKROTIK", "R4-HUAWEI", "R5-FORTINET", "R6-ARISTA",
            "R7-H3C", "R8-NOKIA", "R9-VYOS", "R10-ARUBA"]
    expected = {frozenset((ring[i], ring[(i + 1) % 10])) for i in range(10)}
    expected.add(frozenset(("R1-CISCO", "R6-ARISTA")))
    missing = expected - pairs
    print(f"topology: {len(topo.nodes)} node, {len(topo.links)} link, l3={len(pairs)}")
    for lk in topo.links:
        print(f"  {lk.kind:4} {lk.a}[{lk.a_if} {lk.a_ip}] -- {lk.b}[{lk.b_if} {lk.b_ip}] {lk.label}")
    if missing:
        failures += 1
        print("FAIL missing links:", [sorted(m) for m in missing])
    for fn in (topology.to_svg, topology.to_drawio, topology.to_csv):
        if len(fn(topo)) < 100:
            failures += 1
            print("FAIL export", fn.__name__)

    targets = [collector.Target(host=f"dev-{v}", ip=f"10.0.0.{i}", vendor=v, username="u", password="p")
               for i, v in enumerate(collector.PROFILES, start=1)]
    targets.append(collector.Target(host="bad", ip="10.0.0.99", vendor="cisco_ios", username="u",
                                    password="wrong"))
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp)
        events = []
        res = collector.collect(targets, collector.default_commands(), out, workers=4,
                                on_event=lambda k, t, m: events.append(k), connect=FakeConn)
        ok = sum(1 for v in res.values() if v == "ok")
        logs = list(out.glob("*.log"))
        cfgs = list((out / "configs").glob("*.cfg"))
        print(f"collector: ok={ok}/{len(targets)} logs={len(logs)} configs={len(cfgs)} bad={res['bad']!r}")
        if ok != 10 or len(logs) != 10 or len(cfgs) != 10 or "Login gagal" not in res["bad"]:
            failures += 1
            print("FAIL collector")
        inv = out / "inv.csv"
        collector.save_inventory(inv, targets)
        back = collector.load_inventory(inv)
        if len(back) != len(targets) or any(t.password for t in back):
            failures += 1
            print("FAIL inventory round-trip")
    print("OK" if not failures else f"{failures} gagal")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
