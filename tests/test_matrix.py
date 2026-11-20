"""Round-trip check for every vendor pair.

For each sample: detect vendor, parse, convert to every target vendor, parse the
generated config again with the target parser, and compare the facts that must survive.
Run: python tests/test_matrix.py [-v]
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from netmanage import parsers  # noqa: E402
from netmanage.converter import convert  # noqa: E402
from netmanage.model import VENDORS, Device  # noqa: E402

EXPECTED = {
    "R1-cisco.cfg": "cisco_ios", "R2-juniper.cfg": "juniper_junos", "R3-mikrotik.rsc": "mikrotik_ros",
    "R4-huawei.cfg": "huawei_vrp", "R5-fortinet.conf": "fortinet_fortios", "R6-arista.cfg": "arista_eos",
    "R7-h3c.cfg": "h3c_comware", "R8-nokia.cfg": "nokia_sros", "R9-vyos.cfg": "vyos",
    "R10-aruba.cfg": "aruba_aoscx",
}
# facts a target platform cannot express (documented as warnings in the app)
SKIP = {
    "fortinet_fortios": {"switchports"},
    "nokia_sros": {"switchports", "bgp_networks"},
}


def facts(dev: Device) -> dict:
    areas = dev.ospf_interface_areas()
    ospf_ips = sorted(a for name in areas for a in dev.interfaces[name].ipv4)
    return {
        "hostname": dev.hostname,
        "addresses": sorted(a for i in dev.interfaces.values() for a in i.ipv4),
        "shutdown": sorted(a for i in dev.interfaces.values() if i.shutdown for a in i.ipv4),
        "routes": sorted((r.prefix, r.nexthop, r.distance or 0,
                          r.interface.lower().startswith("null")) for r in dev.static_routes),
        "ospf_ips": ospf_ips,
        "ospf_rid": dev.ospf.router_id if dev.ospf else "",
        "bgp": sorted((n.ip, n.remote_as) for n in dev.bgp.neighbors) if dev.bgp else [],
        "bgp_asn": dev.bgp.asn if dev.bgp and dev.bgp.neighbors else "",
        "bgp_networks": sorted(dev.bgp.networks) if dev.bgp else [],
        "switchports": sorted((i.mode, i.access_vlan or 0) for i in dev.interfaces.values() if i.mode),
        "dns": sorted(dev.dns), "ntp": sorted(dev.ntp), "syslog": sorted(dev.syslog),
    }


def main() -> int:
    verbose = "-v" in sys.argv
    failures = 0
    checked = 0
    for fname, vendor in EXPECTED.items():
        text = (ROOT / "samples" / fname).read_text(encoding="utf-8")
        got = parsers.detect(text)
        if got != vendor:
            print(f"FAIL detect {fname}: {got!r} != {vendor!r}")
            failures += 1
        src = parsers.parse(text, vendor)
        base = facts(src)
        print(f"{fname:18} {len(src.interfaces)} if, {len(src.static_routes)} routes, "
              f"ospf={'y' if src.ospf else 'n'}, bgp={len(src.bgp.neighbors) if src.bgp else 0}, "
              f"unparsed={len(src.unparsed)}")
        if verbose:
            for u in src.unparsed:
                print("      unparsed:", u)
        for dst in VENDORS:
            checked += 1
            try:
                res = convert(text, dst, vendor)
                back = facts(parsers.parse(res.output, dst))
            except Exception as exc:  # noqa: BLE001 - report every failure
                print(f"  FAIL {vendor} -> {dst}: {type(exc).__name__}: {exc}")
                failures += 1
                continue
            if parsers.detect(res.output) != dst:
                print(f"  FAIL {vendor} -> {dst}: output detected as {parsers.detect(res.output)!r}")
                failures += 1
            for key, want in base.items():
                if key in SKIP.get(dst, ()):
                    continue
                if back[key] != want:
                    failures += 1
                    print(f"  FAIL {vendor} -> {dst} [{key}]\n      want {want}\n      got  {back[key]}")
    print(f"\n{checked} konversi diperiksa, {failures} gagal")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
