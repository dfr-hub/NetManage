"""Round-trip check for route-map, prefix-list, community-list, ACL and QoS.

Every sample is converted to every vendor, parsed back, and the policy semantics are
compared. Facts a platform cannot express are skipped through CAPS (they show up as
warnings in the conversion report).
Run: python tests/test_policy.py [-v] [vendor ...]
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from netmanage import parsers  # noqa: E402
from netmanage.converter import convert  # noqa: E402
from netmanage.model import VENDORS, Device  # noqa: E402

ALL_QOS = {"set_dscp", "police", "shape", "bandwidth", "priority", "default", "out", "in"}
# what each target can express
CAPS = {
    "cisco_ios": {"rm": {"tag", "weight", "prepend"}, "qos": ALL_QOS, "acl": {"established", "log"}},
    "arista_eos": {"rm": {"tag", "weight", "prepend"}, "qos": {"set_dscp", "police", "default", "in"},
                   "acl": {"established", "log"}},
    "aruba_aoscx": {"rm": {"tag", "weight", "prepend"}, "qos": {"set_dscp", "police", "priority", "in", "out"},
                    "acl": {"log"}},
    "huawei_vrp": {"rm": {"tag", "weight", "prepend"}, "qos": ALL_QOS, "acl": {"established", "log"}},
    "h3c_comware": {"rm": {"tag", "weight", "prepend"}, "qos": ALL_QOS, "acl": {"established", "log"}},
    "juniper_junos": {"rm": {"tag", "prepend"}, "qos": ALL_QOS, "acl": {"established", "log"}},
    "mikrotik_ros": {"rm": {"weight"}, "qos": {"set_dscp", "rate", "bandwidth", "priority", "in", "out"},
                     "acl": {"established", "log"}},
    "fortinet_fortios": {"rm": {"tag", "weight", "prepend"}, "qos": {"set_dscp", "rate", "bandwidth",
                                                                     "priority", "in", "out"},
                         "acl": {"log"}},
    "nokia_sros": {"rm": {"prepend"}, "qos": set(), "acl": {"established", "log"}},
    "vyos": {"rm": {"tag", "weight", "prepend"}, "qos": {"set_dscp", "rate", "bandwidth", "priority",
                                                         "default", "in", "out"},
             "qos_in": {"rate", "in"},
             "acl": {"established", "log"}},
}


def _ip_of(dev: Device, ifname: str) -> str:
    itf = dev.interfaces.get(ifname)
    return itf.ipv4[0] if itf and itf.ipv4 else f"?{ifname}"


def facts(dev: Device, dst: str) -> dict:
    cap = CAPS[dst]
    pol = dev.policy

    def prefixes(names):
        out = []
        for n in names:
            pl = pol.prefix_lists.get(n)
            for e in (pl.entries if pl else []):
                out.append((e.action, e.prefix, *e.range()))
        return sorted(set(out))

    def comms(names):
        out = []
        for n in names:
            cl = pol.community_lists.get(n)
            out += [v for a, v in (cl.entries if cl else []) if a == "permit"]
        return sorted(set(out))

    rms = {}
    for rm in pol.route_maps.values():
        entries = []
        for e in sorted(rm.entries, key=lambda x: x.seq):
            entries.append((
                e.action, tuple(prefixes(e.match_prefix)), tuple(comms(e.match_community)),
                e.match_tag if "tag" in cap["rm"] else None,
                e.set_local_pref, e.set_med, tuple(e.set_community), bool(e.set_community and e.community_additive),
                e.set_next_hop, len(e.set_prepend) if "prepend" not in cap["rm"] else tuple(e.set_prepend),
                e.set_weight if "weight" in cap["rm"] else None, e.set_tag if "tag" in cap["rm"] else None))
        # a trailing 'deny' with no match equals the implicit deny
        while entries and entries[-1][0] == "deny" and not any(entries[-1][1:4]):
            entries.pop()
        rms[rm.name] = entries

    def rules(acl):
        out = []
        for e in acl.rules():
            dsts = [[p] for p in e.dst_ports] if e.dst_op == "eq" else [e.dst_ports]
            for d in dsts:
                out.append((e.action, e.protocol if acl.kind == "extended" else "ip", e.src,
                            e.src_op, tuple(e.src_ports), e.dst if acl.kind == "extended" else "any",
                            e.dst_op, tuple(d),
                            e.established if "established" in cap["acl"] else False,
                            e.log if "log" in cap["acl"] else False))
        while out and out[-1][0] == "deny" and out[-1][1:8] == ("ip", "any", "", (), "any", "", ()) \
                and not out[-1][9]:
            out.pop()
        return tuple(out)

    bound = {b.acl for b in pol.acl_bindings}
    qos_only = {c.match_acl for c in pol.qos_classes.values()} - bound
    acls = sorted(rules(a) for a in pol.acls.values() if a.name not in qos_only)
    acl_bind = sorted((b.direction, _ip_of(dev, b.interface), rules(pol.acls[b.acl]))
                      for b in pol.acl_bindings if b.acl in pol.acls)

    qos = []
    for b in pol.qos_bindings:
        q = cap.get("qos_in", cap["qos"]) if b.direction == "in" else cap["qos"]
        if b.direction not in q or b.policy not in pol.qos_policies:
            continue
        actions = []
        for a in pol.qos_policies[b.policy].actions:
            default = a.cls in ("class-default", "default")
            if default and "default" not in q:
                continue
            c = pol.qos_classes.get(a.cls)
            match = ("default",) if default or c is None else (
                tuple(sorted(c.match_dscp)),
                tuple(r for r in rules(pol.acls[c.match_acl]) if r[0] == "permit")
                if c.match_acl in pol.acls else ())
            rate = a.police_kbps or a.shape_kbps
            item = (match,
                    a.set_dscp if "set_dscp" in q else None,
                    a.police_kbps if "police" in q else None,
                    a.shape_kbps if "shape" in q else None,
                    rate if "rate" in q else None,
                    (a.bandwidth_kbps if a.bandwidth_kbps else None) if "bandwidth" in q else None,
                    bool(a.priority) if "priority" in q else None)
            if any(x not in (None, False) for x in item[1:]):
                actions.append(item)
        if actions:
            qos.append((b.direction, _ip_of(dev, b.interface), tuple(sorted(actions, key=repr))))
    refs = {
        "bgp": sorted((n.ip, n.route_map_in, n.route_map_out) for n in dev.bgp.neighbors) if dev.bgp else [],
        "bgp_redist": sorted(dev.bgp.redistribute_map.items()) if dev.bgp else [],
        "ospf_redist": sorted(dev.ospf.redistribute_map.items()) if dev.ospf else [],
    }
    return {"route_maps": rms, "acls": acls, "acl_bindings": acl_bind, "qos": sorted(qos), **refs}


def main() -> int:
    verbose = "-v" in sys.argv
    only = [a for a in sys.argv[1:] if not a.startswith("-")]
    failures = checked = 0
    for path in sorted((ROOT / "samples").iterdir()):
        text = path.read_text(encoding="utf-8")
        src = parsers.parse(text)
        p = src.policy
        if not (p.route_maps or p.acls or p.qos_policies):
            continue
        print(f"{path.name:18} rm={len(p.route_maps)} pl={len(p.prefix_lists)} acl={len(p.acls)} "
              f"qos={len(p.qos_policies)} unparsed={len(src.unparsed)}")
        if verbose:
            for u in src.unparsed:
                print("      unparsed:", u)
        for dst in VENDORS:
            if only and dst not in only:
                continue
            checked += 1
            try:
                res = convert(text, dst)
                back = parsers.parse(res.output, dst)
            except Exception as exc:  # noqa: BLE001
                import traceback
                print(f"  FAIL {src.vendor} -> {dst}: {type(exc).__name__}: {exc}")
                if verbose:
                    traceback.print_exc()
                failures += 1
                continue
            want, got = facts(src, dst), facts(back, dst)
            for key in want:
                if dst == "nokia_sros" and key in ("ospf_redist", "bgp_redist"):
                    continue  # SR OS redistribute needs export policies; reported as a warning
                if want[key] != got[key]:
                    failures += 1
                    print(f"  FAIL {src.vendor} -> {dst} [{key}]")
                    print(f"      want {want[key]}")
                    print(f"      got  {got[key]}")
            if verbose and back.unparsed:
                print(f"  {dst}: unparsed setelah parse balik:")
                for u in back.unparsed:
                    print("      ", u)
    print(f"\n{checked} konversi policy diperiksa, {failures} gagal")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
