"""Template context for prefix-lists, route-maps, ACL and QoS.

Values that are awkward to build in Jinja2 (address/port strings per vendor, Junos
route-filter types, MikroTik filter rules) are computed here.
"""
from __future__ import annotations

import ipaddress
from typing import Callable

from .model import Device
from .policy import (AclEntry, PrefixEntry, cidr_norm, dscp_name, kbps_text, proto_name,
                     proto_number, safe_name)

ROS_PROTO = {"47": "gre", "50": "ipsec-esp", "51": "ipsec-ah", "89": "ospf", "103": "pim",
             "2": "igmp", "112": "vrrp"}


# ------------------------------------------------------------------ prefix-list
def _pentry(e: PrefixEntry) -> dict:
    net = ipaddress.ip_network(e.prefix)
    plen = net.prefixlen
    lo, hi = e.range()
    exact = lo == plen and hi == plen
    if exact:
        ios = ""
        junos = "exact"
        nokia = "exact"
    else:
        ios = (f" ge {lo}" + (f" le {hi}" if hi < 32 else "")) if lo > plen else f" le {hi}"
        if lo == plen and hi == 32:
            junos, nokia = "orlonger", "longer"
        elif lo == plen:
            junos, nokia = f"upto /{hi}", f"through {hi}"
        else:
            junos, nokia = f"prefix-length-range /{lo}-/{hi}", f"prefix-length-range {lo}-{hi}"
    vrp = "" if exact else f" greater-equal {lo} less-equal {hi}"
    ros = f"dst in {e.prefix} && " + (f"dst-len == {plen}" if exact else f"dst-len in {lo}-{hi}")
    frr_ge = lo if not exact and lo > plen else None
    frr_le = hi if not exact and (hi < 32 or lo == plen) else None
    return {"frr_ge": frr_ge, "frr_le": frr_le,
            "seq": e.seq, "action": e.action, "permit": e.action == "permit", "prefix": e.prefix,
            "net": str(net.network_address), "plen": plen, "mask": str(net.netmask), "lo": lo, "hi": hi,
            "exact": exact, "ge": lo if not exact else None, "le": hi if not exact else None,
            "ios": ios, "junos": junos, "nokia": nokia, "vrp": vrp, "ros": ros}


# --------------------------------------------------------------------------- ACL
def ios_addr(cidr: str) -> str:
    if cidr == "any":
        return "any"
    net = ipaddress.ip_network(cidr)
    if net.prefixlen == 32:
        return f"host {net.network_address}"
    return f"{net.network_address} {net.hostmask}"


def eos_addr(cidr: str) -> str:
    if cidr == "any":
        return "any"
    return f"host {cidr[:-3]}" if cidr.endswith("/32") else cidr


def aruba_addr(cidr: str) -> str:
    if cidr == "any":
        return "any"
    return cidr[:-3] if cidr.endswith("/32") else cidr


def vrp_addr(cidr: str) -> str:
    net = ipaddress.ip_network(cidr)
    return f"{net.network_address} {'0' if net.prefixlen == 32 else net.hostmask}"


def ios_ports(op: str, ports: list[int]) -> str:
    if not op:
        return ""
    if op == "range":
        return f" range {ports[0]} {ports[1]}"
    return " eq " + " ".join(str(p) for p in ports)


def junos_dscp(value: int) -> str:
    """Junos DSCP alias (ef, af41, cs1, be) or 6-bit string for other values."""
    name = dscp_name(value)
    if name == "default":
        return "be"
    return name if not name.isdigit() else format(value, "06b")


def dash_ports(op: str, ports: list[int], sep: str = ",") -> str:
    if not op:
        return ""
    if op == "range":
        return f"{ports[0]}-{ports[1]}"
    return sep.join(str(p) for p in ports)


def _ace(e: AclEntry, standard: bool) -> dict:
    return {
        "seq": e.seq, "action": e.action, "permit": e.action == "permit", "remark": e.remark,
        "is_remark": e.action == "remark", "protocol": e.protocol, "ip": e.protocol == "ip",
        "proto_name": proto_name(e.protocol), "proto_num": proto_number(e.protocol),
        "ros_proto": ROS_PROTO.get(e.protocol, e.protocol),
        "ports_ok": e.protocol in ("tcp", "udp"),
        "src": e.src, "dst": e.dst, "src_any": e.src == "any", "dst_any": e.dst == "any",
        "src_op": e.src_op, "src_ports": e.src_ports, "dst_op": e.dst_op, "dst_ports": e.dst_ports,
        "src_port_text": dash_ports(e.src_op, e.src_ports), "dst_port_text": dash_ports(e.dst_op, e.dst_ports),
        "established": e.established, "log": e.log, "standard": standard,
    }


def _split(entries: list[AclEntry]) -> list[AclEntry]:
    """One port per entry, for vendors without multi-port 'eq'."""
    out = []
    for e in entries:
        dsts = [[p] for p in e.dst_ports] if e.dst_op == "eq" and len(e.dst_ports) > 1 else [e.dst_ports]
        srcs = [[p] for p in e.src_ports] if e.src_op == "eq" and len(e.src_ports) > 1 else [e.src_ports]
        n = 0
        for s in srcs:
            for d in dsts:
                c = AclEntry(**{**e.__dict__, "src_ports": list(s), "dst_ports": list(d), "seq": e.seq + n})
                out.append(c)
                n += 1
    return out


def _remark_for(entries: list[AclEntry]) -> dict[int, str]:
    """Remark text attached to the rule that follows it (for comment-style vendors)."""
    out, pending = {}, []
    for e in entries:
        if e.action == "remark":
            pending.append(e.remark)
        elif pending:
            out[e.seq] = " | ".join(pending)
            pending = []
    return out


def build(dev: Device, dst: str, m: Callable[[str], str], ifaces: dict[str, dict],
          warn: Callable[[str], str]) -> dict:
    pol = dev.policy

    prefix_lists = []
    for pl in pol.prefix_lists.values():
        entries = [_pentry(e) for e in sorted(pl.entries, key=lambda x: x.seq)]
        prefix_lists.append({"name": pl.name, "entries": entries,
                             "permits": [e for e in entries if e["permit"]],
                             "denies": [e for e in entries if not e["permit"]]})
    pl_by_name = {p["name"]: p for p in prefix_lists}

    community_lists = []
    for cl in pol.community_lists.values():
        community_lists.append({"name": cl.name, "entries": [
            {"action": a, "value": v, "members": v.split(), "index": (i + 1) * 10}
            for i, (a, v) in enumerate(cl.entries)]})
    cl_by_name = {c["name"]: c for c in community_lists}

    ospf_maps = set(dev.ospf.redistribute_map.values()) if dev.ospf else set()
    bgp_maps = set()
    if dev.bgp:
        bgp_maps = set(dev.bgp.redistribute_map.values()) | {
            x for n in dev.bgp.neighbors for x in (n.route_map_in, n.route_map_out) if x}
    route_maps = []
    for rm in pol.route_maps.values():
        entries = []
        for e in rm.entries:
            prefixes = []
            for name in e.match_prefix:
                if name not in pl_by_name:
                    warn(f"route-map {rm.name} {e.seq}: prefix-list {name} tidak ada di konfigurasi.")
                    continue
                prefixes += pl_by_name[name]["entries"]
            comms = []
            for name in e.match_community:
                if name not in cl_by_name:
                    warn(f"route-map {rm.name} {e.seq}: community-list {name} tidak ada di konfigurasi.")
                    continue
                comms += [c["value"] for c in cl_by_name[name]["entries"] if c["action"] == "permit"]
            d = {**e.__dict__, "permit": e.action == "permit", "prefixes": prefixes,
                 "permits": [p for p in prefixes if p["permit"]],
                 "denies": [p for p in prefixes if not p["permit"]], "communities": comms,
                 "has_match": e.has_match, "name": rm.name, "term": f"T{e.seq}",
                 "ospf": rm.name in ospf_maps and rm.name not in bgp_maps}
            d["ros_rule"] = _ros_rule(d, dev, warn) if dst == "mikrotik_ros" else ""
            entries.append(d)
        route_maps.append({"name": rm.name, "entries": entries})

    renamed = {a.name: _acl_name(a.name, a.kind, dst) for a in pol.acls.values()}
    changed = {k: v for k, v in renamed.items() if k != v}
    if changed:
        warn("Nomor ACL tidak valid di vendor tujuan, diganti nama: "
             + ", ".join(f"{k} -> {v}" for k, v in changed.items()))

    acls = []
    for acl in pol.acls.values():
        std = acl.kind == "standard"
        entries = [_ace(e, std) for e in acl.entries]
        split = [_ace(e, std) for e in _split(acl.rules())]
        remarks = _remark_for(acl.entries)
        for s in split:
            s["note"] = remarks.get(s["seq"], "")
        name = renamed[acl.name]
        acls.append({"name": name, "safe": safe_name(name, 30), "kind": acl.kind,
                     "standard": std, "entries": entries, "rules": [e for e in entries if not e["is_remark"]],
                     "split": split, "remarks": [e.remark for e in acl.entries if e.action == "remark"],
                     "numeric": name.isdigit()})
    acl_by_name = {a["name"]: a for a in acls}
    for idx, a in enumerate(acls, start=1):
        a["id"] = idx * 10

    acl_bindings = []
    for b in pol.acl_bindings:
        target = m(b.interface)
        itf = ifaces.get(b.interface)
        aname = renamed.get(b.acl, b.acl)
        if aname not in acl_by_name:
            warn(f"Interface {b.interface}: ACL {b.acl} tidak ada di konfigurasi.")
            continue
        if itf is not None:
            itf[f"acl_{b.direction}"] = aname
        acl_bindings.append({"acl": aname, "acl_obj": acl_by_name[aname], "interface": target,
                             "direction": b.direction, "iface": itf})

    bound = {renamed.get(b.acl, b.acl) for b in pol.acl_bindings}
    for a in acls:
        a["qos_only"] = a["name"] not in bound and any(
            renamed.get(c.match_acl, c.match_acl) == a["name"] for c in pol.qos_classes.values())

    classes = {}
    for c in pol.qos_classes.values():
        cacl = renamed.get(c.match_acl, c.match_acl)
        obj = acl_by_name.get(cacl)
        if obj is not None and any(not r["permit"] for r in obj["rules"]):
            warn(f"class {c.name}: entri deny di ACL {c.match_acl} tidak dipakai sebagai kecocokan class "
                 f"(hanya entri permit yang dikonversi untuk QoS).")
        match_acl = None if obj is None else {**obj, "rules": [r for r in obj["rules"] if r["permit"]],
                                              "split": [r for r in obj["split"] if r["permit"]]}
        classes[c.name] = {"name": c.name, "dscp": c.match_dscp,
                           "dscp_names": [dscp_name(x) for x in c.match_dscp],
                           "acl": cacl, "acl_obj": match_acl,
                           "match_any": c.match_any,
                           "any": not c.match_dscp and not c.match_acl}
        if c.match_acl and cacl not in acl_by_name:
            warn(f"class-map {c.name}: ACL {c.match_acl} tidak ada di konfigurasi.")
    qos_policies = []
    for qp in pol.qos_policies.values():
        actions = []
        for i, a in enumerate(qp.actions, start=1):
            default = a.cls in ("class-default", "default-class", "default")
            cls = classes.get(a.cls) or {"name": a.cls, "dscp": [], "dscp_names": [], "acl": "",
                                         "acl_obj": None, "match_any": True, "any": True}
            if not default and a.cls not in classes:
                warn(f"policy-map {qp.name}: class {a.cls} tidak ada di konfigurasi.")
            actions.append({**a.__dict__, "index": i * 10, "default": default, "class": cls,
                            "set_dscp_name": dscp_name(a.set_dscp) if a.set_dscp is not None else "",
                            "police": kbps_text(a.police_kbps) if a.police_kbps else "",
                            "shape": kbps_text(a.shape_kbps) if a.shape_kbps else "",
                            "rate_kbps": a.police_kbps or a.shape_kbps,
                            "burst_kb": max(16, (a.police_kbps or 0) // 64),
                            "safe": safe_name(f"{qp.name}-{a.cls}", 35)})
        qos_policies.append({"name": qp.name, "actions": actions,
                             "classes": [a for a in actions if not a["default"]],
                             "default": next((a for a in actions if a["default"]), None)})
    qp_by_name = {q["name"]: q for q in qos_policies}
    qos_bindings = []
    for b in pol.qos_bindings:
        itf = ifaces.get(b.interface)
        if b.policy not in qp_by_name:
            warn(f"Interface {b.interface}: policy-map {b.policy} tidak ada di konfigurasi.")
            continue
        if itf is not None:
            itf[f"qos_{b.direction}"] = b.policy
        qos_bindings.append({"policy": b.policy, "policy_obj": qp_by_name[b.policy],
                             "interface": m(b.interface), "direction": b.direction, "iface": itf})

    fgt = _fortinet(acls, acl_bindings, qos_policies, qos_bindings, warn) if dst == "fortinet_fortios" else {}
    return {"fgt": fgt, "prefix_lists": prefix_lists, "community_lists": community_lists, "route_maps": route_maps,
            "acls": acls, "acl_bindings": acl_bindings, "acl_by_name": acl_by_name,
            "qos_classes": classes, "qos_policies": qos_policies, "qos_by_name": qp_by_name,
            "qos_bindings": qos_bindings,
            "has_policy": bool(prefix_lists or community_lists or route_maps or acls or qos_policies)}


def _acl_name(name: str, kind: str, dst: str) -> str:
    """Keep numbered ACLs only where the number is valid on the target platform."""
    if not name.isdigit():
        return name
    n = int(name)
    std = kind == "standard"
    if dst == "cisco_ios":
        ok = (1 <= n <= 99 or 1300 <= n <= 1999) if std else (100 <= n <= 199 or 2000 <= n <= 2699)
    elif dst in ("huawei_vrp", "h3c_comware"):
        ok = (2000 <= n <= 2999) if std else (3000 <= n <= 3999)
    elif dst in ("arista_eos", "aruba_aoscx"):
        ok = False
    else:
        ok = True
    return name if ok else f"ACL-{name}"


def _fortinet(acls, acl_bindings, qos_policies, qos_bindings, warn) -> dict:
    """Address/service objects, firewall policies and shaping policies for FortiOS."""
    addresses: dict[str, str] = {}
    services: dict[str, dict] = {}

    def addr(cidr: str) -> str:
        if cidr == "any":
            return "all"
        net = ipaddress.ip_network(cidr)
        name = f"NM_{net.network_address}_{net.prefixlen}"
        addresses[name] = f"{net.network_address} {net.netmask}"
        return name

    def svc(e: dict) -> str:
        if e["ip"] or e["standard"]:
            return "ALL"
        if e["protocol"] == "icmp":
            return "ALL_ICMP"
        if e["protocol"] not in ("tcp", "udp"):
            name = f"NM_IP_{e['proto_num']}"
            services[name] = {"protocol": "IP", "number": e["proto_num"]}
            return name
        dst = e["dst_port_text"].replace(",", " ") if e["dst_op"] else "1-65535"
        src = e["src_port_text"] if e["src_op"] else ""
        rng = " ".join(f"{d}:{src}" if src else d for d in dst.split())
        name = f"NM_{e['protocol'].upper()}_{dst.replace(' ', '_')}" + (f"_S{src}" if src else "")
        services[name] = {"protocol": "TCP/UDP/SCTP", "key": f"{e['protocol']}-portrange", "range": rng}
        return name

    policies = []
    bound = {b["acl"] for b in acl_bindings}
    jobs = [(b["acl_obj"], b["interface"], b["direction"]) for b in acl_bindings]
    jobs += [(a, "any", "none") for a in acls if a["name"] not in bound and not a["qos_only"]]
    for a, iface, direction in jobs:
        for e in a["split"]:
            if e["established"]:
                warn(f"ACL {a['name']} {e['seq']}: 'established' tidak perlu di FortiOS (firewall stateful), diabaikan.")
            comment = f"NetManage ACL {a['name']} {direction}" + (f" | {e['note']}" if e["note"] else "")
            policies.append({
                "id": len(policies) + 1, "name": f"{a['name']}-{e['seq']}"[:35],
                "srcintf": iface if direction == "in" else "any",
                "dstintf": iface if direction == "out" else "any",
                "srcaddr": addr(e["src"]), "dstaddr": "all" if a["standard"] else addr(e["dst"]),
                "service": svc(e), "action": "accept" if e["permit"] else "deny", "log": e["log"],
                "disabled": direction == "none", "comment": comment.replace('"', "'")})

    shapers, shaping = [], []
    for b in qos_bindings:
        p = b["policy_obj"]
        for a in p["actions"]:
            name = safe_name(f"NM_{p['name']}_{a['cls']}", 35)
            if a["shape_kbps"] and a["police_kbps"]:
                warn(f"QoS {p['name']} class {a['cls']}: police dan shape digabung jadi maximum-bandwidth.")
            if not any(s["name"] == name for s in shapers):
                shapers.append({"name": name, "max": a["rate_kbps"],
                                "guaranteed": a["priority_kbps"] or a["bandwidth_kbps"],
                                "priority": "high" if a["priority"] else "medium",
                                "dscp": format(a["set_dscp"], "06b") if a["set_dscp"] is not None else ""})
            if a["bandwidth_pct"] and not a["bandwidth_kbps"]:
                warn(f"QoS {p['name']} class {a['cls']}: bandwidth persen tidak dikonversi (FortiOS memakai kbps).")
            base = {"shaper": name, "comment": f"NetManage QOS {p['name']} {a['cls']} {b['direction']}",
                    "srcintf": b["interface"] if b["direction"] == "in" else "any",
                    "dstintf": b["interface"] if b["direction"] == "out" else "any"}
            cls = a["class"]
            matches = []
            if a["default"] or cls["any"]:
                matches.append({"srcaddr": "all", "dstaddr": "all", "service": "ALL", "tos": ""})
            elif cls["dscp"]:
                for d in cls["dscp"]:
                    matches.append({"srcaddr": "all", "dstaddr": "all", "service": "ALL",
                                    "tos": f"0x{d << 2:02x}"})
            elif cls["acl_obj"]:
                for e in cls["acl_obj"]["split"]:
                    matches.append({"srcaddr": addr(e["src"]), "dstaddr": addr(e["dst"]), "service": svc(e),
                                    "tos": ""})
            for mt in matches:
                shaping.append({**base, **mt, "id": len(shaping) + 1})
    unbound = [p["name"] for p in qos_policies if p["name"] not in {b["policy"] for b in qos_bindings}]
    if unbound:
        warn("QoS tanpa interface tidak dikonversi ke FortiOS: " + ", ".join(unbound))
    return {"addresses": addresses, "services": services, "policies": policies, "shapers": shapers,
            "shaping": shaping}


def _ros_rule(e: dict, dev: Device, warn) -> str:
    """MikroTik v7 routing filter rule text for one route-map entry."""
    conds = []
    if e["permits"]:
        terms = [f"({p['ros']})" for p in e["permits"]]
        conds.append(terms[0] if len(terms) == 1 else "(" + " || ".join(terms) + ")")
    if e["denies"]:
        conds.append("!(" + " || ".join(f"({p['ros']})" for p in e["denies"]) + ")")
    if e["prefixes"] and not e["permits"]:
        conds.append("false")
    if e["communities"]:
        terms = [f"bgp-communities includes {c.replace(' ', ',')}" for c in e["communities"]]
        conds.append(terms[0] if len(terms) == 1 else "(" + " || ".join(terms) + ")")
    if e["match_tag"] is not None:
        warn(f"route-map {e['name']} {e['seq']}: match tag tidak dikonversi ke MikroTik.")
    acts = []
    if e["set_local_pref"] is not None:
        acts.append(f"set bgp-local-pref {e['set_local_pref']}")
    if e["set_med"] is not None:
        acts.append(f"set {'ospf-ext-metric' if e['ospf'] else 'bgp-med'} {e['set_med']}")
    if e["set_community"]:
        verb = "append" if e["community_additive"] else "set"
        acts.append(f"{verb} bgp-communities {','.join(e['set_community'])}")
    if e["set_next_hop"]:
        acts.append(f"set gw {e['set_next_hop']}")
    if e["set_prepend"]:
        acts.append(f"set bgp-path-prepend {len(e['set_prepend'])}")
    if e["set_weight"] is not None:
        acts.append(f"set bgp-weight {e['set_weight']}")
    if e["set_tag"] is not None and e["ospf"]:
        acts.append(f"set ospf-ext-tag {e['set_tag']}")
    elif e["set_tag"] is not None:
        warn(f"route-map {e['name']} {e['seq']}: set tag tidak dikonversi ke MikroTik.")
    acts.append("accept" if e["permit"] else "reject")
    body = "; ".join(acts)
    if conds:
        return f"if ({' && '.join(conds)}) {{ {body} }}"
    return body


__all__ = ["build", "ios_addr", "eos_addr", "aruba_addr", "vrp_addr", "ios_ports", "dash_ports",
           "cidr_norm"]
