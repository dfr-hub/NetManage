"""FortiOS: router prefix-list/community-list/route-map, firewall policy (ACL), traffic shaping (QoS)."""
from __future__ import annotations

import re

from ..model import Device
from ..policy import AclEntry, cidr_norm, port_ops, rate_kbps

HANDLED = {"router prefix-list", "router community-list", "router route-map", "firewall address",
           "firewall service custom", "firewall policy", "firewall shaper traffic-shaper",
           "firewall shaping-policy", "firewall addrgrp"}

# predefined FortiOS services -> (protocol, dst ports)
PREDEFINED = {"ALL": ("ip", ""), "ALL_ICMP": ("icmp", ""), "PING": ("icmp", ""), "HTTP": ("tcp", "80"),
              "HTTPS": ("tcp", "443"), "SSH": ("tcp", "22"), "TELNET": ("tcp", "23"), "DNS": ("udp", "53"),
              "NTP": ("udp", "123"), "SNMP": ("udp", "161-162"), "BGP": ("tcp", "179"), "SMTP": ("tcp", "25"),
              "FTP": ("tcp", "21"), "ALL_TCP": ("tcp", "1-65535"), "ALL_UDP": ("udp", "1-65535"),
              "SYSLOG": ("udp", "514"), "RDP": ("tcp", "3389")}


def _v(node: dict, key: str, default: str = "") -> str:
    val = node.get(key)
    return val[0] if isinstance(val, list) and val else default


def _list(node: dict, key: str) -> list[str]:
    val = node.get(key)
    return list(val) if isinstance(val, list) else []


def _entries(node) -> list[tuple[str, dict]]:
    return [(k, v) for k, v in (node or {}).items() if isinstance(v, dict)]


def _ports(text: str) -> tuple[str, list[int], str, list[int]]:
    """'22' / '1000-2000' / '22 443' / '22:1024-65535' -> (dst_op, dst, src_op, src)."""
    dst_parts, src_parts = [], []
    for item in text.split():
        d, _, s = item.partition(":")
        dst_parts.append(d)
        if s:
            src_parts.append(s)

    def conv(parts):
        if not parts:
            return "", []
        if len(parts) == 1 and "-" in parts[0]:
            a, b = parts[0].split("-")
            if (a, b) == ("1", "65535") or (a, b) == ("0", "65535"):
                return "", []
            return port_ops("range", [int(a), int(b)])
        if all("-" not in p for p in parts):
            return "eq", [int(p) for p in parts]
        raise ValueError(f"gabungan port {' '.join(parts)} tidak didukung")

    dop, dports = conv(dst_parts)
    sop, sports = conv(sorted(set(src_parts)))
    return dop, dports, sop, sports


def _services(sec: dict) -> dict[str, list[tuple]]:
    """name -> [(protocol, dst_op, dst_ports, src_op, src_ports)]"""
    out: dict[str, list[tuple]] = {}
    for name, d in _entries(sec.get("firewall service custom")):
        items = []
        proto = _v(d, "protocol", "TCP/UDP/SCTP").upper()
        if proto == "ICMP":
            items.append(("icmp", "", [], "", []))
        elif proto == "IP":
            num = _v(d, "protocol-number", "0")
            items.append(("ip" if num == "0" else num, "", [], "", []))
        else:
            for key, p in (("tcp-portrange", "tcp"), ("udp-portrange", "udp")):
                text = " ".join(_list(d, key))
                if text:
                    items.append((p, *_ports(text)))
        out[name] = items
    for name, (p, ports) in PREDEFINED.items():
        if name not in out:
            out[name] = [(p, *_ports(ports))] if ports else [(p, "", [], "", [])]
    return out


def _addresses(sec: dict) -> dict[str, str]:
    out = {"all": "any", "any": "any"}
    for name, d in _entries(sec.get("firewall address")):
        sub = _list(d, "subnet")
        if len(sub) >= 2:
            out[name] = cidr_norm(f"{sub[0]}/{sub[1]}")
        elif len(sub) == 1 and "/" in sub[0]:
            out[name] = cidr_norm(sub[0])
    return out


def parse(dev: Device, sec: dict, nm) -> None:
    pol = dev.policy
    for name, d in _entries(sec.get("router prefix-list")):
        pl = pol.prefix_list(name)
        for rid, r in _entries(d.get("rule")):
            p = _list(r, "prefix")
            if not p or p[0] == "any":
                prefix, plen_default = "0.0.0.0/0", (0, 32)
            else:
                prefix = cidr_norm(f"{p[0]}/{p[1]}") if len(p) > 1 else cidr_norm(p[0])
                plen_default = None
            ge = int(_v(r, "ge")) if _v(r, "ge") else None
            le = int(_v(r, "le")) if _v(r, "le") else None
            if plen_default and ge is None and le is None:
                ge, le = plen_default
            pl.add(_v(r, "action", "permit"), prefix if prefix != "any" else "0.0.0.0/0", ge, le,
                   int(rid) if rid.isdigit() else None)
    for name, d in _entries(sec.get("router community-list")):
        cl = pol.community_list(name)
        for _, r in _entries(d.get("rule")):
            cl.entries.append((_v(r, "action", "permit"), " ".join(_list(r, "match"))))
    for name, d in _entries(sec.get("router route-map")):
        rm = pol.route_map(name)
        for rid, r in _entries(d.get("rule")):
            e = rm.entry(int(rid) if rid.isdigit() else len(rm.entries) * 10 + 10, _v(r, "action", "permit"))
            for key, val in r.items():
                v = val[0] if isinstance(val, list) and val else ""
                if key == "action":
                    pass
                elif key == "match-ip-address":
                    e.match_prefix.append(v)
                elif key == "match-community":
                    e.match_community.append(v)
                elif key == "match-tag":
                    e.match_tag = int(v)
                elif key == "set-local-preference":
                    e.set_local_pref = int(v)
                elif key == "set-metric":
                    e.set_med = int(v)
                elif key == "set-community":
                    e.set_community = " ".join(val).split()
                elif key == "set-community-additive":
                    e.community_additive = v == "enable"
                elif key == "set-ip-nexthop":
                    e.set_next_hop = v
                elif key == "set-aspath":
                    e.set_prepend = " ".join(val).split()
                elif key == "set-weight":
                    e.set_weight = int(v)
                elif key == "set-tag":
                    e.set_tag = int(v)
                else:
                    dev.unparsed.append(f"router route-map {name} rule {rid}: set {key} {' '.join(val)}")

    services = _services(sec)
    addrs = _addresses(sec)

    def expand(d: dict, where: str) -> list[tuple]:
        srcs = [addrs.get(a) for a in _list(d, "srcaddr") or ["all"]]
        dsts = [addrs.get(a) for a in _list(d, "dstaddr") or ["all"]]
        svcs = [services.get(s) for s in _list(d, "service") or ["ALL"]]
        if None in srcs or None in dsts or None in svcs:
            raise ValueError("address/service tidak dikenal (addrgrp, FQDN, atau range belum didukung)")
        return [(s, t, sv) for s in srcs for t in dsts for svl in svcs for sv in svl]

    seen: set[tuple[str, int]] = set()
    for pid, d in _entries(sec.get("firewall policy")):
        comment = _v(d, "comments")
        name = _v(d, "name")
        m = re.match(r"NetManage ACL (\S+) (in|out|none)(?: \| (.*))?$", comment)
        try:
            items = expand(d, pid)
        except ValueError as exc:
            dev.unparsed.append(f"firewall policy {pid} ({name}): {exc}")
            continue
        action = "permit" if _v(d, "action", "deny") == "accept" else "deny"
        log = _v(d, "logtraffic", "utm") == "all"
        if m:
            acl_name, direction, remark = m.group(1), m.group(2), m.group(3)
            seq = int(name.rsplit("-", 1)[1]) if re.search(r"-\d+$", name) else int(pid) * 10
            iface = _v(d, "srcintf") if direction == "in" else _v(d, "dstintf")
            if direction != "none":
                pol.bind_acl(acl_name, nm(iface), direction)
            if (acl_name, seq) in seen:
                continue
            seen.add((acl_name, seq))
        else:
            iface = _v(d, "srcintf", "any")
            acl_name, direction, remark = f"FW-{iface}", "in", name
            seq = (len(pol.acls.get(acl_name).entries) + 1) * 10 if acl_name in pol.acls else 10
            if iface != "any":
                pol.bind_acl(acl_name, nm(iface), "in")
        acl = pol.acl(acl_name)
        if remark:
            acl.entries.append(AclEntry(seq=seq - 1, action="remark", remark=remark))
        for n, (src, dst, (proto, dop, dports, sop, sports)) in enumerate(items):
            acl.entries.append(AclEntry(seq=seq + n, action=action, protocol=proto, src=src, dst=dst,
                                        src_op=sop, src_ports=sports, dst_op=dop, dst_ports=dports, log=log))
    for acl in pol.acls.values():
        acl.entries.sort(key=lambda e: (e.seq, e.action != "remark"))

    shapers = {n: d for n, d in _entries(sec.get("firewall shaper traffic-shaper"))}
    for sid, d in _entries(sec.get("firewall shaping-policy")):
        m = re.match(r"NetManage QOS (\S+) (\S+) (in|out)$", _v(d, "comment"))
        if m:
            pname, cname, direction = m.groups()
        else:
            pname, cname, direction = "FGT-SHAPING", _v(d, "name") or f"C{sid}", "out"
        qp = pol.qos_policy(pname)
        act = qp.action(cname)
        iface = _v(d, "srcintf") if direction == "in" else _v(d, "dstintf")
        if iface and iface != "any":
            pol.bind_qos(pname, nm(iface), direction)
        sh = shapers.get(_v(d, "traffic-shaper"), {})
        if _v(sh, "maximum-bandwidth"):
            act.police_kbps = int(_v(sh, "maximum-bandwidth"))
        if _v(sh, "guaranteed-bandwidth") and _v(sh, "guaranteed-bandwidth") != "0":
            act.bandwidth_kbps = int(_v(sh, "guaranteed-bandwidth"))
        if _v(sh, "priority", "high") == "high" and m:
            act.priority = True
            act.priority_kbps, act.bandwidth_kbps = act.bandwidth_kbps, None
        if _v(sh, "diffserv") == "enable" and _v(sh, "diffservcode"):
            act.set_dscp = int(_v(sh, "diffservcode"), 2)
        if cname == "class-default":
            continue
        cls = pol.qos_class(cname)
        cls.match_any = True
        if _v(d, "tos"):
            dscp = int(_v(d, "tos"), 16) >> 2
            if dscp not in cls.match_dscp:
                cls.match_dscp.append(dscp)
        else:
            try:
                items = expand(d, sid)
            except ValueError as exc:
                dev.unparsed.append(f"firewall shaping-policy {sid}: {exc}")
                continue
            if items == [("any", "any", ("ip", "", [], "", []))]:
                continue
            acl = pol.acl(f"CLS-{cname}")
            for src, dst, (proto, dop, dports, sop, sports) in items:
                sig = (proto, src, dst, dop, tuple(dports))
                if sig in [(x.protocol, x.src, x.dst, x.dst_op, tuple(x.dst_ports)) for x in acl.entries]:
                    continue
                acl.entries.append(AclEntry(seq=acl.next_seq(), protocol=proto, src=src, dst=dst,
                                            src_op=sop, src_ports=sports, dst_op=dop, dst_ports=dports))
            cls.match_acl = acl.name
