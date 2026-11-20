"""Prefix-list, community-list, route-map, ACL and QoS parsing for IOS-style configs.

Covers Cisco IOS/IOS-XE (MQC), Arista EOS and Aruba AOS-CX syntax.
"""
from __future__ import annotations

import re

from ..model import Device, Interface, is_ipv4
from ..policy import (AclEntry, cidr_norm, dscp_value, port_num, port_ops, proto, rate_kbps,
                      wild_cidr)

_PORT_OPS = ("eq", "neq", "gt", "lt", "range")


# --------------------------------------------------------------------- ACL lines
def parse_address(tokens: list[str], i: int, style: str) -> tuple[str, int]:
    """Read one address at tokens[i]. style 'wild' (Cisco) or 'cidr' (Arista, Aruba)."""
    tok = tokens[i].lower()
    if tok == "any":
        return "any", i + 1
    if tok == "host":
        return cidr_norm(tokens[i + 1]), i + 2
    if "/" in tok:
        return cidr_norm(tokens[i]), i + 1
    if not is_ipv4(tokens[i]):
        raise ValueError(f"alamat tidak dikenal: {tokens[i]}")
    if style == "wild" and i + 1 < len(tokens) and is_ipv4(tokens[i + 1]):
        return cidr_norm(wild_cidr(tokens[i], tokens[i + 1])), i + 2
    return cidr_norm(tokens[i]), i + 1


def parse_ports(tokens: list[str], i: int) -> tuple[str, list[int], int]:
    if i >= len(tokens) or tokens[i].lower() not in _PORT_OPS:
        return "", [], i
    op = tokens[i].lower()
    i += 1
    if op == "range":
        return (*port_ops("range", [port_num(tokens[i]), port_num(tokens[i + 1])]), i + 2)
    if op == "eq":
        ports = []
        while i < len(tokens):
            try:
                ports.append(port_num(tokens[i]))
                i += 1
            except ValueError:
                break
        return "eq", ports, i
    if op == "neq":
        raise ValueError("operator neq tidak didukung")
    return (*port_ops(op, [port_num(tokens[i])]), i + 1)


def parse_ace(tokens: list[str], seq: int, style: str, standard: bool = False) -> AclEntry:
    """'permit tcp 10.0.0.0 0.0.0.255 any eq 22 log' -> AclEntry."""
    action = tokens[0].lower()
    if action not in ("permit", "deny"):
        raise ValueError(f"aksi ACL tidak dikenal: {tokens[0]}")
    e = AclEntry(seq=seq, action=action)
    i = 1
    if standard:
        e.src, i = parse_address(tokens, i, style)
    else:
        e.protocol = proto(tokens[i])
        e.src, i = parse_address(tokens, i + 1, style)
        e.src_op, e.src_ports, i = parse_ports(tokens, i)
        e.dst, i = parse_address(tokens, i, style)
        e.dst_op, e.dst_ports, i = parse_ports(tokens, i)
    while i < len(tokens):
        tok = tokens[i].lower()
        if tok in ("log", "log-input"):
            e.log = True
        elif tok == "established":
            e.established = True
        elif tok in ("count", "hit-count"):
            pass
        else:
            raise ValueError(f"opsi ACL tidak didukung: {tokens[i]}")
        i += 1
    return e


def _acl_body(dev: Device, name: str, kind: str, body: list[str], style: str) -> None:
    acl = dev.policy.acl(name, kind)
    for line in body:
        t = line.split()
        seq = None
        if t and t[0].isdigit():
            seq, t = int(t[0]), t[1:]
        if not t:
            continue
        low = t[0].lower()
        if low in ("remark", "comment"):
            acl.entries.append(AclEntry(seq=seq or acl.next_seq(), action="remark",
                                        remark=" ".join(t[1:])))
            continue
        if low in ("statistics", "counters"):
            continue
        try:
            acl.entries.append(parse_ace(t, seq or acl.next_seq(), style, kind == "standard"))
        except (ValueError, IndexError) as exc:
            dev.unparsed.append(f"access-list {name}: {line}  ({exc})")


# ----------------------------------------------------------------- top-level
def handle_top(dev: Device, head: str, low: str, body: list[str]) -> bool:
    w = head.split()
    pol = dev.policy
    style = "wild" if dev.vendor == "cisco_ios" else "cidr"

    if low.startswith("ip prefix-list "):
        name = w[2]
        pol.prefix_list(name)
        if len(w) == 3:  # Arista block form
            for line in body:
                _prefix_line(dev, name, line.split())
        elif w[3].lower() != "description":
            _prefix_line(dev, name, w[3:])
        return True

    if low.startswith("ip community-list "):
        rest = w[2:]
        if rest[0].lower() == "expanded" or (rest[0].isdigit() and int(rest[0]) >= 100):
            return False
        if rest[0].lower() == "standard":
            rest = rest[1:]
        name, rest = rest[0], rest[1:]
        if rest and rest[0].lower() == "seq":
            rest = rest[2:]
        if rest and rest[0].lower() in ("permit", "deny"):
            pol.community_list(name).entries.append((rest[0].lower(), " ".join(rest[1:])))
            return True
        return False

    m = re.match(r"route-map (\S+)(?: (permit|deny))?(?: seq)?(?: (\d+))?$", head, re.I)
    if m:
        entry = pol.route_map(m.group(1)).entry(int(m.group(3) or 10), (m.group(2) or "permit").lower())
        for line in body:
            if not _route_map_line(entry, line):
                dev.unparsed.append(f"route-map {m.group(1)} {entry.seq}: {line}")
        return True

    m = re.match(r"ip access-list (?:(standard|extended) )?(\S+)$", head, re.I)
    if m:
        _acl_body(dev, m.group(2), (m.group(1) or "extended").lower(), body, style)
        return True
    m = re.match(r"access-list ip (\S+)$", head, re.I)
    if m:
        _acl_body(dev, m.group(1), "extended", body, "cidr")
        return True
    m = re.match(r"access-list (\d+) (.+)$", head, re.I)
    if m:
        num = int(m.group(1))
        kind = "standard" if num < 100 or 1300 <= num < 2000 else "extended"
        acl = pol.acl(m.group(1), kind)
        t = m.group(2).split()
        if t[0].lower() == "remark":
            acl.entries.append(AclEntry(seq=acl.next_seq(), action="remark", remark=" ".join(t[1:])))
        else:
            try:
                acl.entries.append(parse_ace(t, acl.next_seq(), "wild", kind == "standard"))
            except (ValueError, IndexError) as exc:
                dev.unparsed.append(f"{head}  ({exc})")
        return True

    m = re.match(r"class-map (?:type qos )?(?:(match-any|match-all) )?(\S+)$", head, re.I)
    if m:
        cls = pol.qos_class(m.group(2))
        cls.match_any = (m.group(1) or "match-all").lower() == "match-any"
        for line in body:
            t = line.split()
            lw = line.lower()
            if re.match(r"match (ip )?dscp ", lw):
                cls.match_dscp += [dscp_value(x) for x in t[2 if t[1].lower() == "dscp" else 3:]]
            elif re.match(r"match (ip )?access-group (name )?\S+$", lw):
                cls.match_acl = t[-1]
            elif lw == "match any":
                cls.match_any, cls.match_dscp = True, []
            elif not lw.startswith("description "):
                dev.unparsed.append(f"class-map {cls.name}: {line}")
        return True

    m = re.match(r"policy-map (?:type (?:quality-of-service|qos) )?(\S+)$", head, re.I)
    if m:
        _policy_map(dev, m.group(1), body)
        return True

    m = re.match(r"class ip (\S+)$", head, re.I)
    if m:
        _aruba_class(dev, m.group(1), body)
        return True
    m = re.match(r"policy (\S+)$", head, re.I)
    if m and dev.vendor == "aruba_aoscx":
        _aruba_policy(dev, m.group(1), body)
        return True
    return False


def _prefix_line(dev: Device, name: str, t: list[str]) -> None:
    seq = None
    if t and t[0].lower() == "seq":
        seq, t = int(t[1]), t[2:]
    if not t or t[0].lower() not in ("permit", "deny"):
        if t and t[0].lower() != "description":
            dev.unparsed.append(f"ip prefix-list {name}: {' '.join(t)}")
        return
    ge = le = None
    rest = t[2:]
    for i in range(0, len(rest) - 1, 2):
        key = rest[i].lower()
        if key == "ge":
            ge = int(rest[i + 1])
        elif key == "le":
            le = int(rest[i + 1])
        elif key == "eq":
            ge = le = int(rest[i + 1])
    dev.policy.prefix_list(name).add(t[0].lower(), t[1], ge, le, seq)


def _route_map_line(e, line: str) -> bool:
    t = line.split()
    low = line.lower()
    if low.startswith("match ip address prefix-list "):
        e.match_prefix += t[4:]
    elif re.match(r"match community(-list)? ", low):
        e.match_community += [x for x in t[2:] if x.lower() != "exact-match"]
    elif low.startswith("match tag "):
        e.match_tag = int(t[2])
    elif low.startswith("set local-preference "):
        e.set_local_pref = int(t[2])
    elif re.match(r"set metric \d+$", low):
        e.set_med = int(t[2])
    elif low.startswith("set community "):
        vals = t[2:]
        if vals and vals[-1].lower() == "additive":
            e.community_additive = True
            vals = vals[:-1]
        e.set_community = vals
    elif re.match(r"set ip next-hop \d", low):
        e.set_next_hop = t[3]
    elif low.startswith("set as-path prepend "):
        e.set_prepend = [x for x in t[3:] if x.isdigit()]
        if not e.set_prepend:
            return False
    elif low.startswith("set weight "):
        e.set_weight = int(t[2])
    elif low.startswith("set tag "):
        e.set_tag = int(t[2])
    elif not low.startswith("description "):
        return False
    return True


def _policy_map(dev: Device, name: str, body: list[str]) -> None:
    qp = dev.policy.qos_policy(name)
    act = None
    for line in body:
        t = line.split()
        low = line.lower()
        if low.startswith("class "):
            act = qp.action(t[-1])
            continue
        if act is None:
            if not low.startswith("description "):
                dev.unparsed.append(f"policy-map {name}: {line}")
            continue
        try:
            if re.match(r"priority( level \d+)?$", low):
                act.priority = True
            elif re.match(r"priority \d+", low):
                act.priority, act.priority_kbps = True, int(t[1])
            elif low.startswith("priority percent "):
                act.priority, act.bandwidth_pct = True, int(t[2])
            elif re.match(r"bandwidth (remaining )?percent \d+", low):
                act.bandwidth_pct = int(t[-1])
            elif re.match(r"bandwidth \d+$", low):
                act.bandwidth_kbps = int(t[1])
            elif re.match(r"set (ip )?dscp \S+$", low):
                act.set_dscp = dscp_value(t[-1])
            elif low.startswith("police rate "):  # Arista: police rate 1000 kbps ...
                unit = t[3].lower() if len(t) > 3 else "kbps"
                act.police_kbps = rate_kbps(t[2], {"kbps": "k", "mbps": "m", "gbps": "g", "bps": ""}.get(unit, "k"))
            elif low.startswith("police cir "):
                act.police_kbps = rate_kbps(t[2])
            elif re.match(r"police \d+", low):
                act.police_kbps = rate_kbps(t[1])
            elif low.startswith("shape average ") and t[2].isdigit():
                act.shape_kbps = rate_kbps(t[2])
            elif not low.startswith(("conform-action", "exceed-action", "violate-action")):
                dev.unparsed.append(f"policy-map {name} class {act.cls}: {line}")
        except (ValueError, IndexError):
            dev.unparsed.append(f"policy-map {name} class {act.cls}: {line}")


def _aruba_class(dev: Device, name: str, body: list[str]) -> None:
    cls = dev.policy.qos_class(name)
    cls.match_any = True
    acl_entries = []
    for line in body:
        t = line.split()
        seq = int(t[0]) if t and t[0].isdigit() else len(acl_entries) * 10 + 10
        if t and t[0].isdigit():
            t = t[1:]
        if not t or t[0].lower() != "match":
            if t and t[0].lower() != "comment":
                dev.unparsed.append(f"class ip {name}: {line}")
            continue
        low = [x.lower() for x in t]
        dscp = None
        if "dscp" in low:
            k = low.index("dscp")
            dscp = dscp_value(t[k + 1])
            t = t[:k] + t[k + 2:]
        if len(t) == 4 and [x.lower() for x in t[1:4]] == ["any", "any", "any"]:
            if dscp is not None:
                cls.match_dscp.append(dscp)
            continue
        try:
            acl_entries.append(parse_ace(["permit"] + t[1:], seq, "cidr"))
        except (ValueError, IndexError):
            dev.unparsed.append(f"class ip {name}: {line}")
    if acl_entries:
        acl = dev.policy.acl(f"CLS-{name}")
        acl.entries += acl_entries
        cls.match_acl = acl.name


def _aruba_policy(dev: Device, name: str, body: list[str]) -> None:
    qp = dev.policy.qos_policy(name)
    for line in body:
        t = line.split()
        if t and t[0].isdigit():
            t = t[1:]
        low = [x.lower() for x in t]
        if len(t) < 3 or low[0] != "class":
            dev.unparsed.append(f"policy {name}: {line}")
            continue
        act = qp.action(t[2])
        i = 3
        while i < len(t):
            if low[i] != "action":
                i += 1
                continue
            key = low[i + 1] if i + 1 < len(t) else ""
            if key == "dscp":
                act.set_dscp = dscp_value(t[i + 2])
                i += 3
            elif key == "cir" and i + 3 < len(t):
                act.police_kbps = rate_kbps(t[i + 3], "k")
                i += 4
            elif key == "local-priority":
                act.priority = int(t[i + 2]) >= 6
                i += 3
            else:
                i += 2


# --------------------------------------------------------------- interface
def handle_interface(dev: Device, itf: Interface, low: str, t: list[str]) -> bool:
    pol = dev.policy
    m = re.match(r"ip access-group (\S+) (in|out)$", low)
    if m:
        pol.bind_acl(t[2], itf.name, m.group(2))
        return True
    m = re.match(r"apply access-list ip (\S+) (in|out|routed-in|routed-out)$", low)
    if m:
        pol.bind_acl(t[3], itf.name, "in" if "in" in m.group(2) else "out")
        return True
    m = re.match(r"service-policy (?:type qos )?(input|output) (\S+)$", low)
    if m:
        pol.bind_qos(t[-1], itf.name, "in" if m.group(1) == "input" else "out")
        return True
    m = re.match(r"apply policy (\S+) (in|out|routed-in|routed-out)$", low)
    if m:
        pol.bind_qos(t[2], itf.name, "in" if "in" in m.group(2) else "out")
        return True
    return False
