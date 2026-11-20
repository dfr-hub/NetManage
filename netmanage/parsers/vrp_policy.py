"""ip-prefix, community-filter, route-policy, ACL and QoS (MQC) parsing for Huawei VRP and H3C Comware."""
from __future__ import annotations

import re

from ..model import Device, Interface
from ..policy import AclEntry, cidr_norm, dscp_value, port_num, port_ops, proto, wild_cidr


def _addr(tokens: list[str], i: int) -> tuple[str, int]:
    """'source 10.0.0.0 0.0.0.255' / 'source any' / 'source 1.1.1.1 0'."""
    if tokens[i].lower() == "any":
        return "any", i + 1
    addr = tokens[i]
    if i + 1 < len(tokens) and re.fullmatch(r"\d+(\.\d+){3}|0", tokens[i + 1]):
        wild = "0.0.0.0" if tokens[i + 1] == "0" else tokens[i + 1]
        return cidr_norm(wild_cidr(addr, wild)), i + 2
    return cidr_norm(addr), i + 1


def _ports(tokens: list[str], i: int) -> tuple[str, list[int], int]:
    op = tokens[i].lower()
    if op == "range":
        return (*port_ops("range", [port_num(tokens[i + 1]), port_num(tokens[i + 2])]), i + 3)
    if op in ("eq", "gt", "lt"):
        return (*port_ops(op, [port_num(tokens[i + 1])]), i + 2)
    raise ValueError(f"operator port tidak dikenal: {tokens[i]}")


def parse_rule(t: list[str], basic: bool) -> AclEntry | None:
    """t = tokens after 'rule'. Returns None for 'rule N description ...'."""
    seq = int(t[0]) if t[0].isdigit() else 0
    if t[0].isdigit():
        t = t[1:]
    action = t[0].lower()
    if action not in ("permit", "deny"):
        raise ValueError(f"aksi rule tidak dikenal: {t[0]}")
    e = AclEntry(seq=seq, action=action)
    i = 1
    if not basic and i < len(t) and t[i].lower() not in ("source", "destination", "logging"):
        e.protocol = proto(t[i])
        i += 1
    while i < len(t):
        key = t[i].lower()
        if key == "source":
            e.src, i = _addr(t, i + 1)
        elif key == "destination":
            e.dst, i = _addr(t, i + 1)
        elif key == "source-port":
            e.src_op, e.src_ports, i = _ports(t, i + 1)
        elif key == "destination-port":
            e.dst_op, e.dst_ports, i = _ports(t, i + 1)
        elif key in ("logging", "log"):
            e.log, i = True, i + 1
        elif key == "established":
            e.established, i = True, i + 1
        elif key == "tcp-flag" and i + 1 < len(t) and t[i + 1].lower() == "established":
            e.established, i = True, i + 2
        elif key == "counting":
            i += 1
        else:
            raise ValueError(f"opsi rule tidak didukung: {t[i]}")
    return e


def handle_top(dev: Device, head: str, low: str, body: list[str], state: dict) -> bool:
    w = head.split()
    pol = dev.policy

    # Huawei: ip ip-prefix NAME index 10 permit 10.0.0.0 8 greater-equal 16 less-equal 24
    # H3C:    ip prefix-list NAME index 10 permit 10.0.0.0 8 greater-equal 16 less-equal 24
    m = re.match(r"ip (?:ip-prefix|prefix-list) (\S+)(?: index (\d+))? (permit|deny) (\S+) (\d+)(.*)$", head, re.I)
    if m:
        rest = m.group(6).split()
        ge = le = None
        for k in range(0, len(rest) - 1, 2):
            if rest[k].lower() == "greater-equal":
                ge = int(rest[k + 1])
            elif rest[k].lower() == "less-equal":
                le = int(rest[k + 1])
        seq = int(m.group(2)) if m.group(2) else None
        pol.prefix_list(m.group(1)).add(m.group(3).lower(), f"{m.group(4)}/{m.group(5)}", ge, le, seq)
        return True
    m = re.match(r"ip (?:community-filter|community-list) (?:basic )?(\S+)(?: index \d+)? (permit|deny) (.+)$",
                 head, re.I)
    if m and "advanced" not in low:
        name = m.group(1)
        if name.isdigit() and int(name) > 99:
            return False
        pol.community_list(name).entries.append((m.group(2).lower(), m.group(3).strip()))
        return True

    m = re.match(r"route-policy (\S+) (permit|deny) node (\d+)$", head, re.I)
    if m:
        e = pol.route_map(m.group(1)).entry(int(m.group(3)), m.group(2).lower())
        for line in body:
            if not _rp_line(e, line):
                dev.unparsed.append(f"route-policy {m.group(1)} node {e.seq}: {line}")
        return True

    m = re.match(r"acl (?:(advance|advanced|basic) )?(?:name (\S+)|number (\d+)|(\d+))(?: name (\S+))?"
                 r"(?: (advance|basic))?(?: match-order \S+)?$", head, re.I)
    if m and low.startswith("acl "):
        number = m.group(3) or m.group(4) or ""
        name = m.group(2) or m.group(5) or number
        kind_word = (m.group(1) or m.group(6) or "").lower()
        basic = kind_word == "basic" or (number.isdigit() and 2000 <= int(number) < 3000)
        acl = pol.acl(name, "standard" if basic else "extended")
        for line in body:
            t = line.split()
            lw = line.lower()
            if lw.startswith("description "):
                acl.entries.insert(0, AclEntry(seq=0, action="remark", remark=line.split(None, 1)[1]))
                continue
            if not lw.startswith("rule "):
                dev.unparsed.append(f"acl {name}: {line}")
                continue
            if len(t) > 3 and t[2].lower() in ("description", "comment", "remark"):
                acl.entries.append(AclEntry(seq=int(t[1]) - 1, action="remark", remark=" ".join(t[3:])))
                continue
            try:
                e = parse_rule(t[1:], basic)
                e.seq = e.seq or acl.next_seq()
                acl.entries.append(e)
            except (ValueError, IndexError) as exc:
                dev.unparsed.append(f"acl {name}: {line}  ({exc})")
        acl.entries.sort(key=lambda x: (x.seq, x.action != "remark"))
        return True

    m = re.match(r"traffic classifier (\S+)(?: operator (and|or))?", head, re.I)
    if m:
        cls = pol.qos_class(m.group(1))
        cls.match_any = (m.group(2) or "and").lower() == "or"
        for line in body:
            t = line.split()
            lw = line.lower()
            if lw.startswith("if-match dscp "):
                cls.match_dscp += [dscp_value(x) for x in t[2:]]
            elif re.match(r"if-match acl (name )?\S+$", lw):
                cls.match_acl = t[-1]
            elif lw == "if-match any":
                cls.match_any = True
            else:
                dev.unparsed.append(f"traffic classifier {cls.name}: {line}")
        return True

    m = re.match(r"traffic behavior (\S+)$", head, re.I)
    if m:
        state.setdefault("behaviors", {})[m.group(1)] = body
        return True

    m = re.match(r"(?:traffic|qos) policy (\S+)", head, re.I)
    if m:
        pairs = state.setdefault("policies", {}).setdefault(m.group(1), [])
        pol.qos_policy(m.group(1))
        for line in body:
            mm = re.match(r"classifier (\S+) behavior (\S+)", line, re.I)
            if mm:
                pairs.append((mm.group(1), mm.group(2)))
            elif not line.lower().startswith(("description", "statistic")):
                dev.unparsed.append(f"qos policy {m.group(1)}: {line}")
        return True
    return False


def finish(dev: Device, state: dict) -> None:
    """Resolve 'classifier X behavior Y' pairs once all behaviors are known."""
    behaviors = state.get("behaviors", {})
    for pname, pairs in state.get("policies", {}).items():
        qp = dev.policy.qos_policy(pname)
        for cname, bname in pairs:
            cls = "class-default" if cname.lower() in ("default-class", "class-default") else cname
            act = qp.action(cls)
            for line in behaviors.get(bname, []):
                t = line.split()
                lw = line.lower()
                try:
                    if lw.startswith("remark dscp "):
                        act.set_dscp = dscp_value(t[2])
                    elif lw.startswith("car cir "):
                        act.police_kbps = int(t[2])
                    elif lw.startswith("gts cir "):
                        act.shape_kbps = int(t[2])
                    elif re.match(r"queue (ef|llq) bandwidth pct \d+", lw):
                        act.priority, act.bandwidth_pct = True, int(t[-1])
                    elif re.match(r"queue (ef|llq) bandwidth \d+", lw):
                        act.priority, act.priority_kbps = True, int(t[3])
                    elif re.match(r"queue af bandwidth (pct|remaining-pct) \d+", lw):
                        act.bandwidth_pct = int(t[-1])
                    elif re.match(r"queue af bandwidth \d+", lw):
                        act.bandwidth_kbps = int(t[3])
                    elif lw.startswith(("statistic", "permit")):
                        pass
                    else:
                        dev.unparsed.append(f"traffic behavior {bname}: {line}")
                except (ValueError, IndexError):
                    dev.unparsed.append(f"traffic behavior {bname}: {line}")


def _rp_line(e, line: str) -> bool:
    t = line.split()
    low = line.lower()
    if re.match(r"if-match (ip-prefix|ip address prefix-list) \S+$", low):
        e.match_prefix.append(t[-1])
    elif re.match(r"if-match (community-filter|community) ", low):
        e.match_community += [x for x in t[2:] if x.lower() not in ("whole-match",)]
    elif low.startswith("if-match tag "):
        e.match_tag = int(t[2])
    elif low.startswith("apply local-preference "):
        e.set_local_pref = int(t[2])
    elif re.match(r"apply cost \d+$", low):
        e.set_med = int(t[2])
    elif low.startswith("apply community "):
        vals = t[2:]
        if vals and vals[-1].lower() == "additive":
            e.community_additive, vals = True, vals[:-1]
        e.set_community = vals
    elif low.startswith("apply ip-address next-hop "):
        e.set_next_hop = t[3]
    elif low.startswith("apply as-path "):
        vals = t[2:]
        if vals and vals[-1].lower() in ("additive", "replace"):
            if vals[-1].lower() == "replace":
                return False
            vals = vals[:-1]
        e.set_prepend = vals
    elif low.startswith("apply preferred-value "):
        e.set_weight = int(t[2])
    elif low.startswith("apply tag "):
        e.set_tag = int(t[2])
    else:
        return False
    return True


def handle_interface(dev: Device, itf: Interface, low: str, t: list[str]) -> bool:
    pol = dev.policy
    m = re.match(r"traffic-filter (inbound|outbound) acl (?:name )?(\S+)$", low)
    if m:
        pol.bind_acl(t[-1], itf.name, "in" if m.group(1) == "inbound" else "out")
        return True
    m = re.match(r"packet-filter (?:name )?(\S+) (inbound|outbound)$", low)
    if m:
        pol.bind_acl(t[-2], itf.name, "in" if m.group(2) == "inbound" else "out")
        return True
    m = re.match(r"(?:traffic-policy|qos apply policy) (\S+) (inbound|outbound)$", low)
    if m:
        pol.bind_qos(t[-2], itf.name, "in" if m.group(2) == "inbound" else "out")
        return True
    return False
