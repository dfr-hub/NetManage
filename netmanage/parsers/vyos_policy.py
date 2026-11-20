"""VyOS policy (prefix-list, community-list, route-map), firewall and QoS parsing."""
from __future__ import annotations

import re

from ..model import Device
from ..policy import AclEntry, cidr_norm, dscp_value, parse_port_text, proto, rate_kbps


class State:
    def __init__(self):
        self.prefix: dict[str, dict[int, dict]] = {}
        self.community: dict[str, dict[int, dict]] = {}
        self.route_map: dict[str, dict[int, list[list[str]]]] = {}
        self.fw: dict[str, dict] = {}  # name -> {"default": str, "rules": {n: {...}}}
        self.jumps: dict[tuple[str, int], dict] = {}
        self.qos: dict[tuple[str, str], dict] = {}  # (shaper|limiter, name) -> {"classes": {n: [...]}, "default": [...]}
        self.qos_if: list[tuple[str, str, str]] = []


def _rate(text: str) -> tuple[int | None, int | None]:
    """'512kbit' -> (512, None); '20%' -> (None, 20)."""
    text = text.strip("'")
    if text.endswith("%"):
        return None, int(text[:-1])
    if text == "auto":
        return None, None
    return rate_kbps(text), None


def statement(st: State, t: list[str]) -> bool:
    if t[0] == "policy" and len(t) > 4:
        kind, name, rest = t[1], t[2], t[3:]
        if kind == "prefix-list" and rest[0] == "rule":
            r = st.prefix.setdefault(name, {}).setdefault(int(rest[1]), {})
            r[rest[2]] = rest[3] if len(rest) > 3 else ""
            return True
        if kind == "community-list" and rest[0] == "rule":
            r = st.community.setdefault(name, {}).setdefault(int(rest[1]), {})
            r[rest[2]] = " ".join(rest[3:])
            return True
        if kind == "route-map" and rest[0] == "rule":
            st.route_map.setdefault(name, {}).setdefault(int(rest[1]), []).append(rest[2:])
            return True
        return False
    if t[0] == "firewall":
        rest = t[1:]
        if rest and rest[0] == "ipv4":
            rest = rest[1:]
        if len(rest) > 3 and rest[0] == "name":
            fw = st.fw.setdefault(rest[1], {"default": "drop", "rules": {}})
            if rest[2] == "default-action":
                fw["default"] = rest[3]
            elif rest[2] == "rule" and len(rest) > 4:
                fw["rules"].setdefault(int(rest[3]), []).append(rest[4:])
            return True
        if len(rest) > 5 and rest[0] in ("forward", "input", "output") and rest[1:3] == ["filter", "rule"]:
            j = st.jumps.setdefault((rest[0], int(rest[3])), {})
            key = rest[4]
            if key == "jump-target":
                j["target"] = rest[5]
            elif key in ("inbound-interface", "outbound-interface"):
                j["dir"] = "in" if key.startswith("in") else "out"
                j["if"] = rest[-1]
            return True
        return False
    if t[:2] == ["qos", "policy"] and len(t) > 4:
        q = st.qos.setdefault((t[2], t[3]), {"classes": {}, "default": []})
        rest = t[4:]
        if rest[0] == "class" and len(rest) > 2:
            q["classes"].setdefault(int(rest[1]), []).append(rest[2:])
        elif rest[0] == "default":
            q["default"].append(rest[1:])
        return True
    if t[:2] == ["qos", "interface"] and len(t) > 3:
        st.qos_if.append((t[2], "in" if t[3] == "ingress" else "out", t[4] if len(t) > 4 else ""))
        return True
    return False


def interface_firewall(st: State, ifname: str, rest: list[str]) -> bool:
    """VyOS 1.3: 'interfaces ethernet eth0 firewall in name X'."""
    if len(rest) >= 4 and rest[0] == "firewall" and rest[2] == "name":
        st.jumps[(f"if-{ifname}-{rest[1]}", 0)] = {"target": rest[3], "dir": "in" if rest[1] in ("in", "local") else "out",
                                                     "if": ifname}
        return True
    return False


def _ace(seq: int, lines: list[list[str]]) -> tuple[AclEntry | None, str]:
    e = AclEntry(seq=seq)
    remark = ""
    action = ""
    for ln in lines:
        k = ln[0]
        if k == "action":
            action = ln[1]
        elif k == "protocol":
            e.protocol = proto(ln[1])
        elif k in ("source", "destination") and len(ln) > 2:
            if ln[1] == "address":
                setattr(e, "src" if k == "source" else "dst", cidr_norm(ln[2]))
            elif ln[1] == "port":
                op, ports = ("eq", [int(p) for p in ln[2].split(",")]) if "," in ln[2] else parse_port_text(ln[2])
                setattr(e, ("src" if k == "source" else "dst") + "_op", op)
                setattr(e, ("src" if k == "source" else "dst") + "_ports", ports)
            else:
                raise ValueError(f"{k} {ln[1]} tidak didukung")
        elif k == "log":
            e.log = True
        elif k == "description":
            remark = " ".join(ln[1:])
        elif k == "state":
            if "established" in ln:
                e.established = True
        elif k == "disable":
            return None, ""
        else:
            raise ValueError(f"rule {' '.join(ln)} tidak didukung")
    if action not in ("accept", "drop", "reject"):
        raise ValueError(f"action {action or '-'} tidak didukung")
    e.action = "permit" if action == "accept" else "deny"
    return e, remark


def finish(dev: Device, st: State) -> None:
    pol = dev.policy
    for name, rules in st.prefix.items():
        pl = pol.prefix_list(name)
        for seq, r in sorted(rules.items()):
            if "prefix" not in r:
                continue
            ge = int(r["ge"]) if r.get("ge") else None
            le = int(r["le"]) if r.get("le") else None
            pl.add(r.get("action", "permit"), r["prefix"], ge, le, seq)
    for name, rules in st.community.items():
        cl = pol.community_list(name)
        for _, r in sorted(rules.items()):
            value = r.get("regex", "").replace("_", " ").strip("^$ ")
            if value:
                cl.entries.append((r.get("action", "permit"), value))
    for name, rules in st.route_map.items():
        rm = pol.route_map(name)
        for seq, lines in sorted(rules.items()):
            e = rm.entry(seq)
            for ln in lines:
                if not _rm_line(e, ln, dev):
                    dev.unparsed.append(f"policy route-map {name} rule {seq} {' '.join(ln)}")

    for name, fw in st.fw.items():
        acl = pol.acl(name)
        for seq, lines in sorted(fw["rules"].items()):
            try:
                e, remark = _ace(seq, lines)
            except (ValueError, IndexError) as exc:
                dev.unparsed.append(f"firewall name {name} rule {seq}: {exc}")
                continue
            if e is None:
                continue
            if remark:
                acl.entries.append(AclEntry(seq=seq - 1, action="remark", remark=remark))
            acl.entries.append(e)
        if fw["default"] == "accept":
            acl.entries.append(AclEntry(seq=acl.next_seq(), action="permit"))
    for (_chain, _n), j in sorted(st.jumps.items()):
        if j.get("target") in pol.acls and j.get("if"):
            pol.bind_acl(j["target"], j["if"], j.get("dir", "in"))

    for (kind, name), q in st.qos.items():
        qp = pol.qos_policy(name[:-3] if kind == "limiter" and name.endswith("-IN") else name)
        for n, lines in sorted(q["classes"].items()):
            desc = next((" ".join(ln[1:]) for ln in lines if ln[0] == "description"), "")
            cname = desc or f"C{n}"
            act = qp.action(cname)
            cls = pol.qos_class(cname)
            cls.match_any = True
            matches: dict[str, list[list[str]]] = {}
            for ln in lines:
                if ln[0] == "match" and len(ln) > 3:
                    matches.setdefault(ln[1], []).append(ln[2:])
            for mname, mlines in matches.items():
                if all(m[:2] == ["ip", "dscp"] for m in mlines):
                    for m in mlines:
                        d = dscp_value(m[2])
                        if d not in cls.match_dscp:
                            cls.match_dscp.append(d)
                    continue
                acl = pol.acl(f"CLS-{cname}")
                if (cname, mname) in st.__dict__.setdefault("_built", set()):
                    continue
                st._built.add((cname, mname))
                e = AclEntry(seq=(len(acl.entries) + 1) * 10)
                for m in mlines:
                    if m[0] != "ip":
                        continue
                    if m[1] == "protocol":
                        e.protocol = proto(m[2])
                    elif m[1] in ("source", "destination") and m[2] == "address":
                        setattr(e, "src" if m[1] == "source" else "dst", cidr_norm(m[3]))
                    elif m[1] in ("source", "destination") and m[2] == "port":
                        op, ports = parse_port_text(m[3])
                        side = "src" if m[1] == "source" else "dst"
                        setattr(e, f"{side}_op", op)
                        setattr(e, f"{side}_ports", ports)
                acl.entries.append(e)
                cls.match_acl = acl.name
            _qos_actions(act, lines, kind)
        if q["default"] and not any(ln[0] == "description" for ln in q["default"]) or \
                any(ln[0] in ("ceiling", "priority", "set-dscp") for ln in q["default"]):
            _qos_actions(qp.action("class-default"), q["default"], kind)
    for ifname, direction, name in st.qos_if:
        base = name[:-3] if direction == "in" and name.endswith("-IN") else name
        if base in pol.qos_policies:
            pol.bind_qos(base, ifname, direction)


def _qos_actions(act, lines: list[list[str]], kind: str) -> None:
    prio = any(ln[0] == "priority" and ln[1].strip("'") not in ("0",) for ln in lines)
    for ln in lines:
        k = ln[0]
        if k == "bandwidth":
            kbps, pct = _rate(ln[1])
            if pct == 1:  # placeholder written by NetManage for classes without a guarantee
                continue
            if kind == "limiter":
                act.police_kbps = kbps
            elif prio:
                act.priority, act.priority_kbps = True, kbps
                if pct and pct != 100:
                    act.bandwidth_pct = pct
            else:
                act.bandwidth_kbps = kbps
                if pct and pct not in (100,):
                    act.bandwidth_pct = pct
        elif k == "ceiling":
            act.shape_kbps = _rate(ln[1])[0]
        elif k == "priority":
            act.priority = prio
        elif k == "set-dscp":
            act.set_dscp = dscp_value(ln[1])


def _rm_line(e, ln: list[str], dev: Device) -> bool:
    k = ln[0]
    if k == "action":
        e.action = "permit" if ln[1] == "permit" else "deny"
    elif ln[:4] == ["match", "ip", "address", "prefix-list"]:
        e.match_prefix.append(ln[4])
    elif ln[:3] == ["match", "community", "community-list"]:
        e.match_community.append(ln[3])
    elif ln[:2] == ["match", "tag"]:
        e.match_tag = int(ln[2])
    elif ln[:2] == ["set", "local-preference"]:
        e.set_local_pref = int(ln[2])
    elif ln[:2] == ["set", "metric"]:
        e.set_med = int(ln[2])
    elif ln[:2] == ["set", "community"]:
        vals = ln[2:]
        if vals and vals[0] in ("add", "replace"):
            e.community_additive = vals[0] == "add"
            vals = vals[1:]
        vals = " ".join(vals).split()
        if vals and vals[-1] == "additive":
            e.community_additive, vals = True, vals[:-1]
        e.set_community += vals
    elif ln[:2] == ["set", "ip-next-hop"]:
        e.set_next_hop = ln[2]
    elif ln[:3] == ["set", "as-path", "prepend"] or ln[:2] == ["set", "as-path-prepend"]:
        e.set_prepend = " ".join(ln[3:] if ln[1] == "as-path" else ln[2:]).split()
    elif ln[:2] == ["set", "weight"]:
        e.set_weight = int(ln[2])
    elif ln[:2] == ["set", "tag"]:
        e.set_tag = int(ln[2])
    elif k == "description":
        pass
    else:
        return False
    return True


__all__ = ["State", "statement", "finish", "interface_firewall", "re"]
