"""MikroTik RouterOS v7: routing filter rules, firewall filter (ACL), mangle + queue tree (QoS)."""
from __future__ import annotations

import re

from ..model import Device
from ..policy import AclEntry, cidr_norm, dscp_value, parse_port_text, proto, rate_kbps

ROS_PROTO_BACK = {"ipsec-esp": "50", "ipsec-ah": "51", "ospf": "89", "pim": "103", "igmp": "2",
                  "vrrp": "112", "gre": "47"}
_ACL_KEYS = {"chain", "action", "protocol", "src-address", "dst-address", "src-port", "dst-port",
             "connection-state", "in-interface", "out-interface", "log", "comment", "jump-target",
             "log-prefix", "disabled"}
IMPLICIT = "NetManage: implicit deny"


class State:
    def __init__(self):
        self.rules: dict[str, list[str]] = {}
        self.filters: list[dict] = []
        self.mangle: list[dict] = []
        self.queues: list[dict] = []
        self.ospf_chain = ""
        self.prepend_counts: list[tuple] = []


def handle(st: State, path: str, p: dict[str, str]) -> bool:
    if path == "/routing filter rule":
        st.rules.setdefault(p.get("chain", ""), []).append(p.get("rule", ""))
        return True
    if path == "/ip firewall filter":
        st.filters.append(p)
        return True
    if path == "/ip firewall mangle" and p.get("comment", "").startswith("QOS "):
        st.mangle.append(p)
        return True
    if path == "/queue tree" and p.get("comment", "").startswith("QOS "):
        st.queues.append(p)
        return True
    return False


# ------------------------------------------------------------ routing filters
def _split_top(text: str, sep: str) -> list[str]:
    parts, depth, buf, i = [], 0, "", 0
    while i < len(text):
        c = text[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        if depth == 0 and text.startswith(sep, i):
            parts.append(buf.strip())
            buf = ""
            i += len(sep)
            continue
        buf += c
        i += 1
    if buf.strip():
        parts.append(buf.strip())
    return parts


def _strip_parens(text: str) -> str:
    text = text.strip()
    while text.startswith("(") and text.endswith(")") and _balanced(text[1:-1]):
        text = text[1:-1].strip()
    return text


def _balanced(text: str) -> bool:
    depth = 0
    for c in text:
        depth += c == "("
        depth -= c == ")"
        if depth < 0:
            return False
    return depth == 0


def _prefix_term(text: str) -> tuple[str, int, int]:
    """'dst in 10.0.0.0/8 && dst-len in 16-24' -> ('10.0.0.0/8', 16, 24)."""
    text = _strip_parens(text)
    m = re.match(r"dst (in|==) (\S+?)(?:\s*&&\s*dst-len (?:in (\d+)-(\d+)|== ?(\d+)|<= ?(\d+)))?$", text)
    if not m:
        raise ValueError(f"kondisi tidak didukung: {text}")
    prefix = m.group(2)
    plen = int(prefix.split("/")[1]) if "/" in prefix else 32
    if m.group(3):
        return prefix, int(m.group(3)), int(m.group(4))
    if m.group(5):
        return prefix, int(m.group(5)), int(m.group(5))
    if m.group(6):
        return prefix, plen, int(m.group(6))
    return (prefix, plen, plen) if m.group(1) == "==" else (prefix, plen, 32)


def _parse_rule(dev: Device, chain: str, seq: int, text: str, st: State) -> None:
    pol = dev.policy
    m = re.match(r"^\s*if\s*\((.*)\)\s*\{(.*)\}\s*$", text, re.S)
    cond, body = (m.group(1), m.group(2)) if m else ("", text)
    e = pol.route_map(chain).entry(seq)
    pl = None

    def plist():
        nonlocal pl
        if pl is None:
            pl = pol.prefix_list(f"{chain}-{seq}")
            e.match_prefix.append(pl.name)
        return pl

    terms: list[str] = []
    for term in (_split_top(cond, "&&") if cond.strip() else []):
        if term.startswith("dst-len") and terms and terms[-1].lstrip("(").startswith("dst "):
            terms[-1] = f"{terms[-1]} && {term}"
        else:
            terms.append(term)
    for term in terms:
        neg = term.startswith("!")
        inner = _strip_parens(term[1:] if neg else term)
        if inner == "false":
            plist()
            continue
        if inner.startswith("bgp-communities includes") or " || bgp-communities" in inner:
            cl = pol.community_list(f"{chain}-{seq}-CL")
            for part in _split_top(inner, "||"):
                val = _strip_parens(part).split("includes", 1)[1].strip()
                cl.entries.append(("permit", val.replace(",", " ")))
            e.match_community.append(cl.name)
            continue
        alts = _split_top(inner, "||")
        if len(alts) == 1 and "&&" in inner and not inner.startswith("dst"):
            alts = [inner]
        for alt in alts:
            prefix, lo, hi = _prefix_term(alt)
            plist().add("deny" if neg else "permit", prefix, lo, hi)
    terminal = ""
    for act in [a.strip() for a in body.split(";") if a.strip()]:
        w = act.split()
        if act in ("accept", "reject"):
            terminal = act
        elif w[:2] == ["set", "bgp-local-pref"]:
            e.set_local_pref = int(w[2])
        elif w[:2] in (["set", "bgp-med"], ["set", "ospf-ext-metric"]):
            e.set_med = int(w[2])
        elif w[:2] == ["set", "ospf-ext-tag"]:
            e.set_tag = int(w[2])
        elif w[1:2] == ["bgp-communities"] and w[0] in ("set", "append"):
            e.set_community = w[2].split(",")
            e.community_additive = w[0] == "append"
        elif w[:2] == ["set", "gw"]:
            e.set_next_hop = w[2]
        elif w[:2] == ["set", "bgp-path-prepend"]:
            st.prepend_counts.append((e, int(w[2])))
        elif w[:2] == ["set", "bgp-weight"]:
            e.set_weight = int(w[2])
        else:
            dev.unparsed.append(f"/routing filter rule chain={chain}: {act}")
    e.action = "deny" if terminal == "reject" else "permit"
    if not terminal:
        dev.unparsed.append(f"/routing filter rule chain={chain}: rule tanpa accept/reject, dianggap permit")


# --------------------------------------------------------------- firewall
def _entry(p: dict[str, str], seq: int) -> AclEntry:
    unknown = set(p) - _ACL_KEYS
    if unknown:
        raise ValueError("properti tidak didukung: " + ", ".join(sorted(unknown)))
    action = p.get("action", "accept")
    if action not in ("accept", "drop", "reject"):
        raise ValueError(f"action={action} tidak didukung")
    e = AclEntry(seq=seq, action="permit" if action == "accept" else "deny")
    if p.get("protocol"):
        e.protocol = ROS_PROTO_BACK.get(p["protocol"], None) or proto(p["protocol"])
    if p.get("src-address"):
        e.src = cidr_norm(p["src-address"])
    if p.get("dst-address"):
        e.dst = cidr_norm(p["dst-address"])
    for key, side in (("src-port", "src"), ("dst-port", "dst")):
        if p.get(key):
            v = p[key]
            op, ports = ("eq", [int(x) for x in v.split(",")]) if "," in v else parse_port_text(v)
            setattr(e, f"{side}_op", op)
            setattr(e, f"{side}_ports", ports)
    if "established" in p.get("connection-state", ""):
        e.established = True
    elif p.get("connection-state"):
        raise ValueError(f"connection-state={p['connection-state']} tidak didukung")
    e.log = p.get("log") == "yes"
    return e


def finish(dev: Device, st: State, nm) -> None:
    pol = dev.policy
    for chain, rules in st.rules.items():
        for i, text in enumerate(rules):
            try:
                _parse_rule(dev, chain, (i + 1) * 10, text, st)
            except (ValueError, IndexError) as exc:
                dev.unparsed.append(f"/routing filter rule chain={chain} rule={text}  ({exc})")
    asn = dev.bgp.asn if dev.bgp else ""
    for e, count in st.prepend_counts:
        e.set_prepend = [asn or "0"] * count

    builtin = ("input", "forward", "output")
    from_builtin: set[str] = set()
    for p in st.filters:
        if p.get("disabled") == "yes":
            continue
        chain = p.get("chain", "")
        if chain in builtin and p.get("action") == "jump":
            target = p.get("jump-target", "")
            if p.get("in-interface"):
                pol.bind_acl(target, nm(p["in-interface"]), "in")
            elif p.get("out-interface"):
                pol.bind_acl(target, nm(p["out-interface"]), "out")
            continue
        if p.get("comment", "").startswith(IMPLICIT):
            continue
        iface = p.get("in-interface") or p.get("out-interface") or ""
        name = chain if chain not in builtin else f"FW-{chain}" + (f"-{iface}" if iface else "")
        if chain in builtin:
            from_builtin.add(name)
        acl = pol.acl(name)
        if p.get("comment"):
            acl.entries.append(AclEntry(seq=acl.next_seq(), action="remark", remark=p["comment"]))
        try:
            data = {k: v for k, v in p.items() if not (chain in builtin and k in ("in-interface", "out-interface"))}
            acl.entries.append(_entry(data, acl.next_seq()))
        except (ValueError, IndexError) as exc:
            dev.unparsed.append(f"/ip firewall filter chain={chain}: {exc}")
        if chain in builtin and iface:
            pol.bind_acl(name, nm(iface), "in" if p.get("in-interface") else "out")
    for name in from_builtin:  # RouterOS accepts at the end of a built-in chain
        acl = pol.acls[name]
        acl.entries.append(AclEntry(seq=acl.next_seq(), action="permit"))

    # QoS from NetManage-tagged mangle + queue tree
    for p in st.mangle:
        parts = p["comment"].split()
        if len(parts) < 3:
            continue
        pname, cname = parts[1], parts[2]
        qp = pol.qos_policy(pname)
        act = qp.action(cname)
        iface = p.get("in-interface") or p.get("out-interface")
        if iface:
            pol.bind_qos(pname, nm(iface), "in" if p.get("in-interface") else "out")
        if p.get("action") == "change-dscp":
            act.set_dscp = int(p.get("new-dscp", "0"))
            continue
        if cname == "class-default":
            continue
        cls = pol.qos_class(cname)
        cls.match_any = True
        if p.get("dscp"):
            d = dscp_value(p["dscp"])
            if d not in cls.match_dscp:
                cls.match_dscp.append(d)
        keys = {"protocol", "src-address", "dst-address", "src-port", "dst-port"} & set(p)
        if keys and f"{pname} {cname}" not in st.__dict__.setdefault("_seen", set()) | {""}:
            acl = pol.acl(f"CLS-{cname}")
            data = {k: p[k] for k in keys}
            e = _entry({**data, "action": "accept"}, acl.next_seq())
            sig = (e.protocol, e.src, e.dst, e.src_op, tuple(e.src_ports), e.dst_op, tuple(e.dst_ports))
            if sig not in [(x.protocol, x.src, x.dst, x.src_op, tuple(x.src_ports), x.dst_op, tuple(x.dst_ports))
                           for x in acl.entries]:
                acl.entries.append(e)
            cls.match_acl = acl.name
    for q in st.queues:
        parts = q["comment"].split()
        if len(parts) < 3:
            continue
        act = pol.qos_policy(parts[1]).action(parts[2])
        if q.get("max-limit"):
            act.police_kbps = rate_kbps(q["max-limit"])
        if q.get("limit-at"):
            act.bandwidth_kbps = rate_kbps(q["limit-at"])
        if q.get("priority") == "1":
            act.priority = True
            act.priority_kbps, act.bandwidth_kbps = act.bandwidth_kbps, None
