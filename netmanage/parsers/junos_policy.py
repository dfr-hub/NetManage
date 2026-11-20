"""Junos policy-options, firewall filter, policer and class-of-service parsing.

Statements are collected while the main parser walks the 'set' lines and are converted
in finish(), when every referenced object is known.
"""
from __future__ import annotations

import ipaddress
import re

from ..model import Device
from ..policy import AclEntry, Policies, RouteMap, cidr_norm, dscp_value, parse_port_text, proto, rate_kbps

GENERATED_EXPORT = ("BGP-EXPORT", "OSPF-EXPORT")


class State:
    def __init__(self):
        self.prefix_lists: dict[str, list[str]] = {}
        self.communities: dict[str, list[str]] = {}
        self.policies: dict[str, dict[str, dict]] = {}  # policy -> term -> {from: [...], then: [...]}
        self.filters: dict[str, dict[str, dict]] = {}
        self.policers: dict[str, int] = {}
        self.fc_sched: dict[str, str] = {}  # forwarding-class -> scheduler
        self.schedulers: dict[str, dict] = {}
        self.if_sched_map: dict[str, str] = {}
        self.sched_maps: dict[str, dict[str, str]] = {}
        self.if_filters: list[tuple[str, str, str]] = []  # (interface, in|out, filter)
        self.ospf_export: list[str] = []
        self.bgp_policy: list[tuple[str, str, str, str]] = []  # (group, neighbor|'', import|export, name)
        self.built_terms: set[tuple[str, str]] = set()  # QoS class terms already turned into class ACLs


def _term(store: dict, name: str, term: str) -> dict:
    return store.setdefault(name, {}).setdefault(term, {"from": [], "then": []})


def statement(st: State, t: list[str]) -> bool:
    """Collect one statement (tokens after 'set'). True when it belongs to this module."""
    if t[0] == "policy-options" and len(t) > 3:
        kind, name, rest = t[1], t[2], t[3:]
        if kind == "prefix-list":
            st.prefix_lists.setdefault(name, []).append(rest[0])
            return True
        if kind == "community" and rest[0] == "members":
            st.communities.setdefault(name, []).extend(x for x in rest[1:] if x not in ("[", "]"))
            return True
        if kind == "policy-statement":
            if rest[0] == "term" and len(rest) > 2:
                _term(st.policies, name, rest[1])[rest[2]].append(rest[3:])
                return rest[2] in ("from", "then")
            if rest[0] in ("from", "then"):
                _term(st.policies, name, "__final__")[rest[0]].append(rest[1:])
                return True
        return False
    if t[0] == "firewall":
        rest = t[1:]
        if rest[:2] == ["family", "inet"]:
            rest = rest[2:]
        if rest and rest[0] == "filter" and len(rest) > 4 and rest[2] == "term":
            _term(st.filters, rest[1], rest[3])[rest[4]].append(rest[5:])
            return rest[4] in ("from", "then")
        if rest and rest[0] == "policer" and len(rest) > 2:
            if "bandwidth-limit" in rest:
                st.policers[rest[1]] = rate_kbps(rest[rest.index("bandwidth-limit") + 1])
            return True
        return False
    if t[0] == "class-of-service" and len(t) > 2:
        kind = t[1]
        if kind == "forwarding-classes":
            return True
        if kind == "schedulers":
            s = st.schedulers.setdefault(t[2], {})
            key = t[3]
            if key == "transmit-rate":
                if t[4] == "percent":
                    s["pct"] = int(t[5])
                else:
                    s["kbps"] = rate_kbps(t[4])
            elif key == "shaping-rate":
                s["shape"] = rate_kbps(t[4])
            elif key == "priority":
                s["priority"] = t[4] in ("strict-high", "high")
            else:
                return False
            return True
        if kind == "scheduler-maps" and len(t) > 6 and t[3] == "forwarding-class":
            st.sched_maps.setdefault(t[2], {})[t[4]] = t[6]
            return True
        if kind == "interfaces" and len(t) > 4 and t[3] == "scheduler-map":
            st.if_sched_map[t[2]] = t[4]
            return True
    return False


def interface_filter(st: State, ifname: str, r: list[str]) -> bool:
    """r = tokens after 'family inet' of an interface unit."""
    if len(r) >= 3 and r[0] == "filter" and r[1] in ("input", "output", "input-list", "output-list"):
        st.if_filters.append((ifname, "in" if r[1].startswith("input") else "out", r[2]))
        return True
    return False


# ------------------------------------------------------------------- finish
def _seq(term: str, idx: int) -> int:
    m = re.match(r"^T(\d+)$", term)
    return int(m.group(1)) if m else (idx + 1) * 10


def _rf_range(prefix: str, kind: list[str]) -> tuple[int, int, list[str]]:
    plen = ipaddress.ip_network(prefix, strict=False).prefixlen
    k = kind[0] if kind else "exact"
    if k == "exact":
        return plen, plen, kind[1:]
    if k == "orlonger":
        return plen, 32, kind[1:]
    if k == "longer":
        return plen + 1, 32, kind[1:]
    if k == "upto":
        return plen, int(kind[1].lstrip("/")), kind[2:]
    if k == "prefix-length-range":
        a, b = kind[1].split("-")
        return int(a.lstrip("/")), int(b.lstrip("/")), kind[2:]
    raise ValueError(f"route-filter {k} tidak didukung")


def _community_list(pol: Policies, names: list[str], comms: dict, fallback: str) -> str:
    bases = {re.sub(r"-\d+$", "", n) for n in names}
    name = bases.pop() if len(bases) == 1 else fallback
    cl = pol.community_list(name)
    for n in names:
        members = comms.get(n)
        if members:
            value = " ".join(members)
            if ("permit", value) not in cl.entries:
                cl.entries.append(("permit", value))
    return name


def _policy_to_route_map(dev: Device, st: State, name: str, skip_protocol: bool = True) -> RouteMap:
    pol = dev.policy
    rm = pol.route_map(name)
    terms = st.policies.get(name, {})
    for idx, (tname, body) in enumerate(terms.items()):
        froms, thens = body["from"], body["then"]
        if tname == "IMPLICIT-DENY" and not froms:
            continue
        if skip_protocol and any(f[0] == "protocol" for f in froms):
            continue
        seq = 65535 if tname == "__final__" else _seq(tname, idx)
        e = rm.entry(seq, "permit")
        pl = None
        comm_names: list[str] = []
        for f in froms:
            try:
                if f[0] == "route-filter":
                    lo, hi, act = _rf_range(f[1], f[2:])
                    if pl is None:
                        pl = pol.prefix_list(f"{name}-{tname}")
                        e.match_prefix.append(pl.name)
                    action = "deny" if act[:1] in (["reject"], ["next"]) else "permit"
                    pl.add(action, f[1], lo, hi)
                elif f[0] in ("prefix-list", "prefix-list-filter"):
                    kind = f[2:] if f[0] == "prefix-list-filter" else ["exact"]
                    lname = f[1] if kind == ["exact"] else f"{f[1]}-{kind[0]}"
                    if lname not in pol.prefix_lists:
                        target = pol.prefix_list(lname)
                        for p in st.prefix_lists.get(f[1], []):
                            lo, hi, _ = _rf_range(p, kind)
                            target.add("permit", p, lo, hi)
                    e.match_prefix.append(lname)
                elif f[0] == "community":
                    comm_names += [x for x in f[1:] if x not in ("[", "]")]
                elif f[0] == "tag":
                    e.match_tag = int(f[1])
                elif f[0] == "protocol":
                    pass
                else:
                    dev.unparsed.append(f"policy-statement {name} term {tname} from {' '.join(f)}")
            except (ValueError, IndexError) as exc:
                dev.unparsed.append(f"policy-statement {name} term {tname} from {' '.join(f)}  ({exc})")
        if comm_names:
            e.match_community.append(_community_list(pol, comm_names, st.communities, f"{name}-{tname}-CL"))
        terminal = False
        for th in thens:
            k = th[0]
            if k == "accept":
                e.action, terminal = "permit", True
            elif k == "reject":
                e.action, terminal = "deny", True
            elif k == "local-preference":
                e.set_local_pref = int(th[1])
            elif k == "metric":
                e.set_med = int(th[-1])
            elif k == "community" and th[1] in ("add", "set"):
                e.set_community = list(st.communities.get(th[2], []))
                e.community_additive = th[1] == "add"
            elif k == "next-hop" and len(th) > 1 and re.match(r"\d", th[1]):
                e.set_next_hop = th[1]
            elif k == "as-path-prepend":
                e.set_prepend = " ".join(th[1:]).strip('"').split()
            elif k == "tag":
                e.set_tag = int(th[1])
            elif k == "next" and th[1:] == ["term"]:
                pass
            else:
                dev.unparsed.append(f"policy-statement {name} term {tname} then {' '.join(th)}")
        if not terminal:
            dev.unparsed.append(f"policy-statement {name} term {tname}: tanpa accept/reject, "
                                f"dianggap permit (Junos lanjut ke term berikutnya)")
    return rm


def _filter_entries(dev: Device, fname: str, tname: str, froms: list[list[str]], seq: int,
                    action: str, log: bool) -> list[AclEntry]:
    srcs, dsts, sports, dports = [], [], [], []
    e = AclEntry(seq=seq, action=action, log=log)
    for f in froms:
        k = f[0]
        if k == "source-address":
            srcs.append(cidr_norm(f[1]))
        elif k == "destination-address":
            dsts.append(cidr_norm(f[1]))
        elif k == "address":
            raise ValueError("'from address' (dua arah) tidak didukung")
        elif k == "protocol":
            e.protocol = proto(f[1])
        elif k in ("source-port", "destination-port"):
            ports = [x for x in f[1:] if x not in ("[", "]")]
            (sports if k == "source-port" else dports).extend(ports)
        elif k == "tcp-established":
            e.established = True
        elif k == "dscp":
            pass
        else:
            raise ValueError(f"from {' '.join(f)} tidak didukung")
    for ports, attr in ((sports, "src"), (dports, "dst")):
        if not ports:
            continue
        if len(ports) == 1:
            op, vals = parse_port_text(ports[0])
        elif all("-" not in p for p in ports):
            op, vals = "eq", [parse_port_text(p)[1][0] for p in ports]
        else:
            raise ValueError("gabungan range port tidak didukung")
        setattr(e, f"{attr}_op", op)
        setattr(e, f"{attr}_ports", vals)
    out = []
    n = 0
    for s in srcs or ["any"]:
        for d in dsts or ["any"]:
            out.append(AclEntry(**{**e.__dict__, "src": s, "dst": d, "seq": seq + n}))
            n += 1
    return out


def _is_qos(terms: dict) -> bool:
    for body in terms.values():
        for th in body["then"]:
            if th[0] in ("policer", "dscp", "forwarding-class", "loss-priority"):
                return True
        if any(f[0] == "dscp" for f in body["from"]):
            return True
    return False


def finish(dev: Device, st: State, groups: dict) -> None:
    pol = dev.policy

    # ---- BGP / OSPF policy references (group level first, neighbor level overrides)
    exports_bgp: set[str] = set()
    for group, nbr, direction, name in sorted(st.bgp_policy, key=lambda x: x[1] != ""):
        has_protocol = any(any(f[0] == "protocol" for f in b["from"])
                           for b in st.policies.get(name, {}).values())
        if direction == "export" and (name in GENERATED_EXPORT or has_protocol):
            exports_bgp.add(name)
        if name in GENERATED_EXPORT or (direction == "export" and not _has_non_protocol_terms(st, name)):
            continue
        ips = [nbr] if nbr else list(groups.get(group, {}).get("neighbors", {}))
        attr = "route_map_in" if direction == "import" else "route_map_out"
        for ip in ips:
            n = dev.get_bgp().neighbor(ip)
            if nbr or not getattr(n, attr):
                setattr(n, attr, name)
    for name in exports_bgp:
        _export_policy(dev, st, name, "bgp")
    for name in st.ospf_export:
        _export_policy(dev, st, name, "ospf")
    for name in st.policies:
        if name in GENERATED_EXPORT:
            continue
        if name in (exports_bgp | set(st.ospf_export)) and not _has_non_protocol_terms(st, name):
            continue
        _policy_to_route_map(dev, st, name)

    # ---- firewall filters
    qos_filters = set()
    for fname, terms in st.filters.items():
        if _is_qos(terms):
            qos_filters.add(fname)
            _qos_filter(dev, st, fname, terms)
            continue
        acl = pol.acl(fname)
        for idx, (tname, body) in enumerate(terms.items()):
            thens = [th[0] for th in body["then"]]
            action = "permit" if "accept" in thens else "deny" if ("discard" in thens or "reject" in thens) else ""
            if not action:
                dev.unparsed.append(f"firewall filter {fname} term {tname}: tanpa accept/discard")
                continue
            try:
                acl.entries += _filter_entries(dev, fname, tname, body["from"], _seq(tname, idx), action,
                                               "syslog" in thens or "log" in thens)
            except (ValueError, IndexError) as exc:
                dev.unparsed.append(f"firewall filter {fname} term {tname}: {exc}")
    for ifname, direction, fname in st.if_filters:
        if fname in qos_filters:
            pol.bind_qos(_qos_name(fname), ifname, direction)
        elif fname in pol.acls:
            pol.bind_acl(fname, ifname, direction)


def _has_non_protocol_terms(st: State, name: str) -> bool:
    return any(not any(f[0] == "protocol" for f in b["from"]) and n != "IMPLICIT-DENY"
               for n, b in st.policies.get(name, {}).items())


def _export_policy(dev: Device, st: State, name: str, proc_name: str) -> None:
    """BGP-EXPORT / OSPF-EXPORT (and native export policies): networks + redistribute."""
    proc = dev.get_bgp() if proc_name == "bgp" else dev.get_ospf()
    for tname, body in st.policies.get(name, {}).items():
        protos = [f[1] for f in body["from"] if f[0] == "protocol"]
        filters = [f for f in body["from"] if f[0] == "route-filter"]
        maps = [f[1] for f in body["from"] if f[0] == "policy"]
        if protos:
            for p in protos:
                p = "connected" if p == "direct" else p
                if p not in proc.redistribute:
                    proc.redistribute.append(p)
                if maps:
                    proc.redistribute_map[p] = maps[0]
        elif filters and proc_name == "bgp" and name in GENERATED_EXPORT:
            for f in filters:
                if f[1] not in proc.networks:
                    proc.networks.append(f[1])


def _qos_name(fname: str) -> str:
    return fname[4:] if fname.startswith("QOS-") else fname


def _qos_filter(dev: Device, st: State, fname: str, terms: dict) -> None:
    pol = dev.policy
    qp = pol.qos_policy(_qos_name(fname))
    fc_actions: dict[str, dict] = {}
    for sm in st.sched_maps.values():
        for fc, sched in sm.items():
            fc_actions[fc] = st.schedulers.get(sched, {})
    for idx, (tname, body) in enumerate(terms.items()):
        cname = re.sub(r"-\d+$", "", tname)
        default = not body["from"] or cname in ("class-default", "DEFAULT")
        if default:
            cname = "class-default"
        act = qp.action(cname)
        dscp = [dscp_value(_binary(x)) for f in body["from"] if f[0] == "dscp" for x in f[1:]
                if x not in ("[", "]")]
        others = [f for f in body["from"] if f[0] != "dscp"]
        if not default and (cname, tname) not in st.built_terms:
            st.built_terms.add((cname, tname))
            cls = pol.qos_class(cname)
            cls.match_any = True
            for d in dscp:
                if d not in cls.match_dscp:
                    cls.match_dscp.append(d)
            if others:
                acl = pol.acl(f"CLS-{cname}")
                try:
                    acl.entries += _filter_entries(dev, fname, tname, others, (len(acl.entries) + 1) * 10,
                                                   "permit", False)
                except (ValueError, IndexError) as exc:
                    dev.unparsed.append(f"firewall filter {fname} term {tname}: {exc}")
                cls.match_acl = acl.name
        for th in body["then"]:
            k = th[0]
            if k == "policer" and th[1] in st.policers:
                act.police_kbps = st.policers[th[1]]
            elif k == "dscp":
                act.set_dscp = dscp_value(_binary(th[1]))
            elif k == "forwarding-class":
                s = fc_actions.get(th[1], {})
                act.priority = bool(s.get("priority")) or th[1] in ("expedited-forwarding", "ef")
                if s.get("priority"):
                    act.priority_kbps = s.get("kbps")
                else:
                    act.bandwidth_kbps = s.get("kbps")
                if s.get("pct"):
                    act.bandwidth_pct = s["pct"]
                act.shape_kbps = s.get("shape")
            elif k in ("accept", "count"):
                pass
            else:
                dev.unparsed.append(f"firewall filter {fname} term {tname} then {' '.join(th)}")


def _binary(token: str) -> str:
    return str(int(token, 2)) if re.fullmatch(r"[01]{6}", token) else token
