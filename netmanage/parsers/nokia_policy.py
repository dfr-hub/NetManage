"""Nokia SR OS classic CLI: policy-options (route policy) and ip-filter (ACL)."""
from __future__ import annotations

import ipaddress

from ..model import Device
from ..policy import AclEntry, cidr_norm, port_num, port_ops, proto


def _prefix_range(prefix: str, t: list[str]) -> tuple[int, int]:
    plen = ipaddress.ip_network(prefix, strict=False).prefixlen
    if not t or t[0] == "exact":
        return plen, plen
    if t[0] == "longer":
        return plen, 32
    if t[0] == "through":
        return plen, int(t[1])
    if t[0] == "prefix-length-range":
        a, b = t[1].split("-")
        return int(a), int(b)
    raise ValueError(f"prefix {' '.join(t)} tidak didukung")


def parse_policy_options(dev: Device, po) -> None:
    pol = dev.policy
    plists: dict[str, list[tuple[str, int, int]]] = {}
    for n in po.find("prefix-list"):
        items = plists.setdefault(n.t[1], [])
        for p in n.find("prefix"):
            try:
                lo, hi = _prefix_range(p.t[1], p.t[2:])
                items.append((p.t[1], lo, hi))
            except (ValueError, IndexError):
                dev.unparsed.append(f"policy-options prefix-list {n.t[1]}: {' '.join(p.t)}")
    comms: dict[str, list[str]] = {}
    for n in po.find("community"):
        if len(n.t) > 3 and n.t[2] == "members":
            comms[n.t[1]] = n.t[3:]
    for ps in po.find("policy-statement"):
        name = ps.t[1]
        rm = pol.route_map(name)
        pending_deny: list[tuple[str, int, int]] = []
        for ent in ps.find("entry"):
            eid = int(ent.t[1])
            froms = []
            fnode = ent.first("from")
            if fnode is not None:
                froms = [c.t for c in fnode.children]
                if len(fnode.t) > 1:
                    froms.append(fnode.t[1:])
            anode = ent.first("action")
            action = anode.t[1] if anode is not None and len(anode.t) > 1 else "accept"
            pls = [x for f in froms if f[0] == "prefix-list" for x in f[1:]]
            if action == "next-entry" and pls and all(f[0] == "prefix-list" for f in froms):
                for x in pls:
                    pending_deny += plists.get(x, [])
                continue
            seq = eid // 10 if eid % 10 < 5 and eid >= 10 else eid
            e = rm.entry(seq, "deny" if action in ("reject", "drop") else "permit")
            if pls or pending_deny:
                pl = dev.policy.prefix_list(f"{name}-{seq}")
                if pl.name not in e.match_prefix:
                    e.match_prefix.append(pl.name)
                for p, lo, hi in pending_deny:
                    pl.add("deny", p, lo, hi)
                for x in pls:
                    for p, lo, hi in plists.get(x, []):
                        if not any(en.prefix == str(ipaddress.ip_network(p, strict=False)) and en.action == "permit"
                                   and en.range() == (lo, hi) for en in pl.entries):
                            pl.add("permit", p, lo, hi)
                pending_deny = []
            for f in froms:
                k = f[0]
                if k == "community":
                    cname = f[1]
                    cl = pol.community_list(cname)
                    if comms.get(cname) and ("permit", " ".join(comms[cname])) not in cl.entries:
                        cl.entries.append(("permit", " ".join(comms[cname])))
                    if cname not in e.match_community:
                        e.match_community.append(cname)
                elif k == "tag":
                    e.match_tag = int(f[1])
                elif k in ("prefix-list", "protocol"):
                    pass
                else:
                    dev.unparsed.append(f"policy-statement {name} entry {eid} from {' '.join(f)}")
            for c in (anode.children if anode is not None else []):
                t = c.t
                if t[0] == "local-preference":
                    e.set_local_pref = int(t[1])
                elif t[0] == "metric" and len(t) > 2:
                    e.set_med = int(t[2])
                elif t[0] == "community" and t[1] in ("add", "replace"):
                    e.set_community = list(comms.get(t[2], []))
                    e.community_additive = t[1] == "add"
                elif t[0] == "next-hop":
                    e.set_next_hop = t[1]
                elif t[0] == "as-path-prepend":
                    e.set_prepend = [t[1]] * (int(t[2]) if len(t) > 2 else 1)
                elif t[0] == "tag":
                    e.set_tag = int(t[1])
                else:
                    dev.unparsed.append(f"policy-statement {name} entry {eid} action {' '.join(t)}")
        default = ps.value("default-action")
        if default.startswith("accept"):
            rm.entry(65535, "permit")


def parse_filters(dev: Device, cfg) -> dict[str, str]:
    """Returns ip-filter id -> ACL name."""
    ids: dict[str, str] = {}
    fnode = cfg.first("filter")
    if fnode is None:
        return ids
    for f in fnode.find("ip-filter"):
        fid = f.t[1]
        name = f.t[f.t.index("name") + 1] if "name" in f.t else (f.value("description") or fid)
        ids[fid] = name
        acl = dev.policy.acl(name)
        for ent in f.find("entry"):
            seq = int(ent.t[1])
            desc = ent.value("description")
            if desc:
                acl.entries.append(AclEntry(seq=seq - 1, action="remark", remark=desc))
            e = AclEntry(seq=seq)
            try:
                m = ent.first("match")
                if m is not None:
                    if "protocol" in m.t:
                        e.protocol = proto(m.t[m.t.index("protocol") + 1])
                    for c in m.children:
                        t = c.t
                        if t[0] in ("src-ip", "dst-ip"):
                            setattr(e, "src" if t[0] == "src-ip" else "dst", cidr_norm(t[1]))
                        elif t[0] in ("src-port", "dst-port"):
                            side = "src" if t[0] == "src-port" else "dst"
                            if t[1] == "range":
                                op, ports = port_ops("range", [port_num(t[2]), port_num(t[3])])
                            else:
                                op, ports = port_ops(t[1], [port_num(t[2])])
                            setattr(e, f"{side}_op", op)
                            setattr(e, f"{side}_ports", ports)
                        elif t[:2] == ["tcp-ack", "true"]:
                            e.established = True
                        else:
                            raise ValueError(f"match {' '.join(t)} tidak didukung")
                a = ent.first("action")
                act = (a.t[1] if a is not None and len(a.t) > 1 else
                       (a.children[0].t[0] if a is not None and a.children else "drop"))
                e.action = "permit" if act == "forward" else "deny"
                if ent.first("log") is not None:
                    e.log = True
                acl.entries.append(e)
            except (ValueError, IndexError) as exc:
                dev.unparsed.append(f"ip-filter {fid} entry {seq}: {exc}")
        if f.value("default-action") == "forward":
            acl.entries.append(AclEntry(seq=acl.next_seq(), action="permit"))
    return ids


def bind_interface(dev: Device, inode, ifname: str, ids: dict[str, str]) -> None:
    for key, direction in (("ingress", "in"), ("egress", "out")):
        n = inode.first(key)
        if n is None:
            continue
        for f in n.find("filter"):
            if len(f.t) > 2 and f.t[1] == "ip" and f.t[2] in ids:
                dev.policy.bind_acl(ids[f.t[2]], ifname, direction)
