"""Nokia SR OS classic CLI parser (admin display-config)."""
from __future__ import annotations

import shlex

from ..model import Device, StaticRoute, is_ipv4
from . import nokia_policy


class Node:
    __slots__ = ("t", "children")

    def __init__(self, tokens: list[str]):
        self.t = tokens
        self.children: list[Node] = []

    def find(self, *head: str) -> list["Node"]:
        n = len(head)
        return [c for c in self.children if c.t[:n] == list(head)]

    def first(self, *head: str) -> "Node | None":
        hits = self.find(*head)
        return hits[0] if hits else None

    def value(self, key: str, default: str = "") -> str:
        node = self.first(key)
        return " ".join(node.t[1:]) if node and len(node.t) > 1 else default

    def has(self, *head: str) -> bool:
        return bool(self.find(*head))


def tree(text: str) -> Node:
    root = Node(["root"])
    stack: list[tuple[int, Node]] = [(-1, root)]
    for raw in text.replace("\r", "").split("\n"):
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "echo ")) or stripped.startswith("exit"):
            continue
        indent = len(line) - len(line.lstrip())
        try:
            tokens = shlex.split(stripped)
        except ValueError:
            tokens = stripped.split()
        if not tokens:
            continue
        while stack and stack[-1][0] >= indent:
            stack.pop()
        node = Node(tokens)
        stack[-1][1].children.append(node)
        stack.append((indent, node))
    return root


def _port_name(port: str) -> tuple[str, int | None]:
    """'1/1/1:100' -> ('1/1/1.100', 100)."""
    if ":" in port:
        base, tag = port.split(":", 1)
        tag = tag.split(".")[0]
        if tag.isdigit() and tag != "0":
            return f"{base}.{tag}", int(tag)
        return base, None
    return port, None


def parse(text: str) -> Device:
    dev = Device(vendor="nokia_sros")
    root = tree(text)
    cfg = root.first("configure") or root
    alias: dict[str, str] = {}
    port_info: dict[str, Node] = {}

    def nm(name: str) -> str:
        return alias.get(name, name)

    sysn = cfg.first("system")
    if sysn:
        dev.hostname = sysn.value("name")
        dev.snmp_location = sysn.value("location")
        dev.snmp_contact = sysn.value("contact")
        time = sysn.first("time")
        ntp = time.first("ntp") if time else None
        if ntp:
            dev.ntp = [n.t[1] for n in ntp.find("server") if len(n.t) > 1]
        dns = sysn.first("dns")
        if dns:
            dev.dns = [dns.value(k) for k in ("primary-dns", "secondary-dns", "tertiary-dns")
                       if is_ipv4(dns.value(k))]
        sec = sysn.first("security")
        if sec:
            snmp = sec.first("snmp")
            for c in (snmp.find("community") if snmp else []):
                if len(c.t) > 2:
                    dev.snmp_communities.append((c.t[1], "rw" if "w" in c.t[2] else "ro"))
            dev.users = [u.t[1] for u in sec.find("user") if len(u.t) > 1]

    log = cfg.first("log")
    for s in (log.find("syslog") if log else []):
        addr = s.value("address").split()
        if addr and is_ipv4(addr[0]):
            dev.syslog.append(addr[0])

    filter_ids = nokia_policy.parse_filters(dev, cfg)
    for po in cfg.find("policy-options"):
        nokia_policy.parse_policy_options(dev, po)

    for p in cfg.find("port") + cfg.find("lag"):
        if len(p.t) > 1:
            port_info[p.t[1] if p.t[0] == "port" else f"lag-{p.t[1]}"] = p

    routers = [r for r in cfg.find("router") if len(r.t) == 1 or r.t[1] in ("Base", "management")]
    routers = [r for r in routers if len(r.t) == 1 or r.t[1] == "Base"]
    asn = router_id = ""

    # pass 1: interfaces (several 'router' blocks can exist in one file)
    for rt in routers:
        for i in rt.find("interface"):
            name = i.t[1]
            port = i.value("port")
            if port:
                neutral, vid = _port_name(port)
            else:
                neutral, vid = name, None
            alias[name] = neutral
            itf = dev.iface(neutral)
            if vid:
                itf.dot1q = vid
            if not port:
                itf.kind_hint = "loopback"
            elif port.startswith("lag-") and not vid:
                itf.kind_hint = "lag"
            itf.description = i.value("description") or ("" if name == neutral else name)
            for a in i.find("address") + i.find("secondary"):
                if len(a.t) > 1 and "/" in a.t[1] and a.t[1] not in itf.ipv4:
                    itf.ipv4.append(a.t[1])
            base = port.split(":")[0]
            pnode = port_info.get(base)
            itf.shutdown = i.has("shutdown") or bool(pnode and pnode.has("shutdown"))
            nokia_policy.bind_interface(dev, i, neutral, filter_ids)
            eth = pnode.first("ethernet") if pnode else None
            if eth and eth.value("mtu").isdigit():
                itf.mtu = int(eth.value("mtu"))
        asn = rt.value("autonomous-system") or asn
        router_id = rt.value("router-id") or router_id

    # physical ports without a router interface
    for pname, pnode in port_info.items():
        if pname not in dev.interfaces and pnode.value("description"):
            itf = dev.iface(pname)
            itf.description = pnode.value("description")
            itf.shutdown = pnode.has("shutdown")

    # pass 2: routing
    for rt in routers:
        for po in rt.find("policy-options"):
            nokia_policy.parse_policy_options(dev, po)
        for sr in rt.find("static-route-entry"):
            hops = sr.find("next-hop") + sr.find("indirect")
            if sr.has("black-hole"):
                dev.static_routes.append(StaticRoute(prefix=sr.t[1], interface="Null0"))
            for h in hops:
                r = StaticRoute(prefix=sr.t[1], description=h.value("description"))
                if is_ipv4(h.t[1]):
                    r.nexthop = h.t[1]
                else:
                    r.interface = nm(h.t[1])
                if h.value("preference").isdigit() and h.value("preference") != "5":
                    r.distance = int(h.value("preference"))
                dev.static_routes.append(r)
        for sr in rt.find("static-route"):  # legacy one-line syntax
            t = sr.t
            r = StaticRoute(prefix=t[1])
            if "next-hop" in t:
                r.nexthop = t[t.index("next-hop") + 1]
            elif "black-hole" in t:
                r.interface = "Null0"
            if "preference" in t:
                r.distance = int(t[t.index("preference") + 1])
            dev.static_routes.append(r)

        for o in rt.find("ospf"):
            ospf = dev.get_ospf()
            ospf.router_id = (o.t[2] if len(o.t) > 2 and is_ipv4(o.t[2]) else "") or router_id
            for area in o.find("area"):
                for i in area.find("interface"):
                    itf = dev.iface(nm(i.t[1]))
                    itf.ospf_area = area.t[1]
                    if i.has("passive") and itf.name not in ospf.passive:
                        ospf.passive.append(itf.name)
                    if i.value("metric").isdigit():
                        itf.ospf_cost = int(i.value("metric"))
            for node in o.children:
                if node.t[0] not in ("area", "shutdown", "no", "asbr", "traffic-engineering",
                                     "reference-bandwidth", "router-id", "timers"):
                    dev.unparsed.append("router ospf: " + " ".join(node.t))

        b = rt.first("bgp")
        if b:
            bgp = dev.get_bgp()
            bgp.asn, bgp.router_id = asn, b.value("router-id") or router_id
            owner = {a.split("/")[0]: i.name for i in dev.interfaces.values() for a in i.ipv4}
            for g in b.find("group"):
                internal = g.value("type") == "internal"
                for n in g.find("neighbor"):
                    nb = bgp.neighbor(n.t[1])
                    nb.remote_as = n.value("peer-as") or g.value("peer-as") or (asn if internal else "")
                    nb.description = n.value("description") or g.value("description")
                    local = n.value("local-address") or g.value("local-address")
                    nb.update_source = owner.get(local, "")
                    hop = n.value("multihop") or g.value("multihop")
                    if hop.isdigit():
                        nb.ebgp_multihop = int(hop)
                    nb.shutdown = n.has("shutdown")
                    nb.next_hop_self = n.has("next-hop-self") or g.has("next-hop-self")
                    nb.route_map_in = n.value("import") or g.value("import")
                    nb.route_map_out = n.value("export") or g.value("export")
        for node in rt.children:
            if node.t[0] in ("isis", "mpls", "rsvp", "ldp", "pim", "rip"):
                dev.unparsed.append(f"router {node.t[0]}  ({len(node.children)} baris)")

    if dev.ospf and not dev.ospf.router_id:
        dev.ospf.router_id = router_id
    svc = cfg.first("service")
    for node in (svc.children if svc else []):
        if node.t[0] in ("vprn", "ies", "vpls", "epipe"):
            dev.unparsed.append("service " + " ".join(node.t[:2]))
    for node in cfg.children:
        if node.t[0] in ("qos", "card", "eth-cfm", "cflowd", "mirror"):
            if node.t[0] != "card":
                dev.unparsed.append(f"{node.t[0]}  ({len(node.children)} baris)")
    return dev
