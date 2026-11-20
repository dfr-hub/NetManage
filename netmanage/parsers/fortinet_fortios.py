"""Fortinet FortiOS parser (show full-configuration / backup file)."""
from __future__ import annotations

import shlex

from ..model import Device, OspfNetwork, StaticRoute, is_ipv4, net_of, to_cidr
from . import fgt_policy

_HANDLED = {
    "system global", "system interface", "router static", "router ospf", "router bgp",
    "system dns", "system ntp", "log syslogd setting", "system snmp community",
    "system snmp sysinfo", "system admin", "vdom", "global",
}


def tree(text: str) -> dict:
    """config/edit/set/next/end -> nested dict. 'set' values are lists, children are dicts."""
    root: dict = {}
    stack = [root]
    for raw in text.replace("\r", "").split("\n"):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            t = shlex.split(line)
        except ValueError:
            t = line.split()
        if not t:
            continue
        cmd = t[0]
        if cmd == "config" and len(t) > 1:
            node = stack[-1].get(" ".join(t[1:]))
            if not isinstance(node, dict):
                node = stack[-1][" ".join(t[1:])] = {}
            stack.append(node)
        elif cmd == "edit" and len(t) > 1:
            node = stack[-1].get(t[1])
            if not isinstance(node, dict):
                node = stack[-1][t[1]] = {}
            stack.append(node)
        elif cmd in ("next", "end"):
            if len(stack) > 1:
                stack.pop()
        elif cmd == "set" and len(t) > 1:
            stack[-1][t[1]] = t[2:]
    return root


def _sections(root: dict) -> dict:
    """Merge 'config global' and every VDOM into one flat section map."""
    merged = {k: v for k, v in root.items() if isinstance(v, dict)}
    for container in (root.get("global"), *(root.get("vdom") or {}).values()):
        if isinstance(container, dict):
            for k, v in container.items():
                if isinstance(v, dict):
                    merged.setdefault(k, {}).update(v)
    return merged


def _v(node: dict, key: str, default: str = "") -> str:
    val = node.get(key)
    return val[0] if isinstance(val, list) and val else default


def _entries(node) -> list[tuple[str, dict]]:
    return [(k, v) for k, v in (node or {}).items() if isinstance(v, dict)]


def _on(node: dict, key: str) -> bool:
    return _v(node, key) in ("enable", "always")


def parse(text: str) -> Device:
    dev = Device(vendor="fortinet_fortios")
    sec = _sections(tree(text))
    alias: dict[str, str] = {}

    def nm(name: str) -> str:
        return alias.get(name, name)

    dev.hostname = _v(sec.get("system global", {}), "hostname")

    for name, d in _entries(sec.get("system interface")):
        kind = _v(d, "type")
        parent, vid = _v(d, "interface"), _v(d, "vlanid")
        if parent and vid:
            alias[name] = f"{parent}.{vid}"
    for name, d in _entries(sec.get("system interface")):
        kind = _v(d, "type")
        itf = dev.iface(nm(name))
        if name in alias:
            itf.dot1q = int(_v(d, "vlanid"))
        itf.description = _v(d, "description") or _v(d, "alias") or ("" if name not in alias else name)
        if kind == "loopback":
            itf.kind_hint = "loopback"
        elif kind in ("aggregate", "redundant"):
            itf.kind_hint = "lag"
        elif kind == "tunnel":
            itf.kind_hint = "tunnel"
        ip = d.get("ip")
        if isinstance(ip, list) and len(ip) >= 2 and ip[0] != "0.0.0.0":
            itf.ipv4.append(to_cidr(ip[0], ip[1]))
        for _, sip in _entries(d.get("secondaryip")):
            ip2 = sip.get("ip")
            if isinstance(ip2, list) and len(ip2) >= 2:
                itf.ipv4.append(to_cidr(ip2[0], ip2[1]))
        itf.shutdown = _v(d, "status") == "down"
        if _v(d, "mtu-override") == "enable" and _v(d, "mtu").isdigit():
            itf.mtu = int(_v(d, "mtu"))

    for _, d in _entries(sec.get("router static")):
        dst = d.get("dst") or ["0.0.0.0", "0.0.0.0"]
        prefix = net_of(*dst[0].split("/")) if "/" in dst[0] else net_of(dst[0], dst[1])
        r = StaticRoute(prefix=prefix, nexthop=_v(d, "gateway"), description=_v(d, "comment"))
        if _v(d, "blackhole") == "enable":
            r.interface = "Null0"
        elif not r.nexthop:
            r.interface = nm(_v(d, "device"))
        if _v(d, "distance", "10") != "10":
            r.distance = int(_v(d, "distance"))
        dev.static_routes.append(r)

    o = sec.get("router ospf")
    if o and (_v(o, "router-id") or _entries(o.get("network")) or _entries(o.get("ospf-interface"))):
        ospf = dev.get_ospf()
        ospf.router_id = _v(o, "router-id")
        for _, n in _entries(o.get("network")):
            p = n.get("prefix")
            if isinstance(p, list) and len(p) >= 2:
                ospf.networks.append(OspfNetwork(net_of(p[0], p[1]), _v(n, "area", "0.0.0.0")))
        for _, n in _entries(o.get("ospf-interface")):
            if _v(n, "interface") and _v(n, "cost").isdigit():
                dev.iface(nm(_v(n, "interface"))).ospf_cost = int(_v(n, "cost"))
        ospf.passive = [nm(x) for x in o.get("passive-interface", []) if isinstance(x, str)]
        for key, n in _entries(o):
            if key.startswith("redistribute ") and _on(n, "status"):
                ospf.redistribute.append(key.split()[1])
                if _v(n, "route-map"):
                    ospf.redistribute_map[key.split()[1]] = _v(n, "route-map")
        ospf.default_originate = _on(o, "default-information-originate")

    b = sec.get("router bgp")
    if b and (_v(b, "as") not in ("", "0") or _entries(b.get("neighbor"))):
        bgp = dev.get_bgp()
        bgp.asn, bgp.router_id = _v(b, "as"), _v(b, "router-id")
        for ip, n in _entries(b.get("neighbor")):
            if not is_ipv4(ip):
                continue
            nb = bgp.neighbor(ip)
            nb.remote_as = _v(n, "remote-as")
            nb.description = _v(n, "description")
            nb.update_source = nm(_v(n, "update-source"))
            if _on(n, "ebgp-enforce-multihop"):
                nb.ebgp_multihop = int(_v(n, "ebgp-multihop-ttl", "255"))
            nb.next_hop_self = _on(n, "next-hop-self")
            nb.shutdown = _on(n, "shutdown")
            nb.route_map_in = _v(n, "route-map-in")
            nb.route_map_out = _v(n, "route-map-out")
        for _, n in _entries(b.get("network")):
            p = n.get("prefix")
            if isinstance(p, list) and len(p) >= 2:
                bgp.networks.append(net_of(p[0], p[1]))
        for key, n in _entries(b):
            if key.startswith("redistribute ") and _on(n, "status"):
                bgp.redistribute.append(key.split()[1])
                if _v(n, "route-map"):
                    bgp.redistribute_map[key.split()[1]] = _v(n, "route-map")

    dns = sec.get("system dns", {})
    dev.dns = [x for x in (_v(dns, "primary"), _v(dns, "secondary")) if is_ipv4(x) and x != "0.0.0.0"]
    dev.domain = _v(dns, "domain")
    for _, n in _entries(sec.get("system ntp", {}).get("ntpserver")):
        if _v(n, "server"):
            dev.ntp.append(_v(n, "server"))
    syslog = sec.get("log syslogd setting", {})
    if _v(syslog, "server"):
        dev.syslog.append(_v(syslog, "server"))
    for _, n in _entries(sec.get("system snmp community")):
        if _v(n, "name"):
            dev.snmp_communities.append((_v(n, "name"), "ro"))
    info = sec.get("system snmp sysinfo", {})
    dev.snmp_location, dev.snmp_contact = _v(info, "location"), _v(info, "contact-info")
    dev.users = [name for name, _ in _entries(sec.get("system admin"))]

    fgt_policy.parse(dev, sec, nm)
    for name, node in sec.items():
        if name not in _HANDLED and name not in fgt_policy.HANDLED and node:
            count = len(_entries(node))
            dev.unparsed.append(f"config {name}" + (f"  ({count} entri)" if count else ""))
    return dev
