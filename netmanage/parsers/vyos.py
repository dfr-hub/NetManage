"""VyOS parser. Accepts 'show configuration commands' (set) and brace format."""
from __future__ import annotations

import re
import shlex

from ..model import Device, OspfNetwork, StaticRoute, is_ipv4
from . import vyos_policy

_IGNORE = re.compile(
    r"^(system (config-management|console|conntrack|login (banner|user \S+ (authentication|full-name|"
    r"level))|syslog (global|local)|time-zone|option|host-name$)|service (ssh|https|lldp|dhcp-server|"
    r"dns)|interfaces \S+ \S+ (hw-id|duplex|speed|smp-affinity|offload|address dhcp|"
    r"member|enable-vlan|stp|mode|hash-policy)|nat |high-availability)"
)


def brace_to_set(text: str) -> list[str]:
    out: list[str] = []
    stack: list[str] = []
    for raw in text.replace("\r", "").split("\n"):
        line = raw.strip()
        if not line or line.startswith(("#", "/*", "//")):
            continue
        if line.endswith("{"):
            stack.append(line[:-1].strip())
        elif line == "}":
            if stack:
                stack.pop()
        else:
            out.append("set " + " ".join(stack + [line]))
    return out


def _set_lines(text: str) -> list[str]:
    lines = [ln.strip() for ln in text.replace("\r", "").split("\n")]
    sets = [ln for ln in lines if ln.startswith("set ")]
    return sets if len(sets) >= 3 else brace_to_set(text)


_HINT = {"loopback": "loopback", "dummy": "loopback", "bonding": "lag", "bridge": "bridge",
         "tunnel": "tunnel"}


def parse(text: str) -> Device:
    dev = Device(vendor="vyos")
    st = vyos_policy.State()
    for line in _set_lines(text):
        try:
            t = shlex.split(line)[1:]
        except ValueError:
            t = line.split()[1:]
        if not t:
            continue
        try:
            ok = vyos_policy.statement(st, t) or _statement(dev, t, st)
        except (ValueError, IndexError):
            ok = False
        if not ok and not _IGNORE.match(" ".join(t)):
            dev.unparsed.append(line)
    vyos_policy.finish(dev, st)
    return dev


def _statement(dev: Device, t: list[str], st=None) -> bool:
    if t[0] == "system":
        return _system(dev, t[1:])
    if t[:2] == ["service", "ntp"] and t[2] == "server":
        if t[3] not in dev.ntp:
            dev.ntp.append(t[3])
        return True
    if t[:2] == ["service", "snmp"]:
        if t[2] == "community":
            auth = "rw" if t[-1] == "rw" else "ro"
            dev.snmp_communities = [c for c in dev.snmp_communities if c[0] != t[3]] + [(t[3], auth)]
        elif t[2] == "location":
            dev.snmp_location = " ".join(t[3:])
        elif t[2] == "contact":
            dev.snmp_contact = " ".join(t[3:])
        else:
            return False
        return True
    if t[0] == "interfaces":
        if st is not None and len(t) > 3:
            name = f"{t[2]}.{t[4]}" if t[3:4] == ["vif"] and len(t) > 4 else t[2]
            rest = t[5:] if t[3:4] == ["vif"] else t[3:]
            if vyos_policy.interface_firewall(st, name, rest):
                return True
        return _interface(dev, t[1:])
    if t[:2] == ["protocols", "static"]:
        return _static(dev, t[2:])
    if t[:2] == ["protocols", "ospf"]:
        return _ospf(dev, t[2:])
    if t[:2] == ["protocols", "bgp"]:
        rest = t[2:]
        if rest and rest[0].isdigit():  # VyOS 1.3: 'protocols bgp 65001 ...'
            dev.get_bgp().asn = rest[0]
            rest = rest[1:]
        return _bgp(dev, rest) if rest else True
    return False


def _system(dev: Device, t: list[str]) -> bool:
    if t[0] == "host-name":
        dev.hostname = t[1]
    elif t[0] == "domain-name":
        dev.domain = t[1]
    elif t[0] == "name-server":
        if is_ipv4(t[1]):
            dev.dns.append(t[1])
    elif t[:2] == ["ntp", "server"]:
        if t[2] not in dev.ntp:
            dev.ntp.append(t[2])
    elif t[0] == "syslog" and t[1] in ("host", "remote"):
        if t[2] not in dev.syslog:
            dev.syslog.append(t[2])
    elif t[:2] == ["login", "user"]:
        if t[2] not in dev.users:
            dev.users.append(t[2])
        return len(t) == 3
    else:
        return False
    return True


def _interface(dev: Device, t: list[str]) -> bool:
    kind, base, rest = t[0], t[1], t[2:]
    hint = _HINT.get(kind, "")
    if rest[:1] == ["vif"]:
        name = f"{base}.{rest[1]}"
        itf = dev.iface(name)
        if kind == "bridge":
            itf.kind_hint = "vlan"
            dev.vlans.setdefault(int(rest[1]), "")
        else:
            itf.dot1q = int(rest[1])
        rest = rest[2:]
    else:
        itf = dev.iface(base)
        itf.kind_hint = hint
    if not rest:
        return True
    key = rest[0]
    if key == "address":
        if "/" not in rest[1]:
            return False
        if ":" not in rest[1] and rest[1] not in itf.ipv4:
            itf.ipv4.append(rest[1])
    elif key == "description":
        itf.description = " ".join(rest[1:])
    elif key == "disable":
        itf.shutdown = True
    elif key == "mtu":
        itf.mtu = int(rest[1])
    elif key == "vrf":
        itf.vrf = rest[1]
    elif rest[:3] == ["ip", "ospf", "cost"]:
        itf.ospf_cost = int(rest[3])
    elif rest[:2] == ["member", "interface"] and kind == "bridge" and len(rest) > 3:
        port = dev.iface(rest[2])
        if rest[3] == "native-vlan":
            port.access_vlan = int(rest[4])
            port.mode = port.mode or "access"
            dev.vlans.setdefault(int(rest[4]), "")
        elif rest[3] == "allowed-vlan":
            port.mode = "trunk"
            port.trunk_vlans = f"{port.trunk_vlans},{rest[4]}" if port.trunk_vlans else rest[4]
        else:
            return False
    else:
        return False
    return True


def _static(dev: Device, t: list[str]) -> bool:
    vrf = ""
    if t[0] != "route" or len(t) < 2:
        return False
    prefix, opts = t[1], t[2:]
    if not opts:
        return True
    if opts[0] == "next-hop":
        r = next((x for x in dev.static_routes if x.prefix == prefix and x.nexthop == opts[1]), None)
        if r is None:
            r = StaticRoute(prefix=prefix, nexthop=opts[1], vrf=vrf)
            dev.static_routes.append(r)
        if "distance" in opts:
            r.distance = int(opts[opts.index("distance") + 1])
        if "interface" in opts:
            r.interface = opts[opts.index("interface") + 1]
    elif opts[0] == "interface":
        r = next((x for x in dev.static_routes if x.prefix == prefix and x.interface == opts[1]), None)
        if r is None:
            r = StaticRoute(prefix=prefix, interface=opts[1])
            dev.static_routes.append(r)
        if "distance" in opts:
            r.distance = int(opts[opts.index("distance") + 1])
    elif opts[0] == "blackhole":
        if not any(x.prefix == prefix and x.interface == "Null0" for x in dev.static_routes):
            dev.static_routes.append(StaticRoute(prefix=prefix, interface="Null0"))
    elif opts[0] == "description":
        for r in dev.static_routes:
            if r.prefix == prefix:
                r.description = " ".join(opts[1:])
    else:
        return False
    return True


def _ospf(dev: Device, t: list[str]) -> bool:
    ospf = dev.get_ospf()
    if t[:2] == ["parameters", "router-id"]:
        ospf.router_id = t[2]
    elif t[0] == "area" and len(t) > 3 and t[2] == "network":
        ospf.networks.append(OspfNetwork(t[3], t[1]))
    elif t[0] == "area" and len(t) == 2:
        pass
    elif t[0] == "interface" and len(t) > 2:
        itf = dev.iface(t[1])
        if t[2] == "area":
            itf.ospf_area = t[3]
        elif t[2] == "passive":
            if "disable" not in t and itf.name not in ospf.passive:
                ospf.passive.append(itf.name)
        elif t[2] == "cost":
            itf.ospf_cost = int(t[3])
        else:
            return False
    elif t[0] == "passive-interface":
        if t[1] != "default" and t[1] not in ospf.passive:
            ospf.passive.append(t[1])
        return t[1] != "default"
    elif t[0] == "redistribute":
        if t[1] not in ospf.redistribute:
            ospf.redistribute.append(t[1])
        if "route-map" in t:
            ospf.redistribute_map[t[1]] = t[t.index("route-map") + 1]
    elif t[:2] == ["default-information", "originate"]:
        ospf.default_originate = True
    elif t[0] in ("log-adjacency-changes", "auto-cost"):
        pass
    else:
        return False
    return True


def _bgp(dev: Device, t: list[str]) -> bool:
    bgp = dev.get_bgp()
    if t[0] in ("system-as", "local-as"):
        bgp.asn = t[1]
    elif t[:2] == ["parameters", "router-id"]:
        bgp.router_id = t[2]
    elif t[0] == "neighbor" and len(t) > 2 and is_ipv4(t[1]):
        n = bgp.neighbor(t[1])
        key = t[2]
        if key == "remote-as":
            n.remote_as = bgp.asn if t[3] == "internal" else t[3]
        elif key == "description":
            n.description = " ".join(t[3:])
        elif key == "update-source":
            src = t[3]
            n.update_source = next((i.name for i in dev.interfaces.values()
                                    if any(a.split("/")[0] == src for a in i.ipv4)), "") \
                if is_ipv4(src) else src
        elif key == "ebgp-multihop":
            n.ebgp_multihop = int(t[3])
        elif key == "shutdown":
            n.shutdown = True
        elif key == "address-family":
            if "nexthop-self" in t:
                n.next_hop_self = True
            if "route-map" in t and len(t) > t.index("route-map") + 2:
                k = t.index("route-map")
                setattr(n, "route_map_in" if t[k + 1] == "import" else "route_map_out", t[k + 2])
                return True
            return "nexthop-self" in t or len(t) == 4
        elif key == "nexthop-self":
            n.next_hop_self = True
        else:
            return False
    elif t[0] == "address-family" and len(t) > 3 and t[2] == "network":
        if t[3] not in bgp.networks:
            bgp.networks.append(t[3])
    elif t[0] == "address-family" and len(t) > 3 and t[2] == "redistribute":
        if t[3] not in bgp.redistribute:
            bgp.redistribute.append(t[3])
        if "route-map" in t:
            bgp.redistribute_map[t[3]] = t[t.index("route-map") + 1]
    elif t[0] == "network":
        bgp.networks.append(t[1])
    elif t[0] == "redistribute":
        bgp.redistribute.append(t[1])
    elif t[0] == "address-family" and len(t) <= 2:
        pass
    else:
        return False
    return True
