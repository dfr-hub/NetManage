"""Juniper Junos parser. Accepts 'display set' format and curly-brace format."""
from __future__ import annotations

import ipaddress
import re
import shlex

from ..model import Device, OspfNetwork, StaticRoute, is_ipv4
from . import junos_policy

_IGNORE = re.compile(
    r"^(version |system (root-authentication|services|login (class|message)|time-zone|"
    r"syslog (file|user)|ports|commit|processes|auto-snapshot|management-instance|"
    r"authentication-order|max-configuration|no-redirects|internet-options)|"
    r"chassis |groups |apply-groups|security (ssh|log))"
)


def brace_to_set(text: str) -> list[str]:
    """Convert curly-brace Junos config into 'set' lines."""
    out: list[str] = []
    stack: list[str] = []
    for raw in text.replace("\r", "").split("\n"):
        line = raw.strip()
        if not line or line.startswith(("#", "/*", "*")):
            continue
        line = re.sub(r"\s*##.*$", "", line)
        if line.endswith("{"):
            stack.append(line[:-1].strip())
        elif line == "}":
            if stack:
                stack.pop()
        elif line.endswith(";"):
            stmt = line[:-1].strip()
            prefix = " ".join(stack)
            m = re.match(r"^(.*?)\[\s*(.*?)\s*\]$", stmt)
            if m:  # 'members [ a b ]' -> one set line per member
                for member in m.group(2).split():
                    out.append(f"set {prefix} {m.group(1).strip()} {member}".replace("  ", " "))
            else:
                out.append(f"set {prefix} {stmt}".replace("  ", " "))
    return out


def _set_lines(text: str) -> list[str]:
    lines = [ln.strip() for ln in text.replace("\r", "").split("\n")]
    sets = [ln for ln in lines if ln.startswith("set ")]
    if len(sets) >= 3:
        return sets
    return brace_to_set(text)


def _split(line: str) -> list[str]:
    try:
        return shlex.split(line)
    except ValueError:
        return line.split()


def _ifname(base: str, unit: str) -> str:
    return base if unit in ("", "0") else f"{base}.{unit}"


def _strip_unit0(name: str) -> str:
    return name[:-2] if name.endswith(".0") else name


def parse(text: str) -> Device:
    dev = Device(vendor="juniper_junos")
    vlan_names: dict[str, int] = {}
    member_refs: list[tuple[str, str]] = []  # (ifname, vlan name or id)
    groups: dict[str, dict] = {}
    local_as = ""
    st = junos_policy.State()

    for line in _set_lines(text):
        t = _split(line)[1:]
        if not t:
            continue
        try:
            handled = _policy_statement(st, t) or _statement(dev, t, vlan_names, member_refs, groups)
        except (ValueError, IndexError):
            handled = False
        if not handled and not _IGNORE.match(" ".join(t)):
            dev.unparsed.append(line)

    # routing-options values captured into pseudo fields
    local_as = groups.pop("__asn__", {}).get("asn", "")
    router_id = groups.pop("__rid__", {}).get("rid", "")
    if dev.ospf and router_id and not dev.ospf.router_id:
        dev.ospf.router_id = router_id

    # switchport VLAN members (by name or id)
    for ifname, ref in member_refs:
        itf = dev.iface(ifname)
        vid = ref if re.fullmatch(r"[\d\-]+", ref) else str(vlan_names.get(ref, ""))
        if not vid:
            continue
        if itf.mode == "trunk":
            itf.trunk_vlans = f"{itf.trunk_vlans},{vid}" if itf.trunk_vlans else vid
        else:
            itf.mode = "access"
            itf.access_vlan = int(vid.split("-")[0])

    # BGP groups -> neighbors
    if groups:
        bgp = dev.get_bgp()
        bgp.asn = local_as
        bgp.router_id = router_id
        ip_owner = {str(ipaddress.ip_interface(a).ip): i.name
                    for i in dev.interfaces.values() for a in i.ipv4}
        for g in groups.values():
            for ip, nb in g.get("neighbors", {}).items():
                n = bgp.neighbor(ip)
                internal = g.get("type") == "internal"
                n.remote_as = nb.get("peer-as") or g.get("peer-as") or (local_as if internal else "")
                n.description = nb.get("description") or g.get("description", "")
                local = nb.get("local-address") or g.get("local-address", "")
                n.update_source = ip_owner.get(local, "")
                hop = nb.get("multihop") or g.get("multihop")
                if hop:
                    n.ebgp_multihop = int(hop)
    elif local_as and dev.bgp:
        dev.bgp.asn = local_as
    junos_policy.finish(dev, st, groups)
    if dev.bgp and not dev.bgp.asn:
        dev.bgp.asn = local_as
    return dev


def _policy_statement(st: junos_policy.State, t: list[str]) -> bool:
    """Route policy, firewall, CoS, and policy references (import/export/filter)."""
    if junos_policy.statement(st, t):
        return True
    if t[:2] == ["protocols", "ospf"] and len(t) > 3 and t[2] == "export":
        st.ospf_export += [x for x in t[3:] if x not in ("[", "]") and x not in st.ospf_export]
        return True
    if t[:3] == ["protocols", "bgp", "group"] and len(t) > 5 and ("import" in t or "export" in t):
        group, rest = t[3], t[4:]
        nbr = ""
        if rest[0] == "neighbor":
            nbr, rest = rest[1], rest[2:]
        if rest and rest[0] in ("import", "export"):
            for name in rest[1:]:
                if name not in ("[", "]"):
                    st.bgp_policy.append((group, nbr, rest[0], name))
            return True
    if t[0] == "interfaces" and len(t) > 6 and t[2] == "unit" and t[4:6] == ["family", "inet"]:
        return junos_policy.interface_filter(st, _ifname(t[1], t[3]), t[6:])
    return False


def _statement(dev, t, vlan_names, member_refs, groups) -> bool:
    top = t[0]
    if top == "system":
        return _system(dev, t[1:])
    if top == "snmp":
        if t[1] == "community":
            auth = "rw" if "read-write" in t else "ro"
            if (t[2], auth) not in dev.snmp_communities and not any(c[0] == t[2] for c in dev.snmp_communities):
                dev.snmp_communities.append((t[2], auth))
            elif auth == "rw":
                dev.snmp_communities = [(c, "rw" if c == t[2] else a) for c, a in dev.snmp_communities]
            return True
        if t[1] == "location":
            dev.snmp_location = " ".join(t[2:])
            return True
        if t[1] == "contact":
            dev.snmp_contact = " ".join(t[2:])
            return True
        return False
    if top == "interfaces":
        return _interface(dev, t[1:], member_refs)
    if top == "vlans":
        name = t[1]
        if len(t) > 3 and t[2] == "vlan-id":
            vlan_names[name] = int(t[3])
            dev.vlans[int(t[3])] = "" if name.lower() in (f"vlan{t[3]}", f"v{t[3]}") else name
            return True
        return len(t) > 2 and t[2] in ("l3-interface", "description")
    if top == "routing-options":
        return _routing_options(dev, t[1:], groups)
    if top == "protocols" and len(t) > 1 and t[1] == "ospf":
        return _ospf(dev, t[2:])
    if top == "protocols" and len(t) > 1 and t[1] == "bgp":
        return _bgp(t[2:], groups)
    if top == "protocols" and len(t) > 1 and t[1] in ("lldp", "lldp-med", "rstp", "igmp-snooping"):
        return True
    return False


def _system(dev: Device, t: list[str]) -> bool:
    if t[0] == "host-name":
        dev.hostname = t[1]
    elif t[0] == "domain-name":
        dev.domain = t[1]
    elif t[0] == "name-server":
        dev.dns.append(t[1])
    elif t[0] == "ntp" and t[1] == "server":
        if t[2] not in dev.ntp:
            dev.ntp.append(t[2])
    elif t[0] == "syslog" and t[1] == "host":
        if is_ipv4(t[2]) and t[2] not in dev.syslog:
            dev.syslog.append(t[2])
    elif t[0] == "login" and t[1] == "user":
        if t[2] not in dev.users:
            dev.users.append(t[2])
    else:
        return False
    return True


def _interface(dev: Device, t: list[str], member_refs) -> bool:
    base = t[0]
    rest = t[1:]
    if not rest:
        dev.iface(base)
        return True
    if rest[0] == "unit":
        unit = rest[1]
        name = _ifname(base, unit)
        itf = dev.iface(name)
        r = rest[2:]
        if not r:
            return True
        if r[0] == "description":
            itf.description = " ".join(r[1:])
        elif r[0] == "vlan-id":
            itf.dot1q = int(r[1])
        elif r[0] == "disable":
            itf.shutdown = True
        elif r[:3] == ["family", "inet", "address"]:
            if r[3] not in itf.ipv4:
                if "primary" in r or "preferred" in r:
                    itf.ipv4.insert(0, r[3])
                else:
                    itf.ipv4.append(r[3])
        elif r[:2] == ["family", "inet"] and len(r) == 2:
            pass
        elif r[:2] == ["family", "inet"] and r[2] == "mtu":
            itf.mtu = int(r[3])
        elif r[:2] == ["family", "ethernet-switching"]:
            e = r[2:]
            if not e:
                itf.mode = itf.mode or "access"
            elif e[0] in ("interface-mode", "port-mode"):
                itf.mode = e[1]
            elif e[:2] == ["vlan", "members"]:
                for ref in e[2:]:
                    if ref not in ("[", "]"):
                        member_refs.append((name, ref))
            else:
                return False
        else:
            return False
        return True
    itf = dev.iface(base)
    if rest[0] == "description":
        if not itf.description:
            itf.description = " ".join(rest[1:])
    elif rest[0] == "disable":
        itf.shutdown = True
    elif rest[0] == "mtu":
        itf.mtu = int(rest[1])
    elif rest[0] in ("vlan-tagging", "flexible-vlan-tagging", "encapsulation", "native-vlan-id",
                     "gigether-options", "ether-options", "aggregated-ether-options", "speed",
                     "link-mode"):
        pass
    else:
        return False
    return True


def _routing_options(dev: Device, t: list[str], groups) -> bool:
    if t[0] == "router-id":
        groups["__rid__"] = {"rid": t[1]}
    elif t[0] == "autonomous-system":
        groups["__asn__"] = {"asn": t[1]}
    elif t[:2] == ["static", "route"]:
        prefix = t[2]
        route = next((r for r in dev.static_routes if r.prefix == prefix and not r.vrf), None)
        opts = t[3:]
        if not opts:
            return True
        if opts[0] in ("next-hop", "qualified-next-hop"):
            if route is None or (route.nexthop or route.interface):
                route = StaticRoute(prefix=prefix)
                dev.static_routes.append(route)
            if is_ipv4(opts[1]):
                route.nexthop = opts[1]
            else:
                route.interface = _strip_unit0(opts[1])
            if "preference" in opts:
                route.distance = int(opts[opts.index("preference") + 1])
        elif opts[0] == "preference" and route:
            route.distance = int(opts[1])
        elif opts[0] in ("discard", "reject"):
            dev.static_routes.append(StaticRoute(prefix=prefix, interface="Null0"))
        else:
            return False
    else:
        return False
    return True


def _ospf(dev: Device, t: list[str]) -> bool:
    ospf = dev.get_ospf()
    if t[0] == "area" and len(t) > 3 and t[2] == "interface":
        name = _strip_unit0(t[3])
        if name == "all":
            return False
        itf = dev.iface(name)
        itf.ospf_area = t[1]
        opts = t[4:]
        if "passive" in opts and name not in ospf.passive:
            ospf.passive.append(name)
        if "metric" in opts:
            itf.ospf_cost = int(opts[opts.index("metric") + 1])
        return not opts or opts[0] in ("passive", "metric", "interface-type")
    if t[0] == "area" and len(t) == 2:
        return True
    if t[0] == "reference-bandwidth":
        return True
    return False


def _bgp(t: list[str], groups) -> bool:
    if t[0] != "group" or len(t) < 3:
        return False
    g = groups.setdefault(t[1], {"neighbors": {}})
    opts = t[2:]
    target = g
    if opts[0] == "neighbor":
        target = g["neighbors"].setdefault(opts[1], {})
        opts = opts[2:]
        if not opts:
            return True
    key = opts[0]
    if key in ("type", "peer-as", "local-address"):
        target[key] = opts[1]
    elif key == "description":
        target[key] = " ".join(opts[1:])
    elif key == "multihop":
        target[key] = opts[2] if len(opts) > 2 and opts[1] == "ttl" else "255"
    elif key in ("family",):
        pass
    else:
        return False
    return True


# kept for symmetry with other parsers
__all__ = ["parse", "brace_to_set", "OspfNetwork"]
