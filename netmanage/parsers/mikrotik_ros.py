"""MikroTik RouterOS '/export' parser (v6 and v7 syntax)."""
from __future__ import annotations

import re

from ..model import Device, OspfNetwork, StaticRoute, is_ipv4
from . import ros_policy

_KV = re.compile(r'([\w.\-]+)=("(?:[^"\\]|\\.)*"|\S*)')

_IGNORE_PATHS = (
    "/interface wireless", "/interface list", "/interface lte", "/interface detect-internet",
    "/ip pool", "/ip dhcp-server", "/ip dhcp-client", "/ip service", "/ip neighbor",
    "/ip settings", "/ip cloud", "/ip smb", "/ip ssh", "/ip hotspot", "/ip upnp", "/ip proxy",
    "/system clock", "/system note", "/system routerboard", "/system package", "/system script",
    "/system scheduler", "/system leds", "/tool", "/port", "/disk", "/certificate", "/ipv6",
    "/queue simple", "/queue type", "/queue interface", "/user group", "/system logging", "/routing bfd", "/routing id", "/ppp", "/radius",
    "/lcd", "/console", "/routing table", "/routing rule", "/system health", "/system watchdog",
    "/interface ethernet switch", "/interface bridge settings", "/routing bgp template",
)


def _logical_lines(text: str) -> list[str]:
    out: list[str] = []
    buf = ""
    for raw in text.replace("\r", "").split("\n"):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith("\\"):
            buf += line[:-1].lstrip() if buf else line[:-1]
            continue
        out.append(buf + line)
        buf = ""
    if buf:
        out.append(buf)
    return out


def _kv(line: str) -> tuple[dict[str, str], str, set[str]]:
    """Return (key=value pairs, 'find' expression, bare flags)."""
    find = ""
    m = re.search(r"\[\s*find\s+(.*?)\]", line)
    if m:
        find = m.group(1).strip()
        line = line.replace(m.group(0), " ")
    pairs = {k: v.strip('"').replace('\\"', '"') for k, v in _KV.findall(line)}
    flags = set(_KV.sub(" ", line).split())
    return pairs, find, flags


def _yes(pairs: dict[str, str], key: str) -> bool:
    return pairs.get(key, "no").lower() in ("yes", "true")


def parse(text: str) -> Device:
    dev = Device(vendor="mikrotik_ros")
    alias: dict[str, str] = {}  # routeros interface name -> neutral name
    areas: dict[str, str] = {}  # area name -> area id
    path = ""
    st = ros_policy.State()

    def nm(name: str) -> str:
        return alias.get(name, name)

    for line in _logical_lines(text):
        if line.startswith("/"):
            m = re.match(r"^(/.*?)(?:\s+(add|set)\s+(.*))?$", line)
            path = m.group(1).strip() if m else line
            if not (m and m.group(2)):
                continue
            action, rest = m.group(2), m.group(3)
        else:
            parts = line.split(None, 1)
            action, rest = parts[0], parts[1] if len(parts) > 1 else ""
        if action not in ("add", "set"):
            continue
        pairs, find, flags = _kv(rest)
        try:
            ok = (action == "add" and ros_policy.handle(st, path, pairs)) or \
                _apply(dev, path, action, pairs, find, flags, alias, areas, nm)
        except (ValueError, IndexError, KeyError):
            ok = False
        if not ok and not path.startswith(_IGNORE_PATHS):
            dev.unparsed.append(f"{path} {action} {rest}")
    st.ospf_chain = dev.__dict__.pop("_ros", {}).get("ospf_chain", "")
    ros_policy.finish(dev, st, nm)
    if dev.ospf and st.ospf_chain:
        for proto in dev.ospf.redistribute:
            dev.ospf.redistribute_map.setdefault(proto, st.ospf_chain)
    return dev


def _apply(dev, path, action, p, find, flags, alias, areas, nm) -> bool:
    if path == "/system identity":
        dev.hostname = p.get("name", dev.hostname)
    elif path == "/interface ethernet":
        default = re.search(r"default-name=(\S+)", find)
        name = p.get("name") or (default.group(1) if default else "")
        if not name:
            return False
        itf = dev.iface(name)
        itf.description = p.get("comment", itf.description)
        itf.shutdown = _yes(p, "disabled")
        if "mtu" in p:
            itf.mtu = int(p["mtu"])
    elif path == "/interface bridge":
        name = p["name"]
        itf = dev.iface(name)
        itf.description = p.get("comment", "")
    elif path == "/interface bonding":
        dev.iface(p["name"]).description = p.get("comment", "")
    elif path == "/interface vlan":
        parent, vid, name = nm(p["interface"]), int(p["vlan-id"]), p["name"]
        parent_itf = dev.interfaces.get(parent)
        if parent_itf is not None and parent_itf.kind == "bridge":
            neutral = f"vlan{vid}"
            dev.vlans.setdefault(vid, "" if name.lower() == neutral else name)
        else:
            neutral = f"{parent}.{vid}"
        alias[name] = neutral
        itf = dev.iface(neutral)
        if neutral != f"vlan{vid}":
            itf.dot1q = vid
        itf.description = p.get("comment", "" if name == neutral else name)
        itf.shutdown = _yes(p, "disabled")
    elif path == "/interface bridge port":
        itf = dev.iface(nm(p["interface"]))
        if "pvid" in p and p["pvid"] != "1":
            itf.mode, itf.access_vlan = "access", int(p["pvid"])
            dev.vlans.setdefault(int(p["pvid"]), "")
    elif path == "/interface bridge vlan":
        vids = p.get("vlan-ids", "")
        for part in vids.split(","):
            if part.isdigit():
                dev.vlans.setdefault(int(part), "")
        for port in filter(None, p.get("tagged", "").split(",")):
            itf = dev.interfaces.get(nm(port))
            if itf is not None and itf.kind != "bridge":
                itf.mode = "trunk"
                itf.trunk_vlans = f"{itf.trunk_vlans},{vids}" if itf.trunk_vlans else vids
    elif path == "/ip address":
        itf = dev.iface(nm(p["interface"]))
        itf.ipv4.append(p["address"] if "/" in p["address"] else p["address"] + "/32")
        if p.get("comment") and not itf.description:
            itf.description = p["comment"]
    elif path == "/ip route":
        gw = p.get("gateway", "")
        r = StaticRoute(prefix=p.get("dst-address", "0.0.0.0/0"), description=p.get("comment", ""))
        if "/" not in r.prefix:
            r.prefix += "/32"
        if is_ipv4(gw):
            r.nexthop = gw
        elif gw:
            r.interface = nm(gw)
        elif p.get("type") == "blackhole" or "blackhole" in flags:
            r.interface = "Null0"
        if p.get("distance", "1") != "1":
            r.distance = int(p["distance"])
        if p.get("routing-table", "main") != "main":
            r.vrf = p["routing-table"]
        dev.static_routes.append(r)
    elif path == "/ip dns":
        dev.dns += [s for s in p.get("servers", "").split(",") if s]
    elif path == "/system ntp client servers":
        dev.ntp.append(p["address"])
    elif path == "/system ntp client":
        for key in ("primary-ntp", "secondary-ntp"):
            if p.get(key, "0.0.0.0") != "0.0.0.0":
                dev.ntp.append(p[key])
        dev.ntp += [s for s in p.get("servers", "").split(",") if s]
    elif path == "/system logging action":
        if p.get("remote"):
            dev.syslog.append(p["remote"])
    elif path == "/snmp community":
        name = p.get("name", "")
        if name:
            dev.snmp_communities.append((name, "rw" if _yes(p, "write-access") else "ro"))
    elif path == "/snmp":
        dev.snmp_location = p.get("location", dev.snmp_location)
        dev.snmp_contact = p.get("contact", dev.snmp_contact)
    elif path == "/user":
        if p.get("name") and p["name"] not in dev.users:
            dev.users.append(p["name"])
    elif path == "/routing ospf instance":
        ospf = dev.get_ospf()
        ospf.router_id = p.get("router-id", ospf.router_id) if is_ipv4(p.get("router-id", "")) else ospf.router_id
        redist = p.get("redistribute", "")
        ospf.redistribute += [x for x in redist.split(",") if x]
        for key, proto in (("redistribute-static", "static"), ("redistribute-connected", "connected")):
            if p.get(key, "no") not in ("no", ""):
                ospf.redistribute.append(proto)
        if p.get("out-filter-chain"):
            dev.__dict__.setdefault("_ros", {})["ospf_chain"] = p["out-filter-chain"]
        if p.get("originate-default", p.get("distribute-default", "never")) not in ("never", ""):
            ospf.default_originate = True
    elif path == "/routing ospf area":
        dev.get_ospf()
        areas[p.get("name", "backbone")] = p.get("area-id", "0.0.0.0")
    elif path in ("/routing ospf interface-template", "/routing ospf network", "/routing ospf interface"):
        ospf = dev.get_ospf()
        area = areas.get(p.get("area", "backbone"), "0.0.0.0")
        passive = "passive" in flags or _yes(p, "passive")
        for net in filter(None, (p.get("networks") or p.get("network", "")).split(",")):
            ospf.networks.append(OspfNetwork(net, area))
            if passive:
                ospf.passive.append(f"network:{net}")
        for name in filter(None, (p.get("interfaces") or p.get("interface", "")).split(",")):
            if name == "all":
                continue
            itf = dev.iface(nm(name))
            if path != "/routing ospf interface":
                itf.ospf_area = area
            if "cost" in p:
                itf.ospf_cost = int(p["cost"])
            if passive and itf.name not in ospf.passive:
                ospf.passive.append(itf.name)
    elif path == "/routing bgp instance":
        bgp = dev.get_bgp()
        bgp.asn = p.get("as", bgp.asn)
        bgp.router_id = p.get("router-id", bgp.router_id)
    elif path in ("/routing bgp connection", "/routing bgp peer"):
        bgp = dev.get_bgp()
        ip = (p.get("remote.address") or p.get("remote-address", "")).split("/")[0]
        if not ip:
            return False
        n = bgp.neighbor(ip)
        n.remote_as = p.get("remote.as") or p.get("remote-as", "")
        n.description = p.get("comment") or p.get("name", "")
        n.shutdown = _yes(p, "disabled")
        if p.get("as"):
            bgp.asn = p["as"]
        if is_ipv4(p.get("router-id", "")):
            bgp.router_id = p["router-id"]
        src = p.get("local.address") or p.get("update-source", "")
        if src:
            owner = next((i.name for i in dev.interfaces.values()
                          if any(a.split("/")[0] == src for a in i.ipv4)), "")
            n.update_source = owner or nm(src) if not is_ipv4(src) else owner
        if _yes(p, "multihop"):
            n.ebgp_multihop = int(p.get("ttl", "255")) if p.get("ttl", "").isdigit() else 255
        if p.get("nexthop-choice") == "force-self":
            n.next_hop_self = True
        if p.get("input.filter"):
            n.route_map_in = p["input.filter"]
        if p.get("output.filter-chain"):
            n.route_map_out = p["output.filter-chain"]
    elif path == "/routing bgp network":
        dev.get_bgp().networks.append(p["network"])
    elif path == "/ip firewall address-list" and p.get("list", "").lower().startswith("bgp"):
        dev.get_bgp().networks.append(p["address"] if "/" in p["address"] else p["address"] + "/32")
    else:
        return False
    return True
