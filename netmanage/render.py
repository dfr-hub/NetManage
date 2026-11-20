"""Device model -> target vendor config, rendered with Jinja2 templates."""
from __future__ import annotations

import ipaddress
import re

from jinja2 import ChoiceLoader, Environment, FileSystemLoader, StrictUndefined

from . import policy_render
from .ifnames import NameMap
from .model import (VENDORS, Device, area_dotted, area_short, prefix_to_mask,
                    prefix_to_wildcard)
from .paths import bundled_templates, user_templates

COMMENT = {"cisco_ios": "!", "arista_eos": "!", "aruba_aoscx": "!"}


def expand_vlans(spec: str, limit: int = 4094) -> list[int]:
    out: list[int] = []
    for part in str(spec or "").replace(" ", "").split(","):
        if "-" in part:
            a, _, b = part.partition("-")
            if a.isdigit() and b.isdigit():
                out += list(range(int(a), min(int(b), limit) + 1))
        elif part.isdigit():
            out.append(int(part))
    return out


def _vrp_vlans(spec: str) -> str:
    return " ".join(p.replace("-", " to ") for p in str(spec or "").split(",") if p)


def _unit(name: str) -> str:
    return name if re.search(r"\.\d+$", name) else f"{name}.0"


def _quote(text) -> str:
    return '"' + str(text).replace('"', "'") + '"'


def _net(prefix: str) -> dict:
    n = ipaddress.ip_network(prefix, strict=False)
    return {"prefix": str(n), "net": str(n.network_address), "plen": n.prefixlen,
            "mask": str(n.netmask), "wildcard": str(n.hostmask)}


def _env() -> Environment:
    env = Environment(
        loader=ChoiceLoader([FileSystemLoader(str(user_templates())),
                             FileSystemLoader(str(bundled_templates()))]),
        trim_blocks=True, lstrip_blocks=True, keep_trailing_newline=True,
        undefined=StrictUndefined, autoescape=False,
    )
    env.filters.update(mask=prefix_to_mask, wildcard=prefix_to_wildcard, area_dotted=area_dotted,
                       area_short=area_short, vrp_vlans=_vrp_vlans, unit=_unit, q=_quote,
                       expand_vlans=expand_vlans, ios_addr=policy_render.ios_addr,
                       eos_addr=policy_render.eos_addr, aruba_addr=policy_render.aruba_addr,
                       vrp_addr=policy_render.vrp_addr, ios_ports=policy_render.ios_ports,
                       dash_ports=policy_render.dash_ports)
    env.globals.update(ios_ports=policy_render.ios_ports, dash_ports=policy_render.dash_ports)
    env.filters["junos_dscp"] = policy_render.junos_dscp
    return env


def build_context(dev: Device, dst: str, m: NameMap, warnings: list[str]) -> dict:
    def warn(message: str) -> str:
        if message not in warnings:
            warnings.append(message)
        return ""

    areas_by_if = dev.ospf_interface_areas()
    passive_src = set(dev.ospf.passive) if dev.ospf else set()
    passive_nets = []
    for p in passive_src:
        if p.startswith("network:"):
            try:
                passive_nets.append(ipaddress.ip_network(p[8:], strict=False))
            except ValueError:
                pass
    passive_mapped = {m(p) for p in passive_src if not p.startswith("network:")}

    interfaces = []
    by_src: dict[str, dict] = {}
    for itf in dev.interfaces.values():
        if itf.kind == "null":
            continue
        name = m(itf.name)
        mt = re.match(r"^(.*)\.(\d+)$", name)
        parent, unit = (mt.group(1), mt.group(2)) if mt else (name, "")
        addrs = []
        for idx, a in enumerate(itf.ipv4):
            ii = ipaddress.ip_interface(a)
            addrs.append({"ip": str(ii.ip), "plen": ii.network.prefixlen, "mask": str(ii.netmask),
                          "cidr": f"{ii.ip}/{ii.network.prefixlen}", "net": str(ii.network),
                          "secondary": idx > 0})
        passive = name in passive_mapped or any(
            ipaddress.ip_interface(a).ip in n for a in itf.ipv4 for n in passive_nets)
        tail = re.search(r"(\d+)$", name)
        kind = itf.kind
        port = parent + (f":{unit}" if unit else "")
        sros_name = name if kind in ("loopback", "vlan") else f"if-{name}"
        d = {
            "name": name, "src": itf.name, "kind": kind, "description": itf.description,
            "addrs": addrs, "shutdown": itf.shutdown, "mtu": itf.mtu, "vrf": itf.vrf,
            "mode": itf.mode, "access_vlan": itf.access_vlan, "trunk_vlans": itf.trunk_vlans,
            "dot1q": itf.dot1q or (int(unit) if unit and kind in ("physical", "lag") else None),
            "parent": parent, "unit": unit, "unit_name": _unit(name),
            "number": tail.group(1) if tail else "",
            "ospf_area": areas_by_if.get(itf.name, ""), "ospf_cost": itf.ospf_cost,
            "passive": passive, "routed": bool(addrs),
            "sros_name": sros_name[:32], "sros_port": port,
            "vyos_type": {"loopback": "dummy", "lag": "bonding", "vlan": "bridge", "bridge": "bridge",
                          "tunnel": "tunnel"}.get(kind, "ethernet"),
            "acl_in": "", "acl_out": "", "qos_in": "", "qos_out": "",
        }
        interfaces.append(d)
        by_src[itf.name] = d

    ports: dict[str, dict] = {}
    for d in interfaces:
        if d["kind"] not in ("physical", "lag"):
            continue
        p = ports.setdefault(d["parent"], {"name": d["parent"], "kind": d["kind"], "tagged": False,
                                           "description": "", "shutdown": False, "mtu": None,
                                           "number": re.sub(r"^\D+", "", d["parent"])})
        if d["unit"]:
            p["tagged"] = True
        else:
            p.update(description=d["description"], shutdown=d["shutdown"], mtu=d["mtu"])

    vlan_ids = set(dev.vlans)
    for d in interfaces:
        if d["access_vlan"]:
            vlan_ids.add(d["access_vlan"])
    vlans = []
    svi = {d["number"]: d["name"] for d in interfaces if d["kind"] == "vlan"}
    for vid in sorted(vlan_ids):
        name = dev.vlans.get(vid, "")
        tagged = [d["name"] for d in interfaces if d["mode"] == "trunk"
                  and (not d["trunk_vlans"] or vid in expand_vlans(d["trunk_vlans"]))]
        untagged = [d["name"] for d in interfaces if d["mode"] == "access" and d["access_vlan"] == vid]
        vlans.append({"id": vid, "name": name,
                      "label": re.sub(r"[^\w\-]", "_", name) if name else f"VLAN{vid}",
                      "svi": svi.get(str(vid), ""), "tagged": tagged, "untagged": untagged})

    def out_if(nexthop: str) -> str:
        try:
            ip = ipaddress.ip_address(nexthop)
        except ValueError:
            return ""
        for d in interfaces:
            if any(ip in ipaddress.ip_network(a["net"]) for a in d["addrs"]):
                return d["name"]
        return ""

    routes = []
    for r in dev.static_routes:
        null = r.interface.lower().startswith(("null", "blackhole", "dsc"))
        iface = "" if null else m(r.interface)
        routes.append({**_net(r.prefix), "nexthop": r.nexthop, "interface": iface, "null": null,
                       "distance": r.distance, "vrf": r.vrf, "description": r.description,
                       "out_if": iface or out_if(r.nexthop)})

    ospf = None
    if dev.ospf:
        o = dev.ospf
        nets = [{**_net(n.prefix), "area": n.area, "area_dotted": area_dotted(n.area),
                 "area_short": area_short(n.area)} for n in dev.ospf_networks_resolved()]
        unmatched = []
        for n in nets:
            net = ipaddress.ip_network(n["prefix"])
            hit = any(ipaddress.ip_address(a["ip"]) in net for d in interfaces for a in d["addrs"])
            if not hit:
                unmatched.append(n)
        area_ids: list[str] = []
        for a in [d["ospf_area"] for d in interfaces if d["ospf_area"]] + [n["area"] for n in nets]:
            if area_dotted(a) not in area_ids:
                area_ids.append(area_dotted(a))
        areas = [{"id": a, "dotted": a, "short": area_short(a),
                  "interfaces": [d for d in interfaces if d["ospf_area"] and area_dotted(d["ospf_area"]) == a],
                  "networks": [n for n in nets if n["area_dotted"] == a],
                  "unmatched": [n for n in unmatched if n["area_dotted"] == a]} for a in area_ids]
        ospf = {"process": o.process or "1", "router_id": o.router_id, "networks": nets,
                "unmatched": unmatched, "areas": areas,
                "passive": [d["name"] for d in interfaces if d["passive"]],
                "redistribute": list(dict.fromkeys(o.redistribute)),
                "redistribute_map": dict(o.redistribute_map),
                "default_originate": o.default_originate}

    bgp = None
    if dev.bgp:
        b = dev.bgp
        neighbors = []
        for n in b.neighbors:
            src = by_src.get(n.update_source)
            neighbors.append({
                "ip": n.ip, "remote_as": n.remote_as, "internal": bool(b.asn) and n.remote_as == b.asn,
                "description": n.description, "update_source": m(n.update_source),
                "update_source_ip": src["addrs"][0]["ip"] if src and src["addrs"] else "",
                "multihop": n.ebgp_multihop, "next_hop_self": n.next_hop_self, "shutdown": n.shutdown,
                "route_map_in": n.route_map_in, "route_map_out": n.route_map_out,
            })
        groups: dict[str, dict] = {}
        for n in neighbors:
            key = "IBGP" if n["internal"] else f"EBGP-AS{n['remote_as'] or 'UNKNOWN'}"
            g = groups.setdefault(key, {"name": key, "internal": n["internal"],
                                        "peer_as": n["remote_as"], "neighbors": []})
            g["neighbors"].append(n)
        bgp = {"asn": b.asn, "router_id": b.router_id, "neighbors": neighbors,
               "networks": [_net(p) for p in dict.fromkeys(b.networks)],
               "redistribute": list(dict.fromkeys(b.redistribute)),
               "redistribute_map": dict(b.redistribute_map), "groups": list(groups.values())}

    vrfs = sorted({d["vrf"] for d in interfaces if d["vrf"]} | {r["vrf"] for r in routes if r["vrf"]})
    pctx = policy_render.build(dev, dst, m, by_src, warn)

    return {
        **pctx,
        "comment": COMMENT.get(dst, "#"), "src_vendor": dev.vendor, "dst_vendor": dst,
        "src_label": VENDORS.get(dev.vendor, dev.vendor), "dst_label": VENDORS.get(dst, dst),
        "hostname": dev.hostname, "domain": dev.domain, "dns": dev.dns, "ntp": dev.ntp,
        "syslog": dev.syslog,
        "snmp": [{"name": n, "access": a} for n, a in dev.snmp_communities],
        "snmp_location": dev.snmp_location, "snmp_contact": dev.snmp_contact, "users": dev.users,
        "vlans": vlans, "interfaces": interfaces, "ports": list(ports.values()), "vrfs": vrfs,
        "routes": routes, "ospf": ospf, "bgp": bgp,
        "router_id": (ospf or {}).get("router_id") or (bgp or {}).get("router_id") or "",
        "needs_bridge": any(d["mode"] or d["kind"] == "vlan" for d in interfaces),
        "warn": warn,
    }


def render(dev: Device, dst: str) -> tuple[str, NameMap, list[str]]:
    """Return (config text, interface name map, warnings)."""
    if dst not in VENDORS:
        raise ValueError(f"Vendor tujuan tidak dikenal: {dst}")
    m = NameMap(dev, dst)
    warnings: list[str] = list(m.warnings)
    if dev.users:
        warnings.append("User lokal tidak dikonversi (hash password tidak bisa dipindah antar vendor): "
                        + ", ".join(dev.users))
    ctx = build_context(dev, dst, m, warnings)
    text = _env().get_template(f"{dst}.j2").render(**ctx)
    text = "\n".join(line.rstrip() for line in text.split("\n"))
    text = re.sub(r"\n{3,}", "\n\n", text).strip() + "\n"
    return text, m, warnings
