"""Topology discovery from parsed configurations.

Links are inferred from:
  1. shared IP subnets (two members = point-to-point link, more = LAN segment)
  2. BGP sessions (neighbor address owned by another loaded device)
  3. interface descriptions naming another loaded device (L2 hint, when no IP link exists)
"""
from __future__ import annotations

import ipaddress
import math
import random
import re
from dataclasses import dataclass, field
from xml.sax.saxutils import escape

from .model import VENDORS, Device

VENDOR_COLORS = {
    "cisco_ios": "#1BA0D7", "juniper_junos": "#84B135", "mikrotik_ros": "#7B8794",
    "huawei_vrp": "#E2231A", "fortinet_fortios": "#EE3124", "arista_eos": "#2F5C9E",
    "h3c_comware": "#D9001B", "nokia_sros": "#124191", "vyos": "#F28C28", "aruba_aoscx": "#FF8300",
    "": "#6B7280",
}


@dataclass
class Node:
    id: str
    label: str
    kind: str = "router"  # router | lan | external
    vendor: str = ""
    detail: str = ""
    x: float = 0.0
    y: float = 0.0


@dataclass
class Link:
    a: str
    b: str
    a_if: str = ""
    b_if: str = ""
    a_ip: str = ""
    b_ip: str = ""
    label: str = ""
    kind: str = "l3"  # l3 | lan | bgp | hint


@dataclass
class Topology:
    nodes: dict[str, Node] = field(default_factory=dict)
    links: list[Link] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _short_if(name: str) -> str:
    table = (("TenGigabitEthernet", "Te"), ("XGigabitEthernet", "XGE"), ("Ten-GigabitEthernet", "XGE"),
             ("GigabitEthernet", "Gi"), ("FastEthernet", "Fa"), ("Ethernet", "Eth"),
             ("Port-channel", "Po"), ("Port-Channel", "Po"), ("Loopback", "Lo"), ("LoopBack", "Lo"),
             ("Vlan-interface", "Vlan"), ("Vlanif", "Vlanif"))
    for long, short in table:
        if name.startswith(long):
            return short + name[len(long):]
    return name


def build(devices: list[Device], show_external: bool = True, show_stub: bool = False) -> Topology:
    topo = Topology()
    used: set[str] = set()
    names: dict[int, str] = {}
    for idx, dev in enumerate(devices):
        base = dev.hostname or (dev.source.replace("\\", "/").split("/")[-1] if dev.source else f"device{idx + 1}")
        name, n = base, 2
        while name in used:
            name, n = f"{base} ({n})", n + 1
        used.add(name)
        names[id(dev)] = name
        ips = sum(len(i.ipv4) for i in dev.interfaces.values())
        detail = f"{VENDORS.get(dev.vendor, dev.vendor)}\n{len(dev.interfaces)} interface, {ips} IP"
        if dev.bgp and dev.bgp.asn:
            detail += f"\nAS {dev.bgp.asn}"
        topo.nodes[name] = Node(id=name, label=name, vendor=dev.vendor, detail=detail)

    # ---- 1. shared subnets
    subnets: dict[ipaddress.IPv4Network, list[tuple[str, str, str]]] = {}
    owner: dict[str, tuple[str, str]] = {}  # ip -> (device, interface)
    for dev in devices:
        me = names[id(dev)]
        for itf in dev.interfaces.values():
            for addr in itf.ipv4:
                try:
                    ii = ipaddress.ip_interface(addr)
                except ValueError:
                    continue
                if ii.version != 4:
                    continue
                owner[str(ii.ip)] = (me, itf.name)
                if ii.network.prefixlen >= 32 or itf.is_loopback or itf.shutdown:
                    continue
                subnets.setdefault(ii.network, []).append((me, itf.name, str(ii.ip)))

    linked: set[frozenset] = set()
    for net, members in sorted(subnets.items(), key=lambda kv: kv[0]):
        devs = {m[0] for m in members}
        ips = [m[2] for m in members]
        if len(set(ips)) != len(ips):
            topo.notes.append(f"IP duplikat di subnet {net}: " + ", ".join(f"{m[0]} {m[2]}" for m in members))
        if len(devs) == 2 and len(members) == 2:
            (a, a_if, a_ip), (b, b_if, b_ip) = members
            topo.links.append(Link(a, b, _short_if(a_if), _short_if(b_if), a_ip, b_ip, str(net), "l3"))
            linked.add(frozenset((a, b)))
        elif len(devs) >= 2:
            lan = f"LAN {net}"
            topo.nodes[lan] = Node(id=lan, label=str(net), kind="lan", detail=f"Segmen multi-akses\n{len(members)} anggota")
            for dev_name, ifname, ip in members:
                topo.links.append(Link(dev_name, lan, _short_if(ifname), "", ip, "", "", "lan"))
            for a in devs:
                for b in devs:
                    if a != b:
                        linked.add(frozenset((a, b)))
        elif show_stub:
            dev_name, ifname, ip = members[0]
            lan = f"LAN {net}"
            topo.nodes[lan] = Node(id=lan, label=str(net), kind="lan", detail="Stub network")
            topo.links.append(Link(dev_name, lan, _short_if(ifname), "", ip, "", "", "lan"))

    # ---- 2. BGP sessions
    seen_bgp: set[frozenset] = set()
    for dev in devices:
        if not dev.bgp:
            continue
        me = names[id(dev)]
        for n in dev.bgp.neighbors:
            peer = owner.get(n.ip)
            if peer and peer[0] != me:
                key = frozenset((me, peer[0]))
                if key in seen_bgp:
                    continue
                seen_bgp.add(key)
                kind = "iBGP" if n.remote_as == dev.bgp.asn else "eBGP"
                topo.links.append(Link(me, peer[0], "", "", "", n.ip,
                                       f"{kind} AS{dev.bgp.asn}-AS{n.remote_as}", "bgp"))
            elif not peer and show_external:
                ext = f"AS{n.remote_as or '?'} {n.ip}"
                topo.nodes.setdefault(ext, Node(id=ext, label=f"AS{n.remote_as or '?'}\n{n.ip}", kind="external",
                                                detail=n.description or "BGP peer di luar konfigurasi yang dimuat"))
                topo.links.append(Link(me, ext, "", "", "", n.ip, n.description or "eBGP", "bgp"))

    # ---- 3. description hints
    for dev in devices:
        me = names[id(dev)]
        for itf in dev.interfaces.values():
            if not itf.description or itf.is_loopback:
                continue
            desc = itf.description.lower()
            for other in used:
                if other == me or len(other) < 3:
                    continue
                if re.search(rf"(?<![\w]){re.escape(other.lower())}(?![\w])", desc):
                    key = frozenset((me, other))
                    if key not in linked:
                        linked.add(key)
                        topo.links.append(Link(me, other, _short_if(itf.name), "", "", "",
                                               "dari description", "hint"))

    if not topo.links and len(devices) > 1:
        topo.notes.append("Tidak ada link terdeteksi. Pastikan konfigurasi berasal dari jaringan yang sama.")
    layout(topo)
    return topo


def layout(topo: Topology, width: float = 1000.0, height: float = 700.0, iterations: int = 300) -> None:
    """Fruchterman-Reingold force-directed layout."""
    nodes = list(topo.nodes.values())
    n = len(nodes)
    if n == 0:
        return
    rng = random.Random(7)
    for i, node in enumerate(nodes):  # start on a circle, deterministic
        angle = 2 * math.pi * i / n
        node.x = width / 2 + math.cos(angle) * width * 0.35 + rng.uniform(-5, 5)
        node.y = height / 2 + math.sin(angle) * height * 0.35 + rng.uniform(-5, 5)
    if n == 1:
        nodes[0].x, nodes[0].y = width / 2, height / 2
        return
    k = math.sqrt(width * height / n) * 0.75
    pairs = {(lk.a, lk.b) for lk in topo.links if lk.kind != "bgp" or True}
    temp = width / 8
    for _ in range(iterations):
        disp = {node.id: [0.0, 0.0] for node in nodes}
        for i in range(n):
            for j in range(i + 1, n):
                a, b = nodes[i], nodes[j]
                dx, dy = a.x - b.x, a.y - b.y
                dist = math.hypot(dx, dy) or 0.01
                force = k * k / dist
                fx, fy = dx / dist * force, dy / dist * force
                disp[a.id][0] += fx
                disp[a.id][1] += fy
                disp[b.id][0] -= fx
                disp[b.id][1] -= fy
        for a_id, b_id in pairs:
            a, b = topo.nodes[a_id], topo.nodes[b_id]
            dx, dy = a.x - b.x, a.y - b.y
            dist = math.hypot(dx, dy) or 0.01
            force = dist * dist / k
            fx, fy = dx / dist * force, dy / dist * force
            disp[a.id][0] -= fx
            disp[a.id][1] -= fy
            disp[b.id][0] += fx
            disp[b.id][1] += fy
        for node in nodes:
            dx, dy = disp[node.id]
            dx += (width / 2 - node.x) * 0.02
            dy += (height / 2 - node.y) * 0.02
            dist = math.hypot(dx, dy) or 0.01
            step = min(dist, temp)
            node.x = min(width - 60, max(60, node.x + dx / dist * step))
            node.y = min(height - 40, max(40, node.y + dy / dist * step))
        temp = max(1.0, temp * 0.97)


# ------------------------------------------------------------------ exports
LINK_STYLE = {"l3": ("#334155", ""), "lan": ("#64748B", ""), "bgp": ("#7C3AED", "6,4"),
              "hint": ("#94A3B8", "2,4")}


def to_csv(topo: Topology) -> str:
    rows = ["device_a,interface_a,ip_a,device_b,interface_b,ip_b,type,info"]
    for lk in topo.links:
        rows.append(",".join(f'"{v}"' for v in (lk.a, lk.a_if, lk.a_ip, lk.b, lk.b_if, lk.b_ip,
                                                 lk.kind, lk.label)))
    return "\n".join(rows) + "\n"


def to_svg(topo: Topology) -> str:
    xs = [n.x for n in topo.nodes.values()] or [0]
    ys = [n.y for n in topo.nodes.values()] or [0]
    min_x, min_y = min(xs) - 120, min(ys) - 80
    w, h = max(xs) - min_x + 120, max(ys) - min_y + 80
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{min_x:.0f} {min_y:.0f} {w:.0f} {h:.0f}" '
           f'font-family="Segoe UI, Arial, sans-serif">',
           f'<rect x="{min_x:.0f}" y="{min_y:.0f}" width="{w:.0f}" height="{h:.0f}" fill="#FFFFFF"/>']
    for lk in topo.links:
        a, b = topo.nodes[lk.a], topo.nodes[lk.b]
        color, dash = LINK_STYLE[lk.kind]
        dash_attr = f' stroke-dasharray="{dash}"' if dash else ""
        out.append(f'<line x1="{a.x:.1f}" y1="{a.y:.1f}" x2="{b.x:.1f}" y2="{b.y:.1f}" stroke="{color}" '
                   f'stroke-width="2"{dash_attr}/>')
        mx, my = (a.x + b.x) / 2, (a.y + b.y) / 2
        if lk.label:
            out.append(f'<text x="{mx:.1f}" y="{my - 4:.1f}" font-size="10" fill="#475569" '
                       f'text-anchor="middle">{escape(lk.label)}</text>')
        for frac, text in ((0.22, " ".join(filter(None, (lk.a_if, lk.a_ip)))),
                           (0.78, " ".join(filter(None, (lk.b_if, lk.b_ip))))):
            if text and lk.kind != "bgp":
                tx, ty = a.x + (b.x - a.x) * frac, a.y + (b.y - a.y) * frac
                out.append(f'<text x="{tx:.1f}" y="{ty + 12:.1f}" font-size="9" fill="#0F172A" '
                           f'text-anchor="middle">{escape(text)}</text>')
    for node in topo.nodes.values():
        lines = node.label.split("\n")
        if node.kind == "router":
            color = VENDOR_COLORS.get(node.vendor, VENDOR_COLORS[""])
            out.append(f'<rect x="{node.x - 62:.1f}" y="{node.y - 20:.1f}" width="124" height="40" rx="8" '
                       f'fill="{color}" stroke="#0F172A" stroke-width="1"/>')
            fill = "#FFFFFF"
        elif node.kind == "lan":
            out.append(f'<ellipse cx="{node.x:.1f}" cy="{node.y:.1f}" rx="62" ry="18" fill="#E2E8F0" '
                       f'stroke="#64748B"/>')
            fill = "#0F172A"
        else:
            out.append(f'<rect x="{node.x - 56:.1f}" y="{node.y - 20:.1f}" width="112" height="40" rx="20" '
                       f'fill="#F5F3FF" stroke="#7C3AED" stroke-dasharray="4,3"/>')
            fill = "#4C1D95"
        start = node.y - (len(lines) - 1) * 6 + 4
        for i, text in enumerate(lines):
            out.append(f'<text x="{node.x:.1f}" y="{start + i * 12:.1f}" font-size="11" font-weight="600" '
                       f'fill="{fill}" text-anchor="middle">{escape(text)}</text>')
    out.append("</svg>")
    return "\n".join(out)


def to_drawio(topo: Topology) -> str:
    """diagrams.net / draw.io file, editable after export."""
    ids = {name: f"n{i}" for i, name in enumerate(topo.nodes, start=2)}
    cells = ['<mxCell id="0"/>', '<mxCell id="1" parent="0"/>']
    for name, node in topo.nodes.items():
        label = escape(node.label.replace("\n", "<br>"), {'"': "&quot;"})
        if node.kind == "router":
            color = VENDOR_COLORS.get(node.vendor, VENDOR_COLORS[""])
            style = f"rounded=1;whiteSpace=wrap;html=1;fillColor={color};fontColor=#FFFFFF;strokeColor=#0F172A;fontStyle=1;"
        elif node.kind == "lan":
            style = "ellipse;whiteSpace=wrap;html=1;fillColor=#E2E8F0;strokeColor=#64748B;"
        else:
            style = "rounded=1;arcSize=50;whiteSpace=wrap;html=1;dashed=1;fillColor=#F5F3FF;strokeColor=#7C3AED;"
        cells.append(f'<mxCell id="{ids[name]}" value="{label}" style="{style}" vertex="1" parent="1">'
                     f'<mxGeometry x="{node.x - 62:.0f}" y="{node.y - 20:.0f}" width="124" height="40" '
                     f'as="geometry"/></mxCell>')
    for i, lk in enumerate(topo.links):
        color, dash = LINK_STYLE[lk.kind]
        style = f"endArrow=none;html=1;strokeColor={color};strokeWidth=2;" + ("dashed=1;" if dash else "")
        eid = f"e{i}"
        cells.append(f'<mxCell id="{eid}" value="{escape(lk.label, {chr(34): "&quot;"})}" style="{style}" edge="1" '
                     f'parent="1" source="{ids[lk.a]}" target="{ids[lk.b]}"><mxGeometry relative="1" '
                     f'as="geometry"/></mxCell>')
        for pos, text in ((-0.6, " ".join(filter(None, (lk.a_if, lk.a_ip)))),
                          (0.6, " ".join(filter(None, (lk.b_if, lk.b_ip))))):
            if text and lk.kind != "bgp":
                cells.append(f'<mxCell id="{eid}l{"a" if pos < 0 else "b"}" value="{escape(text)}" '
                             f'style="edgeLabel;html=1;align=center;verticalAlign=middle;fontSize=9;" '
                             f'vertex="1" connectable="0" parent="{eid}"><mxGeometry x="{pos}" relative="1" '
                             f'as="geometry"><mxPoint as="offset"/></mxGeometry></mxCell>')
    return ('<mxfile host="NetManage"><diagram name="Topology"><mxGraphModel dx="1200" dy="800" grid="1" '
            'gridSize="10" page="0"><root>' + "".join(cells) + "</root></mxGraphModel></diagram></mxfile>")
