"""Vendor-neutral configuration model.

Every parser fills a Device. Every generator reads a Device.
Anything a parser does not understand goes to Device.unparsed, so the user
always sees what was NOT converted.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from .policy import Policies

VENDORS = {
    "cisco_ios": "Cisco IOS / IOS-XE",
    "juniper_junos": "Juniper Junos",
    "mikrotik_ros": "MikroTik RouterOS",
    "huawei_vrp": "Huawei VRP",
    "fortinet_fortios": "Fortinet FortiOS",
    "arista_eos": "Arista EOS",
    "h3c_comware": "H3C Comware",
    "nokia_sros": "Nokia SR OS (classic)",
    "vyos": "VyOS",
    "aruba_aoscx": "Aruba AOS-CX",
}


@dataclass
class Interface:
    name: str
    description: str = ""
    ipv4: list[str] = field(default_factory=list)  # "10.0.0.1/30", first = primary
    shutdown: bool = False
    mtu: int | None = None
    vrf: str = ""
    mode: str = ""  # "", "access", "trunk"
    access_vlan: int | None = None
    trunk_vlans: str = ""  # "10,20,30-40"
    dot1q: int | None = None  # routed sub-interface VLAN tag
    ospf_area: str = ""  # set when OSPF is enabled directly on the interface
    ospf_cost: int | None = None
    kind_hint: str = ""  # set by a parser when the name alone does not tell the kind

    @property
    def kind(self) -> str:
        return self.kind_hint or classify_interface(self.name)

    @property
    def is_loopback(self) -> bool:
        return self.kind == "loopback"


@dataclass
class StaticRoute:
    prefix: str  # "0.0.0.0/0"
    nexthop: str = ""
    interface: str = ""
    distance: int | None = None
    vrf: str = ""
    description: str = ""


@dataclass
class OspfNetwork:
    prefix: str  # "10.0.0.0/30"
    area: str  # "0" or "0.0.0.1"


@dataclass
class Ospf:
    process: str = "1"
    router_id: str = ""
    networks: list[OspfNetwork] = field(default_factory=list)
    passive: list[str] = field(default_factory=list)
    redistribute: list[str] = field(default_factory=list)
    redistribute_map: dict[str, str] = field(default_factory=dict)  # protocol -> route-map
    default_originate: bool = False


@dataclass
class BgpNeighbor:
    ip: str
    remote_as: str = ""
    description: str = ""
    update_source: str = ""
    ebgp_multihop: int | None = None
    next_hop_self: bool = False
    shutdown: bool = False
    route_map_in: str = ""
    route_map_out: str = ""


@dataclass
class Bgp:
    asn: str = ""
    router_id: str = ""
    neighbors: list[BgpNeighbor] = field(default_factory=list)
    networks: list[str] = field(default_factory=list)  # prefixes
    redistribute: list[str] = field(default_factory=list)
    redistribute_map: dict[str, str] = field(default_factory=dict)  # protocol -> route-map

    def neighbor(self, ip: str) -> BgpNeighbor:
        for n in self.neighbors:
            if n.ip == ip:
                return n
        n = BgpNeighbor(ip=ip)
        self.neighbors.append(n)
        return n


@dataclass
class Device:
    hostname: str = ""
    vendor: str = ""
    source: str = ""  # file path or label
    domain: str = ""
    interfaces: dict[str, Interface] = field(default_factory=dict)
    vlans: dict[int, str] = field(default_factory=dict)
    static_routes: list[StaticRoute] = field(default_factory=list)
    ospf: Ospf | None = None
    bgp: Bgp | None = None
    dns: list[str] = field(default_factory=list)
    ntp: list[str] = field(default_factory=list)
    syslog: list[str] = field(default_factory=list)
    snmp_communities: list[tuple[str, str]] = field(default_factory=list)  # (name, ro|rw)
    snmp_location: str = ""
    snmp_contact: str = ""
    users: list[str] = field(default_factory=list)
    policy: Policies = field(default_factory=Policies)
    unparsed: list[str] = field(default_factory=list)

    def iface(self, name: str) -> Interface:
        if name not in self.interfaces:
            self.interfaces[name] = Interface(name=name)
        return self.interfaces[name]

    def get_ospf(self) -> Ospf:
        if self.ospf is None:
            self.ospf = Ospf()
        return self.ospf

    def get_bgp(self) -> Bgp:
        if self.bgp is None:
            self.bgp = Bgp()
        return self.bgp

    def ospf_interface_areas(self) -> dict[str, str]:
        """Interface name -> OSPF area, from per-interface config and network statements."""
        result: dict[str, str] = {}
        nets = []
        if self.ospf:
            for n in self.ospf.networks:
                try:
                    nets.append((ipaddress.ip_network(n.prefix, strict=False), n.area))
                except ValueError:
                    continue
            nets.sort(key=lambda x: x[0].prefixlen, reverse=True)
        for itf in self.interfaces.values():
            if itf.ospf_area:
                result[itf.name] = itf.ospf_area
                continue
            for addr in itf.ipv4:
                ip = ipaddress.ip_interface(addr).ip
                hit = next((area for net, area in nets if ip in net), None)
                if hit is not None:
                    result[itf.name] = hit
                    break
        return result

    def ospf_networks_resolved(self) -> list[OspfNetwork]:
        """Network statements for network-based vendors (Cisco, Huawei, MikroTik)."""
        out: list[OspfNetwork] = []
        seen = set()
        if self.ospf:
            for n in self.ospf.networks:
                if (n.prefix, n.area) not in seen:
                    seen.add((n.prefix, n.area))
                    out.append(n)
        covered = []
        for n in out:
            try:
                covered.append(ipaddress.ip_network(n.prefix, strict=False))
            except ValueError:
                pass
        for itf in self.interfaces.values():
            if not itf.ospf_area:
                continue
            for addr in itf.ipv4:
                net = ipaddress.ip_interface(addr).network
                if any(net.subnet_of(c) for c in covered):
                    continue
                key = (str(net), itf.ospf_area)
                if key not in seen:
                    seen.add(key)
                    out.append(OspfNetwork(str(net), itf.ospf_area))
        return out


# ---------------------------------------------------------------- helpers

_KIND_PATTERNS = [
    ("loopback", r"^(lo\d*(\.\d+)?$|loopback|dum\d|system$)"),
    ("vlan", r"^(vlan|vlanif|vlan-interface|irb|bvi)[\s.\-]?\d|^br\d+\.\d+$"),
    ("tunnel", r"^(tunnel|tun\d|gre|gr-|ip-|st0)"),
    ("lag", r"^(port-channel|po\d|eth-trunk|ae\d|bond|bundle-ether|lag[\s\-]?\d|"
            r"bridge-aggregation|route-aggregation)"),
    ("null", r"^(null|dsc|nullroute|blackhole)"),
    ("mgmt", r"^(mgmt|management|meth|m-gigabitethernet|fxp|em\d|me\d|vme)"),
    ("bridge", r"^(bridge|br\d+$)"),
    ("ppp", r"^(dialer|virtual-template|pppoe|pp\d)"),
]


def classify_interface(name: str) -> str:
    low = name.lower()
    for kind, pat in _KIND_PATTERNS:
        if re.search(pat, low):
            return kind
    return "physical"


def split_iface(name: str) -> tuple[str, str, str]:
    """'GigabitEthernet0/0/1.100' -> ('GigabitEthernet', '0/0/1', '100')."""
    m = re.match(r"^([A-Za-z][A-Za-z\-_ ]*?)[\s\-]*(\d[\d/:]*)(?:\.(\d+))?$", name.strip())
    if not m:
        return name, "", ""
    return m.group(1).strip(), m.group(2), m.group(3) or ""


def mask_to_prefix(mask: str) -> int:
    return ipaddress.ip_network(f"0.0.0.0/{mask}").prefixlen


def wildcard_to_prefix(wild: str) -> int:
    inv = ".".join(str(255 - int(o)) for o in wild.split("."))
    return mask_to_prefix(inv)


def prefix_to_mask(prefix: int) -> str:
    return str(ipaddress.ip_network(f"0.0.0.0/{prefix}").netmask)


def prefix_to_wildcard(prefix: int) -> str:
    return str(ipaddress.ip_network(f"0.0.0.0/{prefix}").hostmask)


def to_cidr(ip: str, mask: str) -> str:
    """ip + (dotted mask | prefix length) -> 'ip/len'."""
    mask = mask.strip()
    plen = int(mask) if mask.isdigit() else mask_to_prefix(mask)
    return f"{ip}/{plen}"


def net_of(ip: str, mask: str) -> str:
    return str(ipaddress.ip_network(to_cidr(ip, mask), strict=False))


def split_cidr(cidr: str) -> tuple[str, int]:
    i = ipaddress.ip_interface(cidr)
    return str(i.ip), i.network.prefixlen


def net_parts(prefix: str) -> tuple[str, int]:
    n = ipaddress.ip_network(prefix, strict=False)
    return str(n.network_address), n.prefixlen


def area_dotted(area: str) -> str:
    """'0' -> '0.0.0.0'. Dotted input is returned unchanged."""
    if "." in area:
        return area
    try:
        return str(ipaddress.ip_address(int(area)))
    except ValueError:
        return area


def area_short(area: str) -> str:
    """'0.0.0.0' -> '0'. Used by Cisco style."""
    if "." not in area:
        return area
    try:
        return str(int(ipaddress.ip_address(area)))
    except ValueError:
        return area


def is_ipv4(text: str) -> bool:
    try:
        ipaddress.IPv4Address(text)
        return True
    except ValueError:
        return False
