"""Vendor-neutral model for routing policy, ACL and QoS, plus shared helpers.

Semantics follow Cisco IOS:
  * prefix-list and ACL entries are evaluated top-down, first match wins, implicit deny at end;
  * a route-map entry matches when ALL its match conditions match; implicit deny at end;
  * a QoS policy is an ordered list of (class, actions); unmatched traffic is class-default.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

# ----------------------------------------------------------------- routing policy


@dataclass
class PrefixEntry:
    seq: int
    action: str  # permit | deny
    prefix: str  # "10.0.0.0/8"
    ge: int | None = None
    le: int | None = None

    def range(self) -> tuple[int, int]:
        """Explicit (min, max) prefix length matched by this entry."""
        plen = ipaddress.ip_network(self.prefix, strict=False).prefixlen
        if self.ge is None and self.le is None:
            return plen, plen
        return (self.ge if self.ge is not None else plen), (self.le if self.le is not None else 32)


@dataclass
class PrefixList:
    name: str
    entries: list[PrefixEntry] = field(default_factory=list)

    def add(self, action: str, prefix: str, ge: int | None = None, le: int | None = None,
            seq: int | None = None) -> PrefixEntry:
        net = str(ipaddress.ip_network(prefix, strict=False))
        plen = int(net.split("/")[1])
        lo, hi = ge, le
        if lo is not None and hi is None:
            hi = 32
        if hi is not None and lo is None:
            lo = plen
        if lo == plen and hi == plen:
            lo = hi = None
        e = PrefixEntry(seq if seq is not None else (len(self.entries) + 1) * 5, action, net, lo, hi)
        self.entries.append(e)
        return e


@dataclass
class CommunityList:
    name: str
    entries: list[tuple[str, str]] = field(default_factory=list)  # (permit|deny, "65001:100")


@dataclass
class RouteMapEntry:
    seq: int
    action: str = "permit"  # permit | deny
    match_prefix: list[str] = field(default_factory=list)  # prefix-list names
    match_community: list[str] = field(default_factory=list)  # community-list names
    match_tag: int | None = None
    set_local_pref: int | None = None
    set_med: int | None = None
    set_community: list[str] = field(default_factory=list)
    community_additive: bool = False
    set_next_hop: str = ""
    set_prepend: list[str] = field(default_factory=list)
    set_weight: int | None = None
    set_tag: int | None = None

    @property
    def has_match(self) -> bool:
        return bool(self.match_prefix or self.match_community or self.match_tag is not None)


@dataclass
class RouteMap:
    name: str
    entries: list[RouteMapEntry] = field(default_factory=list)

    def entry(self, seq: int, action: str = "permit") -> RouteMapEntry:
        for e in self.entries:
            if e.seq == seq:
                return e
        e = RouteMapEntry(seq=seq, action=action)
        self.entries.append(e)
        self.entries.sort(key=lambda x: x.seq)
        return e


# ------------------------------------------------------------------------- ACL


@dataclass
class AclEntry:
    seq: int
    action: str = "permit"  # permit | deny | remark
    protocol: str = "ip"  # ip | tcp | udp | icmp | <number>
    src: str = "any"  # "any" or CIDR
    src_op: str = ""  # "" | eq | range
    src_ports: list[int] = field(default_factory=list)
    dst: str = "any"
    dst_op: str = ""
    dst_ports: list[int] = field(default_factory=list)
    established: bool = False
    log: bool = False
    remark: str = ""


@dataclass
class Acl:
    name: str
    kind: str = "extended"  # standard | extended
    entries: list[AclEntry] = field(default_factory=list)

    def rules(self) -> list[AclEntry]:
        return [e for e in self.entries if e.action != "remark"]

    def next_seq(self) -> int:
        return (max((e.seq for e in self.entries), default=0) // 10 + 1) * 10


@dataclass
class AclBinding:
    acl: str
    interface: str
    direction: str  # in | out


# ------------------------------------------------------------------------- QoS


@dataclass
class QosClass:
    name: str
    match_dscp: list[int] = field(default_factory=list)
    match_acl: str = ""
    match_any: bool = False


@dataclass
class QosAction:
    cls: str  # class name, "class-default" for unmatched traffic
    set_dscp: int | None = None
    police_kbps: int | None = None
    shape_kbps: int | None = None
    bandwidth_kbps: int | None = None
    bandwidth_pct: int | None = None
    priority: bool = False
    priority_kbps: int | None = None


@dataclass
class QosPolicy:
    name: str
    actions: list[QosAction] = field(default_factory=list)

    def action(self, cls: str) -> QosAction:
        for a in self.actions:
            if a.cls == cls:
                return a
        a = QosAction(cls=cls)
        self.actions.append(a)
        return a


@dataclass
class QosBinding:
    policy: str
    interface: str
    direction: str  # in | out


@dataclass
class Policies:
    prefix_lists: dict[str, PrefixList] = field(default_factory=dict)
    community_lists: dict[str, CommunityList] = field(default_factory=dict)
    route_maps: dict[str, RouteMap] = field(default_factory=dict)
    acls: dict[str, Acl] = field(default_factory=dict)
    acl_bindings: list[AclBinding] = field(default_factory=list)
    qos_classes: dict[str, QosClass] = field(default_factory=dict)
    qos_policies: dict[str, QosPolicy] = field(default_factory=dict)
    qos_bindings: list[QosBinding] = field(default_factory=list)

    def prefix_list(self, name: str) -> PrefixList:
        return self.prefix_lists.setdefault(name, PrefixList(name))

    def community_list(self, name: str) -> CommunityList:
        return self.community_lists.setdefault(name, CommunityList(name))

    def route_map(self, name: str) -> RouteMap:
        return self.route_maps.setdefault(name, RouteMap(name))

    def acl(self, name: str, kind: str = "extended") -> Acl:
        if name not in self.acls:
            self.acls[name] = Acl(name, kind)
        return self.acls[name]

    def qos_class(self, name: str) -> QosClass:
        return self.qos_classes.setdefault(name, QosClass(name))

    def qos_policy(self, name: str) -> QosPolicy:
        return self.qos_policies.setdefault(name, QosPolicy(name))

    def bind_acl(self, acl: str, interface: str, direction: str) -> None:
        b = AclBinding(acl, interface, direction)
        if b not in self.acl_bindings:
            self.acl_bindings.append(b)

    def bind_qos(self, policy: str, interface: str, direction: str) -> None:
        b = QosBinding(policy, interface, direction)
        if b not in self.qos_bindings:
            self.qos_bindings.append(b)


# ----------------------------------------------------------------------- tables

PORTS = {
    "ftp-data": 20, "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25, "domain": 53, "dns": 53,
    "tacacs": 49, "bootps": 67, "bootpc": 68, "tftp": 69, "www": 80, "http": 80, "pop3": 110,
    "sunrpc": 111, "ntp": 123, "netbios-ns": 137, "netbios-dgm": 138, "netbios-ss": 139,
    "imap": 143, "snmp": 161, "snmptrap": 162, "snmp-trap": 162, "bgp": 179, "ldap": 389,
    "https": 443, "isakmp": 500, "syslog": 514, "rip": 520, "ldaps": 636, "radius": 1812,
    "radius-acct": 1813, "ms-sql-s": 1433, "mysql": 3306, "rdp": 3389, "ms-wbt-server": 3389,
    "pptp": 1723, "sip": 5060, "kerberos": 88, "lpd": 515, "nntp": 119, "echo": 7, "time": 37,
    "whois": 43, "non500-isakmp": 4500,
}
PROTOCOLS = {"ip": "ip", "ipv4": "ip", "any": "ip", "all": "ip", "tcp": "tcp", "udp": "udp",
             "icmp": "icmp", "1": "icmp", "6": "tcp", "17": "udp", "gre": "47", "47": "47",
             "esp": "50", "50": "50", "ahp": "51", "ah": "51", "51": "51", "ospf": "89", "89": "89",
             "pim": "103", "103": "103", "igmp": "2", "2": "2", "vrrp": "112", "112": "112",
             "0": "ip"}
PROTO_NAMES = {"47": "gre", "50": "esp", "51": "ah", "89": "ospf", "103": "pim", "2": "igmp",
               "112": "vrrp"}
PROTO_NUMBERS = {"tcp": "6", "udp": "17", "icmp": "1"}

DSCP = {"default": 0, "be": 0, "cs0": 0, "cs1": 8, "af11": 10, "af12": 12, "af13": 14, "cs2": 16,
        "af21": 18, "af22": 20, "af23": 22, "cs3": 24, "af31": 26, "af32": 28, "af33": 30,
        "cs4": 32, "af41": 34, "af42": 36, "af43": 38, "cs5": 40, "ef": 46, "cs6": 48, "cs7": 56}
DSCP_NAMES = {v: k for k, v in DSCP.items() if k not in ("be", "cs0")}


def port_num(token: str) -> int:
    token = token.strip().lower()
    if token.isdigit():
        return int(token)
    if token in PORTS:
        return PORTS[token]
    raise ValueError(f"port tidak dikenal: {token}")


def proto(token: str) -> str:
    token = token.strip().lower()
    if token in PROTOCOLS:
        return PROTOCOLS[token]
    if token.isdigit():
        return token
    raise ValueError(f"protokol tidak dikenal: {token}")


def proto_name(p: str) -> str:
    return PROTO_NAMES.get(p, p)


def proto_number(p: str) -> str:
    return PROTO_NUMBERS.get(p, p)


def dscp_value(token: str) -> int:
    token = token.strip().lower()
    if token.isdigit():
        return int(token)
    if token.startswith("0x"):
        return int(token, 16)
    if token in DSCP:
        return DSCP[token]
    raise ValueError(f"DSCP tidak dikenal: {token}")


def dscp_name(value: int) -> str:
    return DSCP_NAMES.get(value, str(value))


def port_ops(op: str, ports: list[int]) -> tuple[str, list[int]]:
    """Normalize gt/lt to range."""
    if op == "gt":
        return "range", [ports[0] + 1, 65535]
    if op == "lt":
        return "range", [0, ports[0] - 1]
    if op == "range" and len(ports) == 2 and ports[0] == ports[1]:
        return "eq", [ports[0]]
    return op, ports


def parse_port_text(text: str) -> tuple[str, list[int]]:
    """'22' -> eq [22]; '1000-2000' -> range."""
    text = text.strip()
    if not text:
        return "", []
    if "-" in text:
        a, b = text.split("-", 1)
        return port_ops("range", [port_num(a), port_num(b)])
    return "eq", [port_num(text)]


def wild_cidr(addr: str, wild: str) -> str:
    """Cisco address + wildcard -> CIDR."""
    inv = ".".join(str(255 - int(o)) for o in wild.split("."))
    return str(ipaddress.ip_network(f"{addr}/{inv}", strict=False))


def cidr_norm(text: str) -> str:
    text = text.strip()
    if text.lower() in ("any", "0.0.0.0/0", "all", ""):
        return "any"
    if "/" not in text:
        text += "/32"
    a, _, m = text.partition("/")
    if "." in m:
        return str(ipaddress.ip_network(f"{a}/{m}", strict=False))
    return str(ipaddress.ip_network(text, strict=False))


def rate_kbps(value: str, unit: str = "") -> int:
    """'10m' / '10','mbps' / '1000000' (bps) -> kbps."""
    text = (str(value) + unit).strip().lower().replace(" ", "")
    m = re.match(r"^(\d+(?:\.\d+)?)([kmg]?)(bit|bps|bits|b)?(/s)?$", text)
    if not m:
        raise ValueError(f"rate tidak dikenal: {value}{unit}")
    mult = {"": 1 / 1000, "k": 1, "m": 1000, "g": 1000000}[m.group(2)]
    return max(1, int(round(float(m.group(1)) * mult)))


def kbps_text(kbps: int) -> str:
    if kbps % 1000000 == 0:
        return f"{kbps // 1000000}g"
    if kbps % 1000 == 0:
        return f"{kbps // 1000}m"
    return f"{kbps}k"


def safe_name(name: str, limit: int = 63) -> str:
    return re.sub(r"[^\w\-]", "_", name)[:limit] or "X"
