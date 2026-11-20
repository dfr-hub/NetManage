"""IOS-style parser: Cisco IOS / IOS-XE, Arista EOS, Aruba AOS-CX."""
from __future__ import annotations

import re

from ..model import Device, OspfNetwork, StaticRoute, is_ipv4, net_of, to_cidr, wildcard_to_prefix
from . import ios_policy
from .common import blocks, clean_lines

_IGNORE = re.compile(
    r"^(version |service |boot[- ]|no service|no ip |ip cef|ip subnet-zero|ip classless|"
    r"line |end$|building configuration|current configuration|last configuration|"
    r"spanning-tree |aaa |enable |control-plane|multilink |redundancy|license |"
    r"platform |subscriber |diagnostic |memory |call-home|crypto pki|no aaa|"
    r"ip forward-protocol|ip http|no ip http|login |archive|banner |vtp |"
    r"voice-card|mmi |ip ssh|transport |exec-timeout|password |logging buffered|"
    r"logging console|no logging|clock |errdisable |ip domain[- ]lookup|ip tcp |ip scp|"
    r"no |ssh server|https-server|vrf (instance|definition) |vrf \S+$|ip routing|management |"
    r"daemon |transceiver |system |module |led |mirror |qos |"
    r"router-id |ip virtual-router|mlag |peer-group |ntp enable)",
    re.I,
)

_IF_IGNORE = re.compile(
    r"(no ip address|no ip redirects|no ip proxy-arp|duplex|speed|negotiation|"
    r"switchport$|no switchport|switchport trunk encapsulation|spanning-tree|"
    r"load-interval|no cdp|cdp |no keepalive|media-type|no mop|no ip unreachables|"
    r"no routing|routing$|lag \d|channel-group|lacp |vlan trunk native|no lldp|lldp |"
    r"ip ospf network|no ip ospf passive|mlag |active-gateway)"
)


def parse(text: str, vendor: str = "cisco_ios") -> Device:
    dev = Device(vendor=vendor)
    for head, body in blocks(clean_lines(text, comment_prefixes=("!",))):
        try:
            if not _top(dev, head, head.lower(), body) and not _IGNORE.match(head):
                dev.unparsed.append(head)
                dev.unparsed.extend("  " + b for b in body)
        except (ValueError, IndexError, StopIteration):
            dev.unparsed.append(head)
    return dev


def _top(dev: Device, head: str, low: str, body: list[str]) -> bool:
    w = head.split()
    if low.startswith("hostname "):
        dev.hostname = w[1]
    elif re.match(r"(ip domain[- ]name|dns domain|ip dns domain-name) ", low):
        dev.domain = w[-1]
    elif re.match(r"(ip name-server|ip dns server-address) ", low):
        dev.dns += [x for x in w[2:] if is_ipv4(x)]
    elif low.startswith("ntp server "):
        dev.ntp.append(next((x for x in w[2:] if is_ipv4(x)), w[2]))
    elif re.match(r"logging (host )?\d+\.\d+\.\d+\.\d+", low):
        dev.syslog.append(next(x for x in w if is_ipv4(x)))
    elif low.startswith("snmp-server community "):
        dev.snmp_communities.append((w[2], "rw" if "rw" in [x.lower() for x in w[3:]] else "ro"))
    elif low.startswith(("snmp-server location ", "snmp-server system-location ")):
        dev.snmp_location = head.split(None, 2)[2]
    elif low.startswith(("snmp-server contact ", "snmp-server system-contact ")):
        dev.snmp_contact = head.split(None, 2)[2]
    elif low.startswith(("username ", "user ")):
        if w[1] not in dev.users:
            dev.users.append(w[1])
    elif re.match(r"vlan \d+$", low):
        name = next((b.split(None, 1)[1] for b in body if b.lower().startswith("name ")), "")
        dev.vlans[int(w[1])] = name
    elif re.match(r"vlan [\d,\-]+$", low):
        for vid in _expand(w[1]):
            dev.vlans.setdefault(vid, "")
    elif low.startswith("interface "):
        _interface(dev, head.split(None, 1)[1], body)
    elif low.startswith("ip route "):
        _route(dev, w[2:])
    elif low.startswith("router ospf "):
        _ospf(dev, w, body)
    elif low.startswith("router bgp "):
        _bgp(dev, w, body)
    elif ios_policy.handle_top(dev, head, low, body):
        pass
    else:
        return False
    return True


def _expand(spec: str) -> list[int]:
    out: list[int] = []
    for part in spec.split(","):
        if "-" in part:
            a, b = part.split("-")
            out += list(range(int(a), int(b) + 1))
        elif part.isdigit():
            out.append(int(part))
    return out


def _interface(dev: Device, name: str, body: list[str]) -> None:
    itf = dev.iface(name.replace(" ", ""))
    for line in body:
        w = line.split()
        low = line.lower()
        if low.startswith("description "):
            itf.description = line.split(None, 1)[1]
        elif re.match(r"ip address \d", low):
            cidr = w[2] if "/" in w[2] else to_cidr(w[2], w[3])
            if "secondary" in low:
                itf.ipv4.append(cidr)
            else:
                itf.ipv4.insert(0, cidr)
        elif low == "shutdown":
            itf.shutdown = True
        elif low == "no shutdown":
            itf.shutdown = False
        elif re.match(r"(ip )?mtu \d+", low):
            itf.mtu = int(w[-1])
        elif re.match(r"((ip )?vrf forwarding|vrf member|vrf attach|vrf) \S+$", low):
            itf.vrf = w[-1]
        elif low.startswith("vlan access "):
            itf.mode, itf.access_vlan = "access", int(w[2])
        elif low.startswith("vlan trunk allowed "):
            itf.mode = "trunk"
            itf.trunk_vlans = "" if w[3] == "all" else w[3]
        elif low == "ip ospf passive":
            dev.get_ospf().passive.append(itf.name)
        elif low.startswith("encapsulation dot1q "):
            itf.dot1q = int(w[-1])
        elif low == "switchport mode access":
            itf.mode = "access"
        elif low == "switchport mode trunk":
            itf.mode = "trunk"
        elif low.startswith("switchport access vlan "):
            itf.access_vlan = int(w[3])
            itf.mode = itf.mode or "access"
        elif low.startswith("switchport trunk allowed vlan "):
            vl = w[-1]
            itf.trunk_vlans = f"{itf.trunk_vlans},{vl}" if " add " in low and itf.trunk_vlans else vl
        elif re.match(r"ip ospf (\S+ )?area ", low):
            itf.ospf_area = w[-1]
        elif low.startswith("ip ospf cost "):
            itf.ospf_cost = int(w[-1])
        elif ios_policy.handle_interface(dev, itf, low, w):
            pass
        elif _IF_IGNORE.match(low):
            pass
        else:
            dev.unparsed.append(f"interface {name}: {line}")


def _route(dev: Device, w: list[str]) -> None:
    vrf = ""
    if w[0].lower() == "vrf":
        vrf, w = w[1], w[2:]
    if "/" in w[0]:
        r, rest = StaticRoute(prefix=net_of(*w[0].split("/")), vrf=vrf), w[1:]
    else:
        r, rest = StaticRoute(prefix=net_of(w[0], w[1]), vrf=vrf), w[2:]
    i = 0
    while i < len(rest):
        tok = rest[i]
        if is_ipv4(tok):
            r.nexthop = tok
        elif tok.isdigit():
            r.distance = int(tok)
        elif tok.lower() == "name" and i + 1 < len(rest):
            r.description = rest[i + 1]
            i += 1
        elif tok.lower() == "vrf" and i + 1 < len(rest):
            r.vrf = rest[i + 1]
            i += 1
        elif tok.lower() == "distance" and i + 1 < len(rest):
            r.distance = int(rest[i + 1])
            i += 1
        elif tok.lower() in ("tag", "track", "metric") and i + 1 < len(rest):
            i += 1
        elif tok.lower() != "permanent":
            r.interface = tok
        i += 1
    dev.static_routes.append(r)


def _ospf(dev: Device, w: list[str], body: list[str]) -> None:
    ospf = dev.get_ospf()
    ospf.process = w[2]
    for line in body:
        t = line.split()
        low = line.lower()
        if low.startswith("router-id "):
            ospf.router_id = t[1]
        elif low.startswith("network ") and " area " in low and "/" in t[1]:
            ospf.networks.append(OspfNetwork(net_of(*t[1].split("/")), t[3]))
        elif low.startswith("network ") and " area " in low:
            ospf.networks.append(OspfNetwork(net_of(t[1], str(wildcard_to_prefix(t[2]))), t[4]))
        elif re.match(r"area \S+$", low) or low.startswith("max-lsa"):
            pass
        elif low.startswith("passive-interface "):
            ospf.passive.append(t[1])
        elif low.startswith("redistribute "):
            _redistribute(ospf, t)
        elif low.startswith("default-information originate"):
            ospf.default_originate = True
        elif low.startswith(("log-adjacency", "auto-cost", "no passive")):
            pass
        else:
            dev.unparsed.append(f"router ospf {ospf.process}: {line}")


def _bgp(dev: Device, w: list[str], body: list[str]) -> None:
    bgp = dev.get_bgp()
    bgp.asn = w[2]
    for line in body:
        t = line.split()
        low = line.lower()
        if low.startswith(("bgp router-id ", "router-id ")):
            bgp.router_id = t[-1]
        elif low.startswith("neighbor ") and len(t) >= 3 and is_ipv4(t[1]):
            n = bgp.neighbor(t[1])
            key = t[2].lower()
            if key == "remote-as":
                n.remote_as = t[3]
            elif key == "description":
                n.description = line.split(None, 3)[3]
            elif key == "update-source":
                n.update_source = t[3]
            elif key == "ebgp-multihop":
                n.ebgp_multihop = int(t[3]) if len(t) > 3 else 255
            elif key == "next-hop-self":
                n.next_hop_self = True
            elif key == "shutdown":
                n.shutdown = True
            elif key == "route-map" and len(t) > 4 and t[4].lower() in ("in", "out"):
                setattr(n, f"route_map_{t[4].lower()}", t[3])
            elif key in ("activate", "send-community", "soft-reconfiguration"):
                pass
            else:
                dev.unparsed.append(f"router bgp {bgp.asn}: {line}")
        elif low.startswith("network ") and "/" in t[1]:
            bgp.networks.append(net_of(*t[1].split("/")))
        elif low.startswith("network "):
            mask = t[3] if len(t) > 3 and t[2].lower() == "mask" else _classful(t[1])
            bgp.networks.append(net_of(t[1], mask))
        elif low.startswith("redistribute "):
            _redistribute(bgp, t)
        elif low.startswith(("bgp log-neighbor", "address-family", "exit-address-family",
                             "no synchronization", "no auto-summary", "bgp bestpath")):
            pass
        else:
            dev.unparsed.append(f"router bgp {bgp.asn}: {line}")


def _redistribute(proc, t: list[str]) -> None:
    """'redistribute static subnets route-map RM' keeps the route-map reference."""
    if t[1] not in proc.redistribute:
        proc.redistribute.append(t[1])
    low = [x.lower() for x in t]
    if "route-map" in low:
        proc.redistribute_map[t[1]] = t[low.index("route-map") + 1]


def _classful(ip: str) -> str:
    first = int(ip.split(".")[0])
    return "8" if first < 128 else "16" if first < 192 else "24"
