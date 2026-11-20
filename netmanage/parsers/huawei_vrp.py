"""VRP-style parser: Huawei VRP and H3C Comware."""
from __future__ import annotations

import re

from ..model import Device, OspfNetwork, StaticRoute, is_ipv4, net_of, to_cidr, wildcard_to_prefix
from . import vrp_policy
from .common import vrp_blocks

_IGNORE = re.compile(
    r"^(\[|software version|sysname$|aaa$|user-interface |authentication-|authorization-|"
    r"accounting-|domain |stelnet |ssh |rsa |telnet |undo |http |drop-profile|"
    r"diffserv |clock |header |set cpu|cpu-defend|lldp |stp |info-center (enable|source|timestamp)|"
    r"snmp-agent$|snmp-agent sys-info version|snmp-agent local-engineid|pki |ike |firewall |"
    r"portal |wlan |license|sftp |ftp |ip vpn-instance|device |assign |error-down|"
    r"dns resolve|ntp-service (authentication|source|enable)|load-balance|line |"
    r"irf |password-recovery|scheduler |user-group |role |public-key |ip unreachables|"
    r"ip ttl-expires|system-working-mode|xbar |lldp global|ssh server|version )",
    re.I,
)

_IF_IGNORE = re.compile(
    r"(undo |negotiation|duplex|speed|stp |lldp |arp broadcast enable|port link-type hybrid|"
    r"undo portswitch|portswitch|combo-port|trust |qos |traffic-|device transceiver|flow-control|"
    r"port link-mode|port link-aggregation|eth-trunk \d|ospf network-type)"
)


def vlan_list(tokens: list[str]) -> str:
    """['10', '20', '30', 'to', '40'] -> '10,20,30-40'."""
    out: list[str] = []
    i = 0
    while i < len(tokens):
        if i + 2 < len(tokens) and tokens[i + 1].lower() == "to":
            out.append(f"{tokens[i]}-{tokens[i + 2]}")
            i += 3
        else:
            out.append(tokens[i])
            i += 1
    return ",".join(out)


def _expand(spec: str) -> list[int]:
    out: list[int] = []
    for part in spec.split(","):
        if "-" in part:
            a, b = part.split("-")
            out += list(range(int(a), int(b) + 1))
        elif part.isdigit():
            out.append(int(part))
    return out


def parse(text: str, vendor: str = "huawei_vrp") -> Device:
    dev = Device(vendor=vendor)
    state: dict = {}
    for head, body in vrp_blocks(text):
        try:
            if not _top(dev, head, head.lower(), body) and \
                    not vrp_policy.handle_top(dev, head, head.lower(), body, state) and \
                    not _IGNORE.match(head):
                dev.unparsed.append(head)
                dev.unparsed.extend("  " + b for b in body)
        except (ValueError, IndexError, StopIteration):
            dev.unparsed.append(head)
    vrp_policy.finish(dev, state)
    return dev


def _top(dev: Device, head: str, low: str, body: list[str]) -> bool:
    w = head.split()
    if low.startswith("sysname "):
        dev.hostname = w[1]
    elif low.startswith("dns domain "):
        dev.domain = w[2]
    elif low.startswith("dns server "):
        dev.dns.append(w[2])
    elif low.startswith("ntp-service unicast-server "):
        dev.ntp.append(w[2])
    elif low.startswith("info-center loghost ") and is_ipv4(w[2]):
        dev.syslog.append(w[2])
    elif low.startswith("snmp-agent community "):
        name = next(x for x in w[3:] if x.lower() != "cipher")
        dev.snmp_communities.append((name, "rw" if w[2].lower() == "write" else "ro"))
    elif low.startswith("snmp-agent sys-info location "):
        dev.snmp_location = head.split(None, 3)[3]
    elif low.startswith("snmp-agent sys-info contact "):
        dev.snmp_contact = head.split(None, 3)[3]
    elif low.startswith("local-user "):
        if w[1] not in dev.users:
            dev.users.append(w[1])
    elif low == "aaa":
        for b in body:
            if b.lower().startswith("local-user "):
                user = b.split()[1]
                if user not in dev.users:
                    dev.users.append(user)
    elif low.startswith("vlan batch "):
        for vid in _expand(vlan_list(w[2:])):
            dev.vlans.setdefault(vid, "")
    elif re.match(r"vlan \d+$", low):
        name = next((b.split(None, 1)[1] for b in body
                     if b.lower().startswith(("name ", "description "))), "")
        dev.vlans[int(w[1])] = name
    elif low.startswith("interface "):
        _interface(dev, head.split(None, 1)[1], body)
    elif low.startswith("ip route-static "):
        _route(dev, w[2:])
    elif re.match(r"ospf( \d+)?( |$)", low) and "ospfv3" not in low:
        _ospf(dev, w, body)
    elif re.match(r"bgp \d", low):
        _bgp(dev, w, body)
    else:
        return False
    return True


def _interface(dev: Device, name: str, body: list[str]) -> None:
    itf = dev.iface(name.replace(" ", ""))
    for line in body:
        w = line.split()
        low = line.lower()
        if low.startswith("description "):
            itf.description = line.split(None, 1)[1]
        elif re.match(r"ip address \d", low):
            cidr = to_cidr(w[2], w[3])
            if low.endswith(" sub"):
                itf.ipv4.append(cidr)
            else:
                itf.ipv4.insert(0, cidr)
        elif low == "shutdown":
            itf.shutdown = True
        elif low == "undo shutdown":
            itf.shutdown = False
        elif re.match(r"mtu \d+", low):
            itf.mtu = int(w[1])
        elif low.startswith("ip binding vpn-instance "):
            itf.vrf = w[3]
        elif low.startswith(("dot1q termination vid ", "vlan-type dot1q ")):
            itf.dot1q = int(w[-1])
        elif low == "port link-type access":
            itf.mode = "access"
        elif low == "port link-type trunk":
            itf.mode = "trunk"
        elif low.startswith(("port default vlan ", "port access vlan ")):
            itf.access_vlan = int(w[3])
            itf.mode = itf.mode or "access"
        elif low.startswith(("port trunk allow-pass vlan ", "port trunk permit vlan ")):
            vl = vlan_list(w[4:])
            itf.trunk_vlans = f"{itf.trunk_vlans},{vl}" if itf.trunk_vlans else vl
        elif re.match(r"ospf (enable )?(\d+ )?area ", low):
            itf.ospf_area = w[-1]
        elif low.startswith("ospf cost "):
            itf.ospf_cost = int(w[2])
        elif vrp_policy.handle_interface(dev, itf, low, w):
            pass
        elif _IF_IGNORE.match(low):
            pass
        else:
            dev.unparsed.append(f"interface {name}: {line}")


def _route(dev: Device, w: list[str]) -> None:
    vrf = ""
    if w[0].lower() == "vpn-instance":
        vrf, w = w[1], w[2:]
    r = StaticRoute(prefix=net_of(w[0], w[1]), vrf=vrf)
    rest = w[2:]
    i = 0
    while i < len(rest):
        tok = rest[i]
        low = tok.lower()
        if is_ipv4(tok):
            r.nexthop = tok
        elif low == "preference" and i + 1 < len(rest):
            r.distance = int(rest[i + 1])
            i += 1
        elif low == "description":
            r.description = " ".join(rest[i + 1:])
            break
        elif low in ("tag", "track") and i + 1 < len(rest):
            i += 2 if low == "track" and i + 2 < len(rest) else 1
        elif low != "permanent":
            r.interface = tok
        i += 1
    dev.static_routes.append(r)


def _ospf(dev: Device, w: list[str], body: list[str]) -> None:
    ospf = dev.get_ospf()
    if len(w) > 1 and w[1].isdigit():
        ospf.process = w[1]
    if "router-id" in w:
        ospf.router_id = w[w.index("router-id") + 1]
    area = "0.0.0.0"
    for line in body:
        t = line.split()
        low = line.lower()
        if low.startswith("area "):
            area = t[1]
        elif low.startswith("network "):
            ospf.networks.append(OspfNetwork(net_of(t[1], str(wildcard_to_prefix(t[2]))), area))
        elif low.startswith("silent-interface "):
            ospf.passive.append(t[1])
        elif low.startswith("import-route "):
            _import(ospf, t)
        elif low.startswith("default-route-advertise"):
            ospf.default_originate = True
        elif low.startswith(("bandwidth-reference", "description ")):
            pass
        else:
            dev.unparsed.append(f"ospf {ospf.process}: {line}")


def _bgp(dev: Device, w: list[str], body: list[str]) -> None:
    bgp = dev.get_bgp()
    bgp.asn = w[1]
    for line in body:
        t = line.split()
        low = line.lower()
        if low.startswith("router-id "):
            bgp.router_id = t[1]
        elif low.startswith("peer ") and len(t) >= 3 and is_ipv4(t[1]):
            n = bgp.neighbor(t[1])
            key = t[2].lower()
            if key == "as-number":
                n.remote_as = t[3]
            elif key == "description":
                n.description = line.split(None, 3)[3]
            elif key == "connect-interface":
                n.update_source = t[3]
            elif key == "ebgp-max-hop":
                n.ebgp_multihop = int(t[3]) if len(t) > 3 else 255
            elif key == "next-hop-local":
                n.next_hop_self = True
            elif key == "ignore":
                n.shutdown = True
            elif key == "route-policy" and len(t) > 4 and t[4].lower() in ("import", "export"):
                setattr(n, "route_map_in" if t[4].lower() == "import" else "route_map_out", t[3])
            elif key in ("enable", "advertise-community"):
                pass
            else:
                dev.unparsed.append(f"bgp {bgp.asn}: {line}")
        elif low.startswith("network "):
            bgp.networks.append(net_of(t[1], t[2]) if len(t) > 2 else net_of(t[1], "24"))
        elif low.startswith("import-route "):
            _import(bgp, t)
        elif low.startswith(("ipv4-family", "address-family", "undo ", "graceful-restart")):
            pass
        else:
            dev.unparsed.append(f"bgp {bgp.asn}: {line}")


def _import(proc, t: list[str]) -> None:
    """'import-route static route-policy RP' -> redistribute + route-map reference."""
    p = "connected" if t[1] == "direct" else t[1]
    if p not in proc.redistribute:
        proc.redistribute.append(p)
    low = [x.lower() for x in t]
    if "route-policy" in low:
        proc.redistribute_map[p] = t[low.index("route-policy") + 1]
