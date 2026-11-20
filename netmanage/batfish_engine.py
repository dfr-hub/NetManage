"""Optional Batfish parsing engine.

Batfish is a separate Java service (default localhost:9996). It parses Cisco, Arista,
Juniper and Fortinet. The other vendors always use the built-in parsers.
Start the service with Docker:  docker run -d -p 9996:9996 batfish/allinone
"""
from __future__ import annotations

import ipaddress
import re
import socket
import tempfile
from pathlib import Path

from .model import Device, OspfNetwork, StaticRoute

SUPPORTED = {"cisco_ios", "arista_eos", "juniper_junos", "fortinet_fortios"}
HOST = "localhost"
PORT = 9996


class BatfishUnavailable(RuntimeError):
    pass


def available(host: str = "", timeout: float = 0.6) -> bool:
    try:
        with socket.create_connection((host or HOST, PORT), timeout=timeout):
            return True
    except OSError:
        return False


def _cell(row, key, default=None):
    try:
        val = row[key]
    except (KeyError, IndexError):
        return default
    if val is None or (isinstance(val, float) and val != val):
        return default
    return val


def _ifname(value) -> str:
    return getattr(value, "interface", None) or str(value).split("[")[-1].rstrip("]")


def parse(text: str, vendor: str, source: str = "", host: str = "") -> Device:
    if vendor not in SUPPORTED:
        raise ValueError(f"Batfish tidak mendukung vendor {vendor}")
    if not available(host):
        raise BatfishUnavailable(
            f"Service Batfish tidak ditemukan di {host or HOST}:{PORT}. "
            "Jalankan: docker run -d -p 9996:9996 batfish/allinone")
    try:
        from pybatfish.client.session import Session
    except ImportError as exc:
        raise BatfishUnavailable("Library pybatfish tidak terpasang.") from exc

    with tempfile.TemporaryDirectory() as tmp:
        cfg_dir = Path(tmp) / "configs"
        cfg_dir.mkdir()
        (cfg_dir / "device.cfg").write_text(text, encoding="utf-8")
        try:
            bf = Session(host=host or HOST)
            bf.set_network("netmanage")
            bf.init_snapshot(tmp, name="convert", overwrite=True)
            return _build(bf, vendor, source)
        except BatfishUnavailable:
            raise
        except Exception as exc:  # noqa: BLE001 - any client/service error falls back
            raise BatfishUnavailable(f"Batfish gagal memproses konfigurasi: {exc}") from exc


def _build(bf, vendor: str, source: str) -> Device:
    dev = Device(vendor=vendor, source=source)

    nodes = bf.q.nodeProperties().answer().frame()
    if len(nodes):
        row = nodes.iloc[0]
        dev.hostname = str(_cell(row, "Hostname", "") or _cell(row, "Node", ""))
        dev.domain = str(_cell(row, "Domain_Name", "") or "")
        dev.dns = [str(x) for x in (_cell(row, "DNS_Servers", []) or [])]
        dev.ntp = [str(x) for x in (_cell(row, "NTP_Servers", []) or [])]
        dev.syslog = [str(x) for x in (_cell(row, "Logging_Servers", []) or [])]

    for _, row in bf.q.interfaceProperties().answer().frame().iterrows():
        name = _ifname(row["Interface"])
        if re.match(r"^(null|unused|dynamic)", name, re.I):
            continue
        if vendor == "juniper_junos" and name.endswith(".0"):
            name = name[:-2]
        itf = dev.iface(name)
        itf.description = str(_cell(row, "Description", "") or "")
        primary = _cell(row, "Primary_Address")
        if primary:
            itf.ipv4.append(str(primary))
        for prefix in _cell(row, "All_Prefixes", []) or []:
            net = ipaddress.ip_network(str(prefix), strict=False)
            if not any(ipaddress.ip_interface(a).network == net for a in itf.ipv4):
                continue
        itf.shutdown = not bool(_cell(row, "Admin_Up", True))
        mtu = _cell(row, "MTU")
        if mtu and int(mtu) not in (1500, 9000, 65535):
            itf.mtu = int(mtu)
        vrf = str(_cell(row, "VRF", "default") or "default")
        itf.vrf = "" if vrf == "default" else vrf
        mode = str(_cell(row, "Switchport_Mode", "NONE") or "NONE").upper()
        if mode == "ACCESS":
            itf.mode = "access"
            vlan = _cell(row, "Access_VLAN")
            itf.access_vlan = int(vlan) if vlan else None
        elif mode == "TRUNK":
            itf.mode = "trunk"
            itf.trunk_vlans = str(_cell(row, "Allowed_VLANs", "") or "")
        encap = _cell(row, "Encapsulation_VLAN")
        if encap:
            itf.dot1q = int(encap)
        area = _cell(row, "OSPF_Area_Name")
        if area is not None and _cell(row, "OSPF_Enabled", False):
            itf.ospf_area = str(area)
            cost = _cell(row, "OSPF_Cost")
            if cost:
                itf.ospf_cost = int(cost)
            if _cell(row, "OSPF_Passive", False):
                dev.get_ospf().passive.append(name)

    ospf = bf.q.ospfProcessConfiguration().answer().frame()
    if len(ospf):
        row = ospf.iloc[0]
        o = dev.get_ospf()
        o.process = str(_cell(row, "Process_ID", "1"))
        o.router_id = str(_cell(row, "Router_ID", "") or "")

    bgp = bf.q.bgpProcessConfiguration().answer().frame()
    if len(bgp):
        dev.get_bgp().router_id = str(_cell(bgp.iloc[0], "Router_ID", "") or "")
    for _, row in bf.q.bgpPeerConfiguration().answer().frame().iterrows():
        remote = _cell(row, "Remote_IP")
        if not remote:
            continue
        b = dev.get_bgp()
        b.asn = str(_cell(row, "Local_AS", b.asn) or b.asn)
        n = b.neighbor(str(remote))
        n.remote_as = str(_cell(row, "Remote_AS", "") or "")
        n.description = str(_cell(row, "Description", "") or "")
        local_if = _cell(row, "Local_Interface")
        if local_if:
            n.update_source = _ifname(local_if)

    routes = bf.q.routes(protocols="static").answer().frame()
    for _, row in routes.iterrows():
        nh_ip = _cell(row, "Next_Hop_IP")
        nh_if = str(_cell(row, "Next_Hop_Interface", "") or "")
        r = StaticRoute(prefix=str(row["Network"]))
        if nh_ip and str(nh_ip) not in ("AUTO/NONE(-1l)", "None"):
            r.nexthop = str(nh_ip)
        elif nh_if.lower().startswith("null"):
            r.interface = "Null0"
        elif nh_if and nh_if != "dynamic":
            r.interface = nh_if
        dist = _cell(row, "Admin_Distance")
        if dist and int(dist) not in (1, 5, 10):
            r.distance = int(dist)
        vrf = str(_cell(row, "VRF", "default") or "default")
        r.vrf = "" if vrf == "default" else vrf
        dev.static_routes.append(r)

    try:
        for _, row in bf.q.parseWarning().answer().frame().iterrows():
            dev.unparsed.append(f"baris {_cell(row, 'Line', '?')}: {_cell(row, 'Text', '')}".strip())
    except Exception:  # noqa: BLE001 - warnings are informational only
        pass
    return dev


__all__ = ["SUPPORTED", "BatfishUnavailable", "available", "parse", "OspfNetwork"]
