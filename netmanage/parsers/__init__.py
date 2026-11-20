"""Parser registry and vendor auto-detection."""
from __future__ import annotations

import re
from functools import partial

from ..model import Device
from . import cisco_ios, fortinet_fortios, huawei_vrp, juniper_junos, mikrotik_ros, nokia_sros, vyos

PARSERS = {
    "cisco_ios": partial(cisco_ios.parse, vendor="cisco_ios"),
    "arista_eos": partial(cisco_ios.parse, vendor="arista_eos"),
    "aruba_aoscx": partial(cisco_ios.parse, vendor="aruba_aoscx"),
    "huawei_vrp": partial(huawei_vrp.parse, vendor="huawei_vrp"),
    "h3c_comware": partial(huawei_vrp.parse, vendor="h3c_comware"),
    "juniper_junos": juniper_junos.parse,
    "mikrotik_ros": mikrotik_ros.parse,
    "fortinet_fortios": fortinet_fortios.parse,
    "nokia_sros": nokia_sros.parse,
    "vyos": vyos.parse,
}

_VRP_SHARED = [
    (r"^\s?sysname ", 8),
    (r"^\s?ip route-static ", 3),
    (r"^(ospf|bgp) \d+", 2),
    (r"^\s*port link-type ", 2),
    (r"^\s?(info-center|snmp-agent|ntp-service) ", 2),
]
_IOS_SHARED = [
    (r"^hostname ", 6),
    (r"^ip route ", 3),
    (r"^router (ospf|bgp) ", 3),
    (r"^(snmp-server|ntp server) ", 2),
]

_SIGNATURES = {
    "juniper_junos": [
        (r"^set (routing-options|chassis|security|policy-options) ", 4),
        (r"^set interfaces \S+ unit \d+", 4),
        (r"^set protocols (ospf|bgp) (area \S+ interface|group) ", 4),
        (r"^(system|interfaces|protocols|routing-options) \{", 3),
        (r"^\s*unit \d+ \{", 4),
        (r"family inet", 2),
    ],
    "vyos": [
        (r"^set interfaces (ethernet|loopback|dummy|bonding|bridge|wireguard|pppoe) ", 5),
        (r"^set protocols static ", 4),
        (r"^set service ", 3),
        (r"^set protocols (ospf|bgp) (parameters|neighbor|system-as|interface|\d+ )", 4),
        (r"^\s*ethernet eth\d+ \{", 6),
        (r"^set system (config-management|login user \S+ authentication)", 3),
    ],
    "mikrotik_ros": [
        (r"^/(ip|interface|system|routing|snmp|user|tool)\b", 4),
        (r"^# .* by RouterOS", 12),
        (r"^add .*=", 1),
    ],
    "fortinet_fortios": [
        (r"^config (system|router|firewall|log|vpn|user) ", 4),
        (r"^#config-version=", 12),
        (r"^\s*edit ", 0.5),
        (r"^\s*next$", 0.5),
    ],
    "nokia_sros": [
        (r"^# TiMOS", 12),
        (r"^\s*echo \"", 2),
        (r"^exit all", 6),
        (r"^\s*(static-route-entry|autonomous-system) ", 4),
        (r"^\s*interface \"", 2),
        (r"^\s+port \d+/\d+/\d+", 2),
        (r"^configure$", 4),
    ],
    "huawei_vrp": _VRP_SHARED + [
        (r"^interface (Vlanif|Eth-Trunk|XGigabitEthernet|MEth|GE\d|10GE|40GE|100GE)", 4),
        (r"^\s*port trunk allow-pass ", 4),
        (r"^\s*port default vlan ", 3),
        (r"^user-interface ", 5),
        (r"^vlan batch ", 3),
        (r"^\s*ipv4-family ", 3),
        (r"^\s*undo shutdown", 1),
    ],
    "h3c_comware": _VRP_SHARED + [
        (r"^interface (Vlan-interface|Bridge-Aggregation|Route-Aggregation|Ten-GigabitEthernet|"
         r"M-GigabitEthernet|FortyGigE|HundredGigE)", 5),
        (r"^\s*port link-mode ", 4),
        (r"^\s*port trunk permit ", 4),
        (r"^\s*port access vlan ", 3),
        (r"^local-user \S+ class ", 5),
        (r"^line (vty|aux|class) ", 4),
        (r"^\s*address-family ipv4", 2),
        (r"^ version \d.*Release", 6),
    ],
    "cisco_ios": _IOS_SHARED + [
        (r"^\s*ip address \d+\.\d+\.\d+\.\d+ 255\.", 2),
        (r"^ip route \S+ 255\.|^ip route \S+ 0\.0\.0\.0 ", 3),
        (r"^interface (FastEthernet|GigabitEthernet|TenGigabitEthernet|Serial)\d", 3),
        (r"^(line vty|service timestamps|ip cef|boot-start-marker|version \d+\.\d+$)", 4),
        (r"^\s*network \S+ \d+\.\d+\.\d+\.\d+ area", 3),
        (r"^\s*switchport ", 1),
    ],
    "arista_eos": _IOS_SHARED + [
        (r"^! device: .*EOS", 12),
        (r"^interface (Ethernet\d+(/\d+)*|Management\d+|Port-Channel\d+)$", 3),
        (r"^(vrf instance|management api|daemon |transceiver qsfp|service routing protocols model)", 5),
        (r"^\s*ip address \d+\.\d+\.\d+\.\d+/\d+", 1),
        (r"^ip route \d+\.\d+\.\d+\.\d+/\d+", 2),
        (r"^\s*switchport ", 1),
    ],
    "aruba_aoscx": _IOS_SHARED + [
        (r"^!Version ArubaOS-CX", 12),
        (r"^interface \d+/\d+/\d+", 4),
        (r"^interface (lag|vlan|loopback) \d+", 4),
        (r"^\s*vlan (access|trunk) ", 4),
        (r"^(ssh server vrf|https-server |ip dns server-address)", 4),
        (r"^\s*no routing$", 3),
        (r"^\s*ip address \d+\.\d+\.\d+\.\d+/\d+", 1),
        (r"^ip route \d+\.\d+\.\d+\.\d+/\d+", 2),
    ],
}

_COMPILED = {v: [(re.compile(p, re.I), w) for p, w in sigs] for v, sigs in _SIGNATURES.items()}


def detect(text: str) -> str:
    """Best-guess vendor key for a config text. '' when nothing matches."""
    scores = dict.fromkeys(_COMPILED, 0.0)
    lines = text.replace("\r", "").split("\n")[:5000]
    for vendor, sigs in _COMPILED.items():
        for rx, weight in sigs:
            hits = sum(1 for line in lines if rx.search(line))
            scores[vendor] += weight * min(hits, 10)
    best = max(scores, key=scores.get)
    return best if scores[best] >= 4 else ""


def parse(text: str, vendor: str = "", source: str = "") -> Device:
    vendor = vendor or detect(text)
    if vendor not in PARSERS:
        raise ValueError("Vendor tidak dikenali. Pilih vendor sumber secara manual.")
    dev = PARSERS[vendor](text)
    dev.source = source
    return dev
