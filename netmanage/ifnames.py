"""Interface name translation between vendors.

Each source name is reduced to a canonical form (kind, speed, numbering, sub-unit)
and re-written with the naming rules of the target vendor.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .model import Device, Interface

FLAT = {"arista_eos": ("Ethernet", 1), "mikrotik_ros": ("ether", 1),
        "fortinet_fortios": ("port", 1), "vyos": ("eth", 0)}

_SPEED = {
    "fastethernet": "fe", "fa": "fe", "fe": "fe",
    "gigabitethernet": "ge", "gi": "ge", "ge": "ge", "gige": "ge", "sfp": "ge",
    "tengigabitethernet": "xe", "te": "xe", "xe": "xe", "xgigabitethernet": "xe",
    "ten-gigabitethernet": "xe", "xge": "xe", "sfp-sfpplus": "xe",
    "twentyfivegige": "25g", "twenty-fivegige": "25g",
    "fortygigabitethernet": "40g", "fortygige": "40g", "fo": "40g", "qsfpplus": "40g",
    "hundredgige": "100g", "hu": "100g",
    "ethernet": "eth", "eth": "eth", "ether": "eth", "et": "eth", "port": "eth", "": "eth",
}

_PREFIX = {
    "cisco_ios": {"fe": "FastEthernet", "ge": "GigabitEthernet", "xe": "TenGigabitEthernet",
                  "25g": "TwentyFiveGigE", "40g": "FortyGigabitEthernet", "100g": "HundredGigE",
                  "eth": "GigabitEthernet"},
    "huawei_vrp": {"fe": "Ethernet", "ge": "GigabitEthernet", "xe": "XGigabitEthernet",
                   "25g": "25GE", "40g": "40GE", "100g": "100GE", "eth": "GigabitEthernet"},
    "h3c_comware": {"fe": "GigabitEthernet", "ge": "GigabitEthernet", "xe": "Ten-GigabitEthernet",
                    "25g": "Twenty-FiveGigE", "40g": "FortyGigE", "100g": "HundredGigE",
                    "eth": "GigabitEthernet"},
    "juniper_junos": {"fe": "fe-", "ge": "ge-", "xe": "xe-", "25g": "et-", "40g": "et-",
                      "100g": "et-", "eth": "ge-"},
    "nokia_sros": {},
    "aruba_aoscx": {},
}

_NAMES = {  # kind -> vendor -> format
    "loopback": {"cisco_ios": "Loopback{n}", "arista_eos": "Loopback{n}", "huawei_vrp": "LoopBack{n}",
                 "h3c_comware": "LoopBack{n}", "juniper_junos": "lo0.{n}", "mikrotik_ros": "loopback{n}",
                 "fortinet_fortios": "loopback{n}", "nokia_sros": "loopback{n}", "vyos": "dum{n}",
                 "aruba_aoscx": "loopback{n}"},
    "vlan": {"cisco_ios": "Vlan{n}", "arista_eos": "Vlan{n}", "huawei_vrp": "Vlanif{n}",
             "h3c_comware": "Vlan-interface{n}", "juniper_junos": "irb.{n}", "mikrotik_ros": "vlan{n}",
             "fortinet_fortios": "vlan{n}", "nokia_sros": "vlan{n}", "vyos": "br0.{n}",
             "aruba_aoscx": "vlan{n}"},
    "lag": {"cisco_ios": "Port-channel{n}", "arista_eos": "Port-Channel{n}", "huawei_vrp": "Eth-Trunk{n}",
            "h3c_comware": "Route-Aggregation{n}", "juniper_junos": "ae{n}", "mikrotik_ros": "bonding{n}",
            "fortinet_fortios": "agg{n}", "nokia_sros": "lag-{n}", "vyos": "bond{n}",
            "aruba_aoscx": "lag{n}"},
    "tunnel": {"cisco_ios": "Tunnel{n}", "arista_eos": "Tunnel{n}", "huawei_vrp": "Tunnel0/0/{n}",
               "h3c_comware": "Tunnel{n}", "juniper_junos": "gr-0/0/0.{n}", "mikrotik_ros": "gre-tunnel{n}",
               "fortinet_fortios": "tunnel{n}", "nokia_sros": "tunnel{n}", "vyos": "tun{n}",
               "aruba_aoscx": "tunnel{n}"},
    "mgmt": {"cisco_ios": "GigabitEthernet0", "arista_eos": "Management1", "huawei_vrp": "MEth0/0/1",
             "h3c_comware": "M-GigabitEthernet0/0/0", "juniper_junos": "fxp0",
             "fortinet_fortios": "mgmt", "aruba_aoscx": "mgmt"},
    "bridge": {"mikrotik_ros": "bridge{n}", "vyos": "br{n}"},
}


@dataclass(frozen=True)
class Canon:
    kind: str
    speed: str = ""
    nums: str = ""  # "0/0/1"; "" when unknown
    num: str = ""  # number of a logical interface (loopback 0, vlan 10)
    sub: str = ""


def _tail(text: str) -> str:
    m = re.search(r"(\d+)$", text)
    return m.group(1) if m else ""


def canon(itf: Interface, vendor: str) -> Canon:
    name = itf.name
    base, _, sub = name.partition(".")
    if not sub.isdigit():
        base, sub = name, ""
    low = base.lower()
    kind = itf.kind
    if kind == "loopback":
        if vendor == "juniper_junos":
            return Canon("loopback", num=sub or "0")
        return Canon("loopback", num="0" if low in ("system", "lo") else _tail(base))
    if kind == "vlan":
        num = sub if (vendor == "juniper_junos" or re.match(r"^br\d+$", low)) and sub else _tail(name)
        return Canon("vlan", num=num)
    if kind == "tunnel":
        return Canon("tunnel", num=sub if vendor == "juniper_junos" and sub else _tail(base))
    if kind == "lag":
        return Canon("lag", num=_tail(base), sub=sub)
    if kind in ("null", "mgmt"):
        return Canon(kind)
    if kind == "bridge":
        return Canon("bridge", num=_tail(base), sub=sub)
    m = re.match(r"^(10|25|40|100)ge(\d+(?:/\d+)*)$", low)
    if m:
        speed = {"10": "xe", "25": "25g", "40": "40g", "100": "100g"}[m.group(1)]
        return Canon("physical", speed, m.group(2), sub=sub)
    m = re.match(r"^([a-z\-]*?)[\-\s]?(\d+(?:/\d+)*)$", low)
    if not m or m.group(1) not in _SPEED:
        return Canon("physical", "eth", "", sub=sub)
    speed = _SPEED[m.group(1)]
    if vendor == "juniper_junos" and m.group(1) == "et":
        speed = "100g"
    return Canon("physical", speed, m.group(2), sub=sub)


def _natural(text: str) -> list:
    return [int(p) if p.isdigit() else p for p in re.split(r"(\d+)", text)]


def _structured(parts: list[int], dst: str) -> list[int]:
    if dst == "cisco_ios":
        return parts if len(parts) >= 2 else [0] + parts
    if dst in ("huawei_vrp", "juniper_junos"):
        return ([0, 0, 0] + parts)[-3:] if len(parts) < 3 else parts[-3:]
    lead = [1, 0] if dst == "h3c_comware" else [1, 1]
    if len(parts) == 1:
        return lead + parts
    if len(parts) == 2:
        return [1] + parts
    return parts[-3:]


class NameMap:
    """Callable source-name -> target-name mapper with a report table."""

    def __init__(self, dev: Device, dst: str):
        self.table: dict[str, str] = {}
        self.warnings: list[str] = []
        self._canon: dict[Canon, str] = {}
        self._vendor = dev.vendor
        self._identity = dev.vendor == dst
        if self._identity:
            self.table = {n: n for n in dev.interfaces}
            return
        self._build(dev, dst)

    def __call__(self, name: str) -> str:
        if not name:
            return name
        if name in self.table:
            return self.table[name]
        if name.lower().startswith("null"):
            return "Null0"
        hit = self._canon.get(canon(Interface(name=name), self._vendor))
        return hit or name

    # ------------------------------------------------------------ internals
    def _build(self, dev: Device, dst: str) -> None:
        canons = {name: canon(itf, dev.vendor) for name, itf in dev.interfaces.items()}
        base_names = self._physical(canons, dst)
        used_numbers: dict[str, set[int]] = {}
        for c in canons.values():
            if c.kind != "physical" and c.num.isdigit():
                used_numbers.setdefault(c.kind, set()).add(int(c.num))

        for name, c in canons.items():
            itf = dev.interfaces[name]
            if c.kind == "physical":
                target = base_names[(c.speed, c.nums, "" if c.nums else name.partition(".")[0])]
            elif c.kind == "null":
                target = "Null0"
            elif c.kind in _NAMES and dst in _NAMES[c.kind]:
                n = c.num
                if not n.isdigit():
                    pool = used_numbers.setdefault(c.kind, set())
                    n = str(next(i for i in range(0 if c.kind == "loopback" else 1, 4096) if i not in pool))
                    pool.add(int(n))
                target = _NAMES[c.kind][dst].format(n=n)
                if c.kind == "loopback" and dst == "nokia_sros" and n == "0":
                    target = "system"
                if c.kind == "lag" and dst == "h3c_comware" and not itf.ipv4 and itf.mode:
                    target = f"Bridge-Aggregation{n}"
                if c.kind == "tunnel":
                    self.warnings.append(f"Tunnel {name}: parameter tunnel (source/destination/mode) "
                                         f"tidak dikonversi, lengkapi manual.")
            else:
                target = base_names.get(("x", "", name), name)
                if target == name:
                    self.warnings.append(f"Interface {name} ({c.kind}) tidak punya padanan di vendor "
                                         f"tujuan, nama dipertahankan.")
            if c.sub and c.kind in ("physical", "lag", "bridge"):
                target = f"{target}.{c.sub}"
            self.table[name] = target
            self._canon.setdefault(c, target)

    def _physical(self, canons: dict[str, Canon], dst: str) -> dict[tuple, str]:
        """(speed, nums, fallback-name) -> target base name for every physical port."""
        # mgmt ports without a native name are numbered like unknown physical ports
        for name, c in canons.items():
            if c.kind == "mgmt" and dst not in _NAMES["mgmt"]:
                canons[name] = Canon("physical", "eth", "")
        keys: list[tuple] = []
        for name, c in canons.items():
            if c.kind == "physical":
                key = (c.speed, c.nums, "" if c.nums else name.partition(".")[0])
                if key not in keys:
                    keys.append(key)
        known = sorted((k for k in keys if k[1]), key=lambda k: (_natural(k[1]), k[0]))
        unknown = [k for k in keys if not k[1]]
        if unknown:
            self.warnings.append("Port tanpa nomor baku dinomori ulang: "
                                 + ", ".join(k[2] for k in unknown))
        result: dict[tuple, str] = {}

        if dst in FLAT:
            prefix, base = FLAT[dst]
            singles = [int(k[1]) for k in known if "/" not in k[1]]
            keep = known and len(singles) == len(known) and len(set(singles)) == len(singles)
            if keep:
                shift = 0
                if base == 1 and min(singles) == 0:
                    shift = 1
                elif base == 0 and self._vendor in FLAT and FLAT[self._vendor][1] == 1 and min(singles) >= 1:
                    shift = -1
                for k in known:
                    result[k] = f"{prefix}{int(k[1]) + shift}"
                nxt = max(singles) + shift + 1
            else:
                nxt = base
                for k in known:
                    result[k] = f"{prefix}{nxt}"
                    nxt += 1
            for k in unknown:
                result[k] = f"{prefix}{nxt}"
                nxt += 1
            return result

        last = max((int(k[1].split("/")[-1]) for k in known), default=0)
        numbered = [(k, [int(x) for x in k[1].split("/")]) for k in known]
        for i, k in enumerate(unknown, start=1):
            numbered.append((k, [last + i]))
        shaped = [(k, _structured(parts, dst)) for k, parts in numbered]
        if dst in ("nokia_sros", "aruba_aoscx", "h3c_comware"):
            positions = (0,) if dst == "h3c_comware" else (0, 1, 2)
            for pos in positions:
                if any(len(p) > pos and p[pos] == 0 for _, p in shaped):
                    for _, p in shaped:
                        if len(p) > pos:
                            p[pos] += 1
        prefixes = _PREFIX[dst]
        for k, parts in shaped:
            result[k] = prefixes.get(k[0], "") + "/".join(str(x) for x in parts)
        if len(set(result.values())) != len(result):  # collision -> renumber everything
            lead = "1/1/" if dst in ("nokia_sros", "aruba_aoscx") else "1/0/" if dst == "h3c_comware" else "0/0/"
            if dst == "cisco_ios":
                lead = "0/"
            for i, (k, _) in enumerate(shaped, start=1):
                result[k] = prefixes.get(k[0], "") + f"{lead}{i}"
            self.warnings.append("Nomor port bentrok setelah konversi, semua port dinomori ulang "
                                 "berurutan. Periksa tabel mapping interface.")
        return result
