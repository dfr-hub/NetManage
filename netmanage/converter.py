"""Config conversion pipeline: text -> parser -> Device -> Jinja2 template -> text."""
from __future__ import annotations

from dataclasses import dataclass, field

from . import parsers
from .i18n import _
from .model import VENDORS, Device
from .render import render


@dataclass
class Result:
    output: str
    device: Device
    src_vendor: str
    dst_vendor: str
    engine: str = "builtin"
    mapping: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    unparsed: list[str] = field(default_factory=list)

    def report(self) -> str:
        d, p = self.device, self.device.policy
        lines = [_("Sumber : {src}  (parser: {engine})").format(src=VENDORS.get(self.src_vendor, self.src_vendor),
                                                               engine=self.engine),
                 _("Tujuan : {dst}").format(dst=VENDORS.get(self.dst_vendor, self.dst_vendor)),
                 _("Device : {dev}").format(dev=d.hostname or "-"), ""]
        lines.append(_("Terkonversi: {ifs} interface, {vlans} VLAN, {routes} static route, OSPF {ospf}, "
                       "BGP {bgp} neighbor").format(ifs=len(d.interfaces), vlans=len(d.vlans),
                                                    routes=len(d.static_routes),
                                                    ospf=_("ya") if d.ospf else _("tidak"),
                                                    bgp=len(d.bgp.neighbors) if d.bgp else 0))
        lines.append(_("Policy     : {rm} route-map, {pl} prefix-list, {cl} community-list, {acl} ACL "
                       "({aclb} terpasang di interface), {qos} QoS policy ({qosb} terpasang)").format(
            rm=len(p.route_maps), pl=len(p.prefix_lists), cl=len(p.community_lists), acl=len(p.acls),
            aclb=len(p.acl_bindings), qos=len(p.qos_policies), qosb=len(p.qos_bindings)))
        changed = {a: b for a, b in self.mapping.items() if a != b}
        if changed:
            lines += ["", _("MAPPING INTERFACE (periksa dan sesuaikan dengan port fisik sebenarnya):")]
            width = max(len(a) for a in changed)
            lines += [f"  {a.ljust(width)}  ->  {b}" for a, b in changed.items()]
        if self.warnings:
            lines += ["", _("PERINGATAN ({count}):").format(count=len(self.warnings))]
            lines += [f"  - {w}" for w in self.warnings]
        if self.unparsed:
            lines += ["", _("TIDAK DIKONVERSI ({count} baris, konversi manual):").format(count=len(self.unparsed))]
            lines += [f"  {u}" for u in self.unparsed]
        return "\n".join(lines)


def parse_config(text: str, vendor: str = "", engine: str = "builtin", source: str = "") -> tuple[Device, str]:
    """Parse with the chosen engine. Returns (device, engine actually used)."""
    vendor = vendor or parsers.detect(text)
    if not vendor:
        raise ValueError("Vendor sumber tidak dikenali. Pilih vendor sumber secara manual.")
    if engine in ("batfish", "auto"):
        from . import batfish_engine
        if vendor in batfish_engine.SUPPORTED:
            try:
                return batfish_engine.parse(text, vendor, source), "batfish"
            except batfish_engine.BatfishUnavailable:
                if engine == "batfish":
                    raise
        elif engine == "batfish":
            raise ValueError(f"Batfish tidak mendukung {VENDORS[vendor]}. Pakai parser bawaan.")
    return parsers.parse(text, vendor, source), "builtin"


def convert(text: str, dst: str, src: str = "", engine: str = "builtin", source: str = "") -> Result:
    if not text.strip():
        raise ValueError("Konfigurasi sumber kosong.")
    dev, used = parse_config(text, src, engine, source)
    output, namemap, warnings = render(dev, dst)
    return Result(output=output, device=dev, src_vendor=dev.vendor, dst_vendor=dst, engine=used,
                  mapping=dict(namemap.table), warnings=warnings, unparsed=list(dev.unparsed))
