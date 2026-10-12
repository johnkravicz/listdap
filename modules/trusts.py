"""
Trusts module — enumerate domain trusts.
"""

from modules.base import BaseModule, ScanContext
from core.output import Severity, C
from utils.ldap_helpers import get_attr, get_int

_TRUST_FILTER = "(objectClass=trustedDomain)"
_ATTRS = [
    "name", "trustPartner", "trustDirection",
    "trustType", "trustAttributes", "whenCreated", "whenChanged",
]

# trustDirection
_DIRECTIONS = {
    0: "Disabled",
    1: "Inbound (partner trusts us)",
    2: "Outbound (we trust partner)",
    3: "Bidirectional",
}

# trustType
_TYPES = {
    1: "Downlevel (Windows NT)",
    2: "Uplevel (Active Directory)",
    3: "MIT Kerberos",
    4: "DCE",
}

# trustAttributes flags
_ATTR_FLAGS = {
    0x00000001: "Non-transitive",
    0x00000002: "Uplevel clients only",
    0x00000004: "Quarantined (SID filtering)",
    0x00000008: "Forest trust",
    0x00000010: "Cross-organization",
    0x00000020: "Within forest",
    0x00000040: "Treat as external",
    0x00000080: "Uses RC4 encryption",
    0x00000200: "Cross-organization no TGT delegation",
    0x00000400: "PIM trust",
}


def _decode_trust_attrs(value: int) -> str:
    parts = [label for flag, label in _ATTR_FLAGS.items() if value & flag]
    return ", ".join(parts) if parts else str(value)


def _is_sid_filtering_disabled(attrs: int) -> bool:
    """SID filtering is disabled when NOT quarantined and NOT within-forest."""
    quarantined    = bool(attrs & 0x00000004)
    within_forest  = bool(attrs & 0x00000020)
    return not quarantined and not within_forest


class TrustsModule(BaseModule):
    name        = "trusts"
    description = "Domain trust enumeration"

    def run(self, ctx: ScanContext) -> None:
        out = ctx.out
        out.section("DOMAIN TRUSTS")

        entries = ctx.conn.search(_TRUST_FILTER, _ATTRS)
        if not entries:
            out.info("No trusts found")
            return

        trusts = []
        for entry in entries:
            name       = get_attr(entry, "name")
            partner    = get_attr(entry, "trustPartner")
            direction  = get_int(entry, "trustDirection")
            ttype      = get_int(entry, "trustType")
            attrs      = get_int(entry, "trustAttributes")
            created    = get_attr(entry, "whenCreated")

            trusts.append({
                "name":      name or partner,
                "partner":   partner,
                "direction": direction,
                "type":      ttype,
                "attrs":     attrs,
                "created":   str(created),
            })

        out.counter("Trusts", len(trusts))

        rows = []
        for t in trusts:
            dir_str  = _DIRECTIONS.get(t["direction"], str(t["direction"]))
            type_str = _TYPES.get(t["type"], str(t["type"]))
            attr_str = _decode_trust_attrs(t["attrs"])
            rows.append([t["name"], dir_str, type_str, attr_str])

        out.table(
            ["Trust Partner", "Direction", "Type", "Attributes"],
            rows,
            highlight_fn=lambda r: C.YELLOW if "Bidirectional" in r[1] or "Forest trust" in r[3] else None,
        )

        # SID filtering checks
        for t in trusts:
            if t["direction"] in (2, 3):  # outbound or bidirectional
                if _is_sid_filtering_disabled(t["attrs"]):
                    ctx.quick_wins.add(
                        Severity.HIGH,
                        f"SID Filtering potentially disabled on trust with {t['name']}",
                        "If SID filtering is not enforced, a compromised trusted domain can forge\n"
                        "SIDs of privileged groups in this domain (SID history attack).",
                    )

        # Forest trusts are high-value
        forest_trusts = [t for t in trusts if t["attrs"] & 0x00000008]
        if forest_trusts:
            ctx.quick_wins.add(
                Severity.INFO,
                f"{len(forest_trusts)} forest trust(s) detected",
                "Forest trusts can be pivoting paths. Check for golden ticket / SID history exploitation.",
            )
