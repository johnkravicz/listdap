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

# trustAttributes flags (MS-ADTS 6.1.6.7.9)
TA_NON_TRANSITIVE          = 0x00000001
TA_UPLEVEL_ONLY            = 0x00000002
TA_QUARANTINED_DOMAIN      = 0x00000004   # SID filtering enforced (external trust)
TA_FOREST_TRANSITIVE       = 0x00000008   # forest trust
TA_CROSS_ORGANIZATION      = 0x00000010
TA_WITHIN_FOREST           = 0x00000020
TA_TREAT_AS_EXTERNAL       = 0x00000040
TA_USES_RC4_ENCRYPTION     = 0x00000080
TA_NO_TGT_DELEGATION       = 0x00000200   # TGT delegation across trust disabled (safe)
TA_PIM_TRUST               = 0x00000400
TA_ENABLE_TGT_DELEGATION   = 0x00000800   # TGT delegation enabled (dangerous)

_ATTR_FLAGS = {
    TA_NON_TRANSITIVE:        "Non-transitive",
    TA_UPLEVEL_ONLY:          "Uplevel clients only",
    TA_QUARANTINED_DOMAIN:    "Quarantined (SID filtering)",
    TA_FOREST_TRANSITIVE:     "Forest trust",
    TA_CROSS_ORGANIZATION:    "Cross-organization",
    TA_WITHIN_FOREST:         "Within forest",
    TA_TREAT_AS_EXTERNAL:     "Treat as external",
    TA_USES_RC4_ENCRYPTION:   "Uses RC4 encryption",
    TA_NO_TGT_DELEGATION:     "No TGT delegation",
    TA_PIM_TRUST:             "PIM trust",
    TA_ENABLE_TGT_DELEGATION: "Enable TGT delegation",
}


def _decode_trust_attrs(value: int) -> str:
    parts = [label for flag, label in _ATTR_FLAGS.items() if value & flag]
    known = 0
    for flag in _ATTR_FLAGS:
        known |= flag
    extra = value & ~known
    if extra:
        parts.append(f"0x{extra:x}")
    return ", ".join(parts) if parts else str(value)


def _sid_filtering_off_external(attrs: int) -> bool:
    """For an EXTERNAL trust (not forest, not within-forest), SID filtering is
    governed by the quarantine bit: absent → SID history injection is possible.

    Forest trusts enforce SID filtering by default and expose no positive
    'disabled' bit here, so they are handled separately (not by this check)."""
    if attrs & TA_WITHIN_FOREST or attrs & TA_FOREST_TRANSITIVE:
        return False
    return not bool(attrs & TA_QUARANTINED_DOMAIN)


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

        def _hl(r):
            if "Enable TGT delegation" in r[3]:
                return C.RED
            if "Bidirectional" in r[1] or "Forest trust" in r[3]:
                return C.YELLOW
            return None

        out.table(
            ["Trust Partner", "Direction", "Type", "Attributes"],
            rows,
            highlight_fn=_hl,
        )

        # --- SID filtering (external trusts; inbound exposes THIS domain) ---
        for t in trusts:
            a = t["attrs"]
            # direction 2 (outbound: we trust partner) or 3 (bidirectional):
            # partner's SIDs are honoured here, so a compromised partner can
            # inject privileged SIDs of THIS domain when filtering is off.
            if t["direction"] in (2, 3) and _sid_filtering_off_external(a):
                ctx.quick_wins.add(
                    Severity.HIGH,
                    f"SID filtering disabled on external trust with {t['name']}",
                    "This external trust is not quarantined → SID filtering is OFF. "
                    "A compromised trusted domain can forge SIDs of privileged "
                    "groups in this domain (SID-history injection across the trust).\n"
                    "  # from the trusted side, inject a Domain Admins / Enterprise "
                    "Admins SID of this domain into an inter-realm TGT (mimikatz / "
                    "ticketer.py -extra-sid <this-domain>-519).",
                )

        # --- TGT delegation across the trust (cross-forest unconstrained) ---
        for t in trusts:
            a = t["attrs"]
            if a & TA_ENABLE_TGT_DELEGATION:
                ctx.quick_wins.add(
                    Severity.HIGH,
                    f"TGT delegation ENABLED across trust with {t['name']}",
                    "TRUST_ATTRIBUTE_CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION is set, "
                    "so a TGT can be forwarded across this trust → an unconstrained-"
                    "delegation host in one forest can capture TGTs from the other "
                    "(cross-forest unconstrained delegation / printerbug coercion).",
                )
            elif (a & TA_FOREST_TRANSITIVE) and not (a & TA_NO_TGT_DELEGATION):
                # Forest trust without the explicit NO_TGT_DELEGATION guard — the
                # default flipped to disabled after 2019 patches, but an unpatched
                # or manually-relaxed DC may still forward TGTs. Worth checking.
                ctx.quick_wins.add(
                    Severity.MEDIUM,
                    f"Forest trust with {t['name']} — TGT delegation not explicitly disabled",
                    "Neither ENABLE nor NO_TGT_DELEGATION is set. Modern DCs default "
                    "to disabled, but confirm the DC is patched — if TGT delegation "
                    "is honoured, cross-forest unconstrained-delegation abuse applies.",
                )

        # --- RC4 trust key ---
        for t in trusts:
            if t["attrs"] & TA_USES_RC4_ENCRYPTION:
                ctx.quick_wins.add(
                    Severity.MEDIUM,
                    f"Trust with {t['name']} uses RC4 encryption",
                    "The inter-realm trust key uses RC4 (NT-hash-derived), making a "
                    "forged inter-realm (inter-domain) TGT easier once the trust key "
                    "is dumped (secretsdump of the trust account, then ticketer.py).",
                )

        # --- Forest trusts are high-value pivot paths ---
        forest_trusts = [t for t in trusts if t["attrs"] & TA_FOREST_TRANSITIVE]
        if forest_trusts:
            ctx.quick_wins.add(
                Severity.INFO,
                f"{len(forest_trusts)} forest trust(s) detected",
                "Forest trusts can be pivoting paths. Check for golden/diamond "
                "ticket, SID history and cross-forest delegation exploitation:\n  "
                + ", ".join(t["name"] for t in forest_trusts),
            )
