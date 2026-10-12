"""
GPO module — list Group Policy Objects.
"""

from modules.base import BaseModule, ScanContext
from core.output import C
from utils.ldap_helpers import get_attr, get_list

_GPO_FILTER  = "(objectClass=groupPolicyContainer)"
_ATTRS = [
    "displayName", "gPCFileSysPath", "distinguishedName",
    "flags", "whenCreated", "whenChanged",
]

# Known dangerous GPO names (case-insensitive partial match)
_INTERESTING = [
    "default domain policy",
    "default domain controller",
    "password", "bitlocker", "applocker",
    "screensaver", "logon", "startup", "shutdown",
    "software install", "laps",
]


def _is_interesting(name: str) -> bool:
    n = name.lower()
    return any(kw in n for kw in _INTERESTING)


class GPOModule(BaseModule):
    name        = "gpo"
    description = "Group Policy Object enumeration"

    def run(self, ctx: ScanContext) -> None:
        out = ctx.out
        out.section("GROUP POLICY OBJECTS")

        entries = ctx.conn.search(_GPO_FILTER, _ATTRS)
        if not entries:
            out.warning("No GPOs found (check permissions)")
            return

        gpos = []
        for entry in entries:
            name    = get_attr(entry, "displayName")
            path    = get_attr(entry, "gPCFileSysPath")
            dn      = get_attr(entry, "distinguishedName")
            changed = get_attr(entry, "whenChanged")
            flags   = get_attr(entry, "flags")

            status = ""
            try:
                f = int(flags)
                if f == 1:   status = "User config disabled"
                elif f == 2: status = "Computer config disabled"
                elif f == 3: status = "All settings disabled"
            except (ValueError, TypeError):
                pass

            gpos.append({
                "name":    name,
                "path":    path,
                "dn":      dn,
                "changed": str(changed),
                "status":  status,
                "notable": _is_interesting(name),
            })

        out.counter("GPOs", len(gpos), {
            "notable": sum(1 for g in gpos if g["notable"]),
        })

        # Notable GPOs first
        notable = [g for g in gpos if g["notable"]]
        if notable:
            out.subsection("Notable GPOs")
            rows = [[g["name"], g["path"], g["status"] or "enabled"] for g in notable]
            out.table(
                ["Name", "Path", "Status"],
                rows,
                highlight_fn=lambda r: C.CYAN,
            )

        # All GPOs (verbose)
        if ctx.out.verbose:
            out.subsection("All GPOs")
            rows = [
                [g["name"], g["changed"], g["status"] or "enabled", g["path"]]
                for g in gpos
            ]
            out.table(["Name", "Last Changed", "Status", "Path"], rows)
