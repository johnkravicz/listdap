"""
Shadow Credentials module — enumerate msDS-KeyCredentialLink.
Objects with this attribute set may have been backdoored
or configured for certificate-based RBCD.
"""

from modules.base import BaseModule, ScanContext
from core.output import Severity, C
from utils.ldap_helpers import get_attr, get_int, get_list

_FILTER  = "(msDS-KeyCredentialLink=*)"
_ATTRS   = ["sAMAccountName", "msDS-KeyCredentialLink", "objectClass",
            "userAccountControl", "distinguishedName"]


class ShadowModule(BaseModule):
    name        = "shadow"
    description = "Shadow Credentials (msDS-KeyCredentialLink) enumeration"

    def run(self, ctx: ScanContext) -> None:
        out = ctx.out
        out.section("SHADOW CREDENTIALS")

        entries = ctx.conn.search(_FILTER, _ATTRS)
        if not entries:
            out.success("No objects with msDS-KeyCredentialLink found")
            return

        users     = []
        computers = []

        for entry in entries:
            sam   = get_attr(entry, "sAMAccountName")
            kc    = get_list(entry, "msDS-KeyCredentialLink")
            oc    = get_list(entry, "objectClass")
            dn    = get_attr(entry, "distinguishedName")
            kind  = "Computer" if "computer" in oc else "User"

            obj = {
                "sam":   sam,
                "dn":    dn,
                "count": len(kc),
                "kind":  kind,
            }
            if kind == "Computer":
                computers.append(obj)
            else:
                users.append(obj)

        total = len(users) + len(computers)
        out.counter("Objects with Shadow Credentials", total, {
            "users":     len(users),
            "computers": len(computers),
        })

        if users:
            out.subsection("User Accounts")
            rows = [[u["sam"], str(u["count"]) + " key(s)", u["dn"]] for u in users]
            out.table(["Username", "Key Count", "DN"], rows,
                      highlight_fn=lambda r: C.YELLOW)

        if computers:
            out.subsection("Computer Accounts")
            rows = [[c["sam"], str(c["count"]) + " key(s)", c["dn"]] for c in computers]
            out.table(["Computer", "Key Count", "DN"], rows,
                      highlight_fn=lambda r: C.YELLOW)

        ctx.quick_wins.add(
            Severity.HIGH,
            f"Shadow Credentials on {total} object(s)",
            "msDS-KeyCredentialLink allows certificate-based authentication as the target account.\n"
            "May indicate persistence (backdoor key) or RBCD abuse setup.\n"
            "Investigate with: certipy shadow auto -account <sam>\n"
            "Affected: " + ", ".join(
                o["sam"] for o in users + computers
            ),
        )
