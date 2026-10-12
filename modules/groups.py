"""
Groups module — enumerate groups with focus on high-value ones.
"""

from modules.base import BaseModule, ScanContext
from core.output import Severity, C
from utils.ldap_helpers import get_attr, get_int, get_list
from utils.sids import is_high_value_sid

_GROUP_FILTER = "(objectClass=group)"
_ATTRS = [
    "sAMAccountName", "distinguishedName", "description",
    "member", "memberOf", "objectSid", "groupType", "adminCount",
]

# Groups to always highlight (CN partial match, lower)
_HIGH_VALUE_NAMES = [
    "domain admins", "enterprise admins", "schema admins",
    "administrators", "account operators", "backup operators",
    "server operators", "print operators",
    "group policy creator owners", "protected users",
    "key admins", "enterprise key admins",
    "dnsadmins", "dnsupdate proxy",
    "exchange windows permissions", "organization management",
    "remote desktop users", "remote management users",
]


def _is_high_value_name(name: str) -> bool:
    n = name.lower()
    return any(hv in n for hv in _HIGH_VALUE_NAMES)


def _group_type_str(gt: int) -> str:
    """Decode groupType integer to a readable string."""
    if gt == 0:
        return ""
    security  = bool(gt & 0x80000000)
    local     = bool(gt & 0x00000004)
    global_   = bool(gt & 0x00000002)
    universal = bool(gt & 0x00000008)
    scope = "Domain Local" if local else ("Universal" if universal else ("Global" if global_ else "?"))
    kind  = "Security" if security else "Distribution"
    return f"{scope} {kind}"


class GroupsModule(BaseModule):
    name        = "groups"
    description = "Group enumeration with member listing for high-value groups"

    def run(self, ctx: ScanContext) -> None:
        out = ctx.out
        out.section("GROUPS")

        entries = ctx.conn.search(_GROUP_FILTER, _ATTRS)
        if not entries:
            out.warning("No groups found (check permissions)")
            return

        all_groups = []
        high_value = []

        for entry in entries:
            sam     = get_attr(entry, "sAMAccountName")
            members = get_list(entry, "member")
            gt      = get_int(entry, "groupType")
            desc    = get_attr(entry, "description")
            dn      = get_attr(entry, "distinguishedName")

            group = {
                "sam":     sam,
                "dn":      dn,
                "members": members,
                "type":    _group_type_str(gt),
                "desc":    desc,
            }
            all_groups.append(group)

            if _is_high_value_name(sam):
                high_value.append(group)

        out.counter("Groups", len(all_groups), {
            "high-value": len(high_value),
        })

        # --- High-value groups with their members ---
        if high_value:
            out.subsection("High-Value Groups")
            for group in high_value:
                member_count = len(group["members"])
                header = f"{C.YELLOW}{C.BOLD}{group['sam']}{C.RESET}  [{group['type']}]  {member_count} member(s)"
                if group["desc"]:
                    header += f"  — {C.DIM}{group['desc']}{C.RESET}"
                print(f"    {header}")

                if group["members"]:
                    for member_dn in group["members"]:
                        # Extract CN=xxx from DN
                        cn = member_dn.split(",")[0].split("=", 1)[-1]
                        print(f"        {C.CYAN}•{C.RESET} {cn}  {C.GREY}({member_dn}){C.RESET}")

                    # Quick win for DA / EA
                    if member_count > 0 and any(
                        hv in group["sam"].lower()
                        for hv in ["domain admins", "enterprise admins", "schema admins"]
                    ):
                        ctx.quick_wins.add(
                            Severity.INFO,
                            f"{group['sam']}: {member_count} member(s)",
                            "\n".join(
                                m.split(",")[0].split("=", 1)[-1]
                                for m in group["members"]
                            ),
                        )

        # --- All groups summary (verbose) ---
        if ctx.out.verbose:
            out.subsection("All Groups")
            rows = [
                [g["sam"], g["type"], str(len(g["members"])), g["desc"]]
                for g in all_groups
            ]
            out.table(
                ["Name", "Type", "Members", "Description"],
                rows,
                highlight_fn=lambda r: C.YELLOW if _is_high_value_name(r[0]) else None,
            )
