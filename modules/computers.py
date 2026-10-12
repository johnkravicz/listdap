"""
Computers module — enumerate domain-joined machines.
"""

from modules.base import BaseModule, ScanContext
from core.output import Severity, C
from utils.ldap_helpers import get_attr, get_int, get_list
from utils.uac import uac_has, UAC_TRUSTED_DELEG, UAC_TRUSTED_TO_AUTH, UAC_DISABLED, UAC_SERVER_TRUST
from utils.timestamp import filetime_to_str, days_since_filetime

_COMPUTER_FILTER = "(objectClass=computer)"
_ATTRS = [
    "sAMAccountName", "dNSHostName", "operatingSystem",
    "operatingSystemVersion", "operatingSystemServicePack",
    "lastLogonTimestamp", "userAccountControl", "description",
    "servicePrincipalName", "msDS-AllowedToDelegateTo",
    "msDS-KeyCredentialLink",
]

# OS strings indicating EOL / no longer supported
_EOL_OS = [
    "windows xp", "windows 2000", "windows vista",
    "windows 7", "windows 8", "windows server 2003",
    "windows server 2008", "windows server 2000",
]


def _is_eol(os_str: str) -> bool:
    s = os_str.lower()
    return any(eol in s for eol in _EOL_OS)


class ComputersModule(BaseModule):
    name        = "computers"
    description = "Domain computer enumeration (OS, delegation, EOL)"

    def run(self, ctx: ScanContext) -> None:
        out = ctx.out
        out.section("COMPUTERS")

        entries = ctx.conn.search(_COMPUTER_FILTER, _ATTRS)
        if not entries:
            out.warning("No computers found (check permissions)")
            return

        all_computers = []
        dcs           = []
        eol           = []
        uncons_deleg  = []
        cons_deleg    = []
        shadow_creds  = []
        inactive      = []

        inactive_days = getattr(ctx.args, "inactive_days", 90)

        for entry in entries:
            sam  = get_attr(entry, "sAMAccountName")
            dns  = get_attr(entry, "dNSHostName")
            os   = get_attr(entry, "operatingSystem")
            osv  = get_attr(entry, "operatingSystemVersion")
            uac  = get_int(entry, "userAccountControl")
            spns = get_list(entry, "servicePrincipalName")
            deleg_to = get_list(entry, "msDS-AllowedToDelegateTo")
            kc   = get_list(entry, "msDS-KeyCredentialLink")
            ll   = get_attr(entry, "lastLogonTimestamp")
            desc = get_attr(entry, "description")

            computer = {
                "sam":      sam.rstrip("$"),
                "dns":      dns,
                "os":       os,
                "os_ver":   osv,
                "uac":      uac,
                "spns":     spns,
                "deleg_to": deleg_to,
                "key_cred": kc,
                "last_logon": ll,
                "desc":     desc,
            }
            all_computers.append(computer)

            is_dc = uac_has(uac, UAC_SERVER_TRUST)
            if is_dc:
                dcs.append(computer)

            if uac_has(uac, UAC_TRUSTED_DELEG) and not is_dc:
                uncons_deleg.append(computer)
            if deleg_to:
                cons_deleg.append(computer)
            if os and _is_eol(os):
                eol.append(computer)
            if kc:
                shadow_creds.append(computer)

            days = days_since_filetime(ll)
            if days >= inactive_days:
                inactive.append(computer)

        out.counter("Computers", len(all_computers), {
            "DCs":                    len(dcs),
            "EOL OS":                 len(eol),
            "unconstrained deleg":    len(uncons_deleg),
            "constrained deleg":      len(cons_deleg),
            "shadow creds":           len(shadow_creds),
        })

        # --- Domain Controllers ---
        if dcs:
            out.subsection("Domain Controllers")
            rows = [
                [c["sam"], c["dns"], c["os"], filetime_to_str(c["last_logon"])]
                for c in dcs
            ]
            out.table(["Name", "DNS", "OS", "Last Logon"], rows,
                      highlight_fn=lambda r: C.CYAN)

        # --- Unconstrained delegation ---
        if uncons_deleg:
            out.subsection("Unconstrained Delegation (high-value targets)")
            rows = [
                [c["sam"], c["dns"], c["os"], filetime_to_str(c["last_logon"])]
                for c in uncons_deleg
            ]
            out.table(["Name", "DNS", "OS", "Last Logon"], rows,
                      highlight_fn=lambda r: C.RED)
            ctx.quick_wins.add(
                Severity.HIGH,
                f"Unconstrained Delegation — {len(uncons_deleg)} computer(s)",
                "These machines store TGTs of all connecting users in memory.\n"
                "Compromise → PrinterBug / PetitPotam to coerce DC → DCSync.\n"
                "Targets: " + ", ".join(c["sam"] for c in uncons_deleg),
            )

        # --- Constrained delegation ---
        if cons_deleg:
            out.subsection("Constrained Delegation")
            rows = []
            for c in cons_deleg:
                services = " | ".join(c["deleg_to"][:3])
                if len(c["deleg_to"]) > 3:
                    services += f" (+{len(c['deleg_to'])-3})"
                rows.append([c["sam"], services])
            out.table(["Name", "Allowed to Delegate To"], rows,
                      highlight_fn=lambda r: C.YELLOW)
            ctx.quick_wins.add(
                Severity.MEDIUM,
                f"Constrained Delegation — {len(cons_deleg)} computer(s)",
                "May be exploitable via S4U2Proxy / protocol transition.\n"
                "Targets: " + ", ".join(c["sam"] for c in cons_deleg),
            )

        # --- EOL operating systems ---
        if eol:
            out.subsection("End-of-Life Operating Systems")
            rows = [
                [c["sam"], c["os"], c["os_ver"], filetime_to_str(c["last_logon"])]
                for c in eol
            ]
            out.table(["Name", "OS", "Version", "Last Logon"], rows,
                      highlight_fn=lambda r: C.YELLOW)
            ctx.quick_wins.add(
                Severity.MEDIUM,
                f"EOL OS detected on {len(eol)} host(s)",
                "Targets: " + ", ".join(f"{c['sam']} ({c['os']})" for c in eol),
            )

        # --- Shadow credentials on computers ---
        if shadow_creds:
            out.subsection("Shadow Credentials on Computers")
            rows = [[c["sam"], str(len(c["key_cred"])) + " key(s)"] for c in shadow_creds]
            out.table(["Name", "Key Credentials"], rows,
                      highlight_fn=lambda r: C.YELLOW)

        # --- All computers (verbose) ---
        if ctx.out.verbose:
            out.subsection("All Computers")
            rows = [
                [c["sam"], c["os"], c["os_ver"], filetime_to_str(c["last_logon"])]
                for c in all_computers
            ]
            out.table(
                ["Name", "OS", "Version", "Last Logon"],
                rows,
                highlight_fn=lambda r: C.YELLOW if _is_eol(r[1]) else None,
            )
