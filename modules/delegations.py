"""
Delegations module — unconstrained, constrained, and RBCD (resource-based).
Covers both user and computer accounts.
"""

from modules.base import BaseModule, ScanContext
from core.output import Severity, C
from utils.ldap_helpers import get_attr, get_int, get_list
from utils import exploit_cmds
from utils.uac import uac_has, UAC_TRUSTED_DELEG, UAC_TRUSTED_TO_AUTH, UAC_SERVER_TRUST

_ATTRS_DELEGATION = [
    "sAMAccountName", "userAccountControl", "objectClass",
    "msDS-AllowedToDelegateTo",           # constrained
    "msDS-AllowedToActOnBehalfOfOtherIdentity",  # RBCD
    "servicePrincipalName",
    "distinguishedName",
]


class DelegationsModule(BaseModule):
    name        = "delegations"
    description = "Delegation enumeration (unconstrained, constrained, RBCD)"

    def run(self, ctx: ScanContext) -> None:
        out = ctx.out
        out.section("DELEGATIONS")

        # Query all objects that have some delegation flag set
        # We query users and computers separately for clarity
        uncons   = []
        cons     = []
        rbcd     = []

        # --- Unconstrained (TRUSTED_FOR_DELEGATION, not DCs) ---
        entries = ctx.conn.search(
            "(userAccountControl:1.2.840.113556.1.4.803:=524288)",  # flag 0x80000
            _ATTRS_DELEGATION,
        )
        for entry in entries:
            uac = get_int(entry, "userAccountControl")
            sam = get_attr(entry, "sAMAccountName")
            # Skip DCs (they always have unconstrained delegation by design)
            if uac_has(uac, UAC_SERVER_TRUST):
                continue
            oc = get_list(entry, "objectClass")
            kind = "Computer" if "computer" in oc else "User"
            uncons.append({"sam": sam, "kind": kind, "uac": uac})

        # --- Constrained (msDS-AllowedToDelegateTo) ---
        entries = ctx.conn.search(
            "(msDS-AllowedToDelegateTo=*)",
            _ATTRS_DELEGATION,
        )
        for entry in entries:
            sam      = get_attr(entry, "sAMAccountName")
            deleg_to = get_list(entry, "msDS-AllowedToDelegateTo")
            uac      = get_int(entry, "userAccountControl")
            oc       = get_list(entry, "objectClass")
            kind     = "Computer" if "computer" in oc else "User"
            # Protocol transition flag
            proto_trans = uac_has(uac, UAC_TRUSTED_TO_AUTH)
            cons.append({
                "sam":         sam,
                "kind":        kind,
                "deleg_to":    deleg_to,
                "proto_trans": proto_trans,
            })

        # --- RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity) ---
        entries = ctx.conn.search(
            "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
            _ATTRS_DELEGATION,
        )
        for entry in entries:
            sam  = get_attr(entry, "sAMAccountName")
            oc   = get_list(entry, "objectClass")
            kind = "Computer" if "computer" in oc else "User"
            rbcd.append({"sam": sam, "kind": kind})

        out.counter("Delegation findings", len(uncons) + len(cons) + len(rbcd), {
            "unconstrained": len(uncons),
            "constrained":   len(cons),
            "RBCD":          len(rbcd),
        })

        # --- Unconstrained ---
        if uncons:
            out.subsection("Unconstrained Delegation")
            rows = [[u["sam"], u["kind"]] for u in uncons]
            out.table(["Account", "Type"], rows, highlight_fn=lambda r: C.RED)
            ctx.quick_wins.add(
                Severity.HIGH,
                f"Unconstrained Delegation — {len(uncons)} account(s)",
                "Compromise these accounts → capture TGTs of any connecting user (incl. DA).\n"
                "Accounts: " + ", ".join(u["sam"] for u in uncons) + "\n"
                + exploit_cmds.unconstrained(ctx, uncons[0]["sam"]),
            )

        # --- Constrained ---
        if cons:
            out.subsection("Constrained Delegation")
            rows = []
            for c in cons:
                services = " | ".join(c["deleg_to"][:3])
                if len(c["deleg_to"]) > 3:
                    services += f" (+{len(c['deleg_to'])-3})"
                proto = " [PROTOCOL TRANSITION]" if c["proto_trans"] else ""
                rows.append([c["sam"], c["kind"], services + proto])
            out.table(
                ["Account", "Type", "Allowed Services"],
                rows,
                highlight_fn=lambda r: C.RED if "PROTOCOL TRANSITION" in r[2] else C.YELLOW,
            )
            proto_trans_count = sum(1 for c in cons if c["proto_trans"])
            if proto_trans_count:
                proto_accounts = [c["sam"] for c in cons if c["proto_trans"]]
                ctx.quick_wins.add(
                    Severity.HIGH,
                    f"Constrained Delegation with Protocol Transition — {proto_trans_count} account(s)",
                    "Protocol transition (S4U2Self) allows impersonating ANY user to the delegated services.\n"
                    "Accounts: " + ", ".join(proto_accounts) + "\n"
                    + exploit_cmds.constrained_deleg(ctx, proto_accounts[0], True),
                )
            else:
                ctx.quick_wins.add(
                    Severity.MEDIUM,
                    f"Constrained Delegation — {len(cons)} account(s)",
                    "May be exploitable via S4U2Proxy if you can compromise the delegating account.\n"
                    "Accounts: " + ", ".join(c["sam"] for c in cons) + "\n"
                    + exploit_cmds.constrained_deleg(ctx, cons[0]["sam"], False),
                )

        # --- RBCD ---
        if rbcd:
            out.subsection("Resource-Based Constrained Delegation (RBCD)")
            rows = [[r["sam"], r["kind"]] for r in rbcd]
            out.table(["Resource Account", "Type"], rows, highlight_fn=lambda r: C.YELLOW)
            ctx.quick_wins.add(
                Severity.MEDIUM,
                f"RBCD configured on {len(rbcd)} account(s)",
                "An actor with write access to msDS-AllowedToActOnBehalfOfOtherIdentity can\n"
                "set up RBCD to impersonate any user to the target service.\n"
                "Accounts: " + ", ".join(r["sam"] for r in rbcd) + "\n"
                + exploit_cmds.rbcd_exploit(ctx, rbcd[0]["sam"]),
            )
