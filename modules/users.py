"""
Users module — full user enumeration with pentest-relevant attributes.
"""

from modules.base import BaseModule, ScanContext
from core.output import Severity, C
from utils.ldap_helpers import get_attr, get_int, get_list
from utils import exploit_cmds
from utils.highlight import analyze_description, extract_credentials, HIGH as DESC_HIGH, MEDIUM as DESC_MEDIUM
from utils.uac import (
    uac_has, uac_summary,
    UAC_DISABLED, UAC_LOCKOUT, UAC_NO_PREAUTH, UAC_PASSWD_NOTREQD,
    UAC_NO_EXPIRE_PWD, UAC_TRUSTED_DELEG, UAC_TRUSTED_TO_AUTH, UAC_PWD_EXPIRED,
)
from utils.timestamp import filetime_to_str, days_since_filetime

# LDAP filter: user accounts only (exclude computers)
_USER_FILTER = "(&(objectCategory=person)(objectClass=user))"

_ATTRS = [
    "sAMAccountName", "displayName", "userPrincipalName",
    "userAccountControl", "memberOf",
    "lastLogonTimestamp", "pwdLastSet", "accountExpires",
    "servicePrincipalName", "description",
    "adminCount", "whenCreated",
    "msDS-SupportedEncryptionTypes",
    "msDS-KeyCredentialLink",
]

# High-privilege groups (partial DN match, case-insensitive)
_PRIV_GROUPS = [
    "domain admins",
    "enterprise admins",
    "schema admins",
    "administrators",
    "account operators",
    "backup operators",
    "server operators",
    "print operators",
    "group policy creator owners",
    "protected users",
    "key admins",
    "enterprise key admins",
    "dnsadmins",
    "exchange windows permissions",
    "organization management",
]


def _is_priv_member(member_of: list) -> bool:
    for group in member_of:
        g = group.lower()
        for priv in _PRIV_GROUPS:
            if priv in g:
                return True
    return False


def _priv_groups_of(member_of: list) -> list:
    found = []
    for group in member_of:
        g = group.lower()
        for priv in _PRIV_GROUPS:
            if priv in g:
                # Extract CN=... from DN
                cn = group.split(",")[0].split("=", 1)[-1]
                if cn not in found:
                    found.append(cn)
    return found


def _fmt_desc(raw: str) -> tuple[str, str | None]:
    """
    Returns (display_string, severity) for a description.
    display_string has inline ANSI highlights on suspicious tokens.
    A severity badge is prepended: [!!] for HIGH, [!] for MEDIUM.
    """
    highlighted, sev = analyze_description(raw)
    if sev == DESC_HIGH:
        badge = f"{C.RED}{C.BOLD}[!!]{C.RESET} "
        return badge + highlighted, sev
    if sev == DESC_MEDIUM:
        badge = f"{C.YELLOW}{C.BOLD}[!]{C.RESET} "
        return badge + highlighted, sev
    return highlighted or "", sev


class UsersModule(BaseModule):
    name        = "users"
    description = "User enumeration (flags, SPNs, AS-REP, privileged accounts)"

    def run(self, ctx: ScanContext) -> None:
        out = ctx.out
        out.section("USERS")

        entries = ctx.conn.search(_USER_FILTER, _ATTRS)
        if not entries:
            out.warning("No users found (check permissions)")
            return

        # --- Categorize ---
        all_users       = []
        disabled        = []
        locked          = []
        asrep           = []   # no preauth
        kerberoastable  = []   # has SPN
        passwd_notreqd  = []
        no_expire       = []
        pwd_expired     = []
        never_logged    = []
        inactive        = []   # not logged in since --inactive-days
        admin_count     = []   # adminCount=1
        privileged      = []   # member of high-priv group
        shadow_creds    = []   # msDS-KeyCredentialLink set

        inactive_days = getattr(ctx.args, "inactive_days", 90)

        for entry in entries:
            sam  = get_attr(entry, "sAMAccountName")
            if not sam:
                continue
            uac  = get_int(entry, "userAccountControl")
            spns = get_list(entry, "servicePrincipalName")
            mof  = get_list(entry, "memberOf")
            kc   = get_list(entry, "msDS-KeyCredentialLink")

            raw_desc               = get_attr(entry, "description")
            desc_display, desc_sev = _fmt_desc(raw_desc)

            user = {
                "sam":         sam,
                "display":     get_attr(entry, "displayName"),
                "upn":         get_attr(entry, "userPrincipalName"),
                "uac":         uac,
                "spns":        spns,
                "member_of":   mof,
                "last_logon":  get_attr(entry, "lastLogonTimestamp"),
                "pwd_last_set": get_attr(entry, "pwdLastSet"),
                "description": desc_display,   # pre-highlighted (ANSI + badge)
                "raw_desc":    raw_desc,        # original, for credential extraction
                "desc_sev":    desc_sev,        # HIGH / MEDIUM / LOW / None
                "admin_count": get_int(entry, "adminCount"),
                "key_cred":    kc,
            }
            all_users.append(user)

            # Dump
            if ctx.dump:
                ctx.dump.add_user(sam)

            if uac_has(uac, UAC_DISABLED):
                disabled.append(user)
            if uac_has(uac, UAC_LOCKOUT):
                locked.append(user)
            if uac_has(uac, UAC_NO_PREAUTH) and not uac_has(uac, UAC_DISABLED):
                asrep.append(user)
                if ctx.dump:
                    ctx.dump.add_np_user(sam)
            if spns and not uac_has(uac, UAC_DISABLED):
                kerberoastable.append(user)
                if ctx.dump:
                    ctx.dump.add_spn_user(sam)
            if uac_has(uac, UAC_PASSWD_NOTREQD):
                passwd_notreqd.append(user)
            if uac_has(uac, UAC_NO_EXPIRE_PWD):
                no_expire.append(user)
            if uac_has(uac, UAC_PWD_EXPIRED):
                pwd_expired.append(user)
            if user["admin_count"] == 1:
                admin_count.append(user)
            if _is_priv_member(mof):
                privileged.append(user)
            if kc:
                shadow_creds.append(user)

            # Last logon
            last_logon_val = user["last_logon"]
            if not last_logon_val or last_logon_val in ("0", ""):
                never_logged.append(user)
            else:
                days = days_since_filetime(last_logon_val)
                if days >= inactive_days:
                    inactive.append(user)

        # --- Quick Wins: credentials found in descriptions ---
        self._qw_desc_credentials(ctx, all_users)

        # --- Summary counter ---
        out.counter("Users", len(all_users), {
            "disabled":        len(disabled),
            "locked":          len(locked),
            "AS-REP roastable": len(asrep),
            "Kerberoastable":  len(kerberoastable),
            "passwd_notreqd":  len(passwd_notreqd),
            "shadow creds":    len(shadow_creds),
            "adminCount=1":    len(admin_count),
        })

        # Build a sam→user lookup for highlight closures
        _umap = {u["sam"]: u for u in all_users}

        def _row_color(sam: str, default_color: str = None) -> str | None:
            """
            Row-level color logic:
            - If description has HIGH-severity finding: no row color
              (let the inline highlights stand on their own)
            - Otherwise: apply default_color if provided
            """
            u = _umap.get(sam)
            if u and u["desc_sev"] == DESC_HIGH:
                return None
            return default_color

        # --- Privileged users ---
        if privileged:
            out.subsection("Privileged Users")
            rows = []
            for u in privileged:
                groups = ", ".join(_priv_groups_of(u["member_of"]))
                ll = filetime_to_str(u["last_logon"]) if u["last_logon"] else "never"
                rows.append([u["sam"], groups, ll, u["description"]])
            out.table(
                ["Username", "Privileged Groups", "Last Logon", "Description"],
                rows,
                highlight_fn=lambda r: _row_color(
                    r[0],
                    C.RED if any(
                        g in r[1].lower()
                        for g in ["domain admins", "enterprise admins", "schema admins"]
                    ) else C.YELLOW,
                ),
            )

        # --- AS-REP roastable ---
        if asrep:
            out.subsection("AS-REP Roastable (no pre-auth required)")
            rows = [[u["sam"], u["description"]] for u in asrep]
            out.table(["Username", "Description"], rows,
                      highlight_fn=lambda r: _row_color(r[0], C.RED))
            ctx.quick_wins.add(
                Severity.CRITICAL,
                f"AS-REP Roasting — {len(asrep)} account(s)",
                "Accounts: " + ", ".join(u["sam"] for u in asrep) + "\n"
                + exploit_cmds.asreproast(ctx),
            )

        # --- Kerberoastable ---
        if kerberoastable:
            out.subsection("Kerberoastable (SPN set)")
            rows = []
            for u in kerberoastable:
                spn_str = " | ".join(u["spns"][:3])
                if len(u["spns"]) > 3:
                    spn_str += f" (+{len(u['spns'])-3})"
                rows.append([u["sam"], spn_str, u["description"]])
            out.table(["Username", "SPNs", "Description"], rows,
                      highlight_fn=lambda r: _row_color(r[0], C.YELLOW))
            ctx.quick_wins.add(
                Severity.HIGH,
                f"Kerberoasting — {len(kerberoastable)} account(s)",
                "Accounts: " + ", ".join(u["sam"] for u in kerberoastable) + "\n"
                + exploit_cmds.kerberoast(ctx),
            )

        # --- Shadow credentials ---
        if shadow_creds:
            out.subsection("Shadow Credentials (msDS-KeyCredentialLink)")
            rows = [[u["sam"], str(len(u["key_cred"])) + " key(s)"] for u in shadow_creds]
            out.table(["Username", "Key Credentials"], rows,
                      highlight_fn=lambda r: C.YELLOW)
            ctx.quick_wins.add(
                Severity.HIGH,
                f"Shadow Credentials set on {len(shadow_creds)} account(s)",
                "May indicate persistence backdoor or RBCD setup. Accounts: "
                + ", ".join(u["sam"] for u in shadow_creds),
            )

        # --- PASSWD_NOTREQD ---
        if passwd_notreqd:
            out.subsection("PASSWD_NOTREQD (may have empty password)")
            rows = [[u["sam"], uac_summary(u["uac"]), u["description"]] for u in passwd_notreqd]
            out.table(["Username", "UAC Flags", "Description"], rows,
                      highlight_fn=lambda r: _row_color(r[0]))
            ctx.quick_wins.add(
                Severity.MEDIUM,
                f"PASSWD_NOTREQD — {len(passwd_notreqd)} account(s)",
                "These accounts may have an empty password.\n"
                + exploit_cmds.empty_password(ctx, [u["sam"] for u in passwd_notreqd]),
            )

        # --- Inactive accounts ---
        if inactive or never_logged:
            out.subsection(f"Inactive / Never Logged-in (>{inactive_days} days)")
            combined = never_logged + [u for u in inactive if u not in never_logged]
            rows = []
            for u in combined[:30]:  # cap display to 30
                ll = filetime_to_str(u["last_logon"]) if u["last_logon"] else "never"
                rows.append([u["sam"], ll, uac_summary(u["uac"]) or "-", u["description"]])
            if len(combined) > 30:
                out.info(f"  ... and {len(combined) - 30} more")
            out.table(["Username", "Last Logon", "Flags", "Description"], rows,
                      highlight_fn=lambda r: _row_color(r[0]))
            out.info(
                f"{len(combined)} inactive/never-logged account(s) — "
                f"lower risk for password spraying detection"
            )

        # --- Locked accounts ---
        if locked:
            out.subsection("Locked Accounts")
            rows = [[u["sam"], filetime_to_str(u["last_logon"]), u["description"]] for u in locked]
            out.table(["Username", "Last Logon", "Description"], rows,
                      highlight_fn=lambda r: _row_color(r[0]))

        # --- adminCount=1 ---
        if admin_count:
            out.subsection("AdminSDHolder Protected (adminCount=1)")
            rows = [[u["sam"], uac_summary(u["uac"]) or "-", u["description"]] for u in admin_count]
            out.table(["Username", "UAC Flags", "Description"], rows,
                      highlight_fn=lambda r: _row_color(r[0]))

        # --- All users (always shown) ---
        out.subsection("All Users")
        rows = []
        for u in all_users:
            ll    = filetime_to_str(u["last_logon"]) if u["last_logon"] else "never"
            pls   = filetime_to_str(u["pwd_last_set"]) if u["pwd_last_set"] else "never"
            flags = uac_summary(u["uac"]) or "-"
            if ctx.out.verbose:
                rows.append([u["sam"], ll, pls, flags, u["description"]])
            else:
                rows.append([u["sam"], ll, flags, u["description"]])

        flags_col = 3 if ctx.out.verbose else 2
        if ctx.out.verbose:
            out.table(
                ["Username", "Last Logon", "Pwd Last Set", "Flags", "Description"],
                rows,
                highlight_fn=lambda r: _row_color(
                    r[0],
                    C.RED if "DISABLED" in r[flags_col] else None,
                ),
            )
        else:
            out.table(
                ["Username", "Last Logon", "Flags", "Description"],
                rows,
                highlight_fn=lambda r: _row_color(
                    r[0],
                    C.RED if "DISABLED" in r[flags_col] else None,
                ),
            )

    # ------------------------------------------------------------------

    @staticmethod
    def _qw_desc_credentials(ctx: ScanContext, all_users: list) -> None:
        """
        For each user whose description contains a HIGH-confidence credential,
        add a Critical Quick Win with the extracted value and a suggested
        authenticated listdap command.
        """
        dc      = ctx.conn.dc_info
        dc_ip   = getattr(ctx.args, "dc", dc.ip or dc.hostname)
        domain  = ctx.domain or dc.domain
        ldaps   = getattr(ctx.args, "ldaps", False)
        proto   = "--ldaps " if ldaps else ""

        for u in all_users:
            if u.get("desc_sev") != DESC_HIGH:
                continue

            raw_desc = u.get("raw_desc", "")
            creds    = extract_credentials(raw_desc)
            if not creds:
                continue

            sam = u["sam"]
            for cred in creds:
                cmd = (
                    f"python3 listdap.py -d {domain} -dc {dc_ip} "
                    f"{proto}-u {sam} -p '{cred}'"
                )
                ctx.quick_wins.add(
                    Severity.CRITICAL,
                    f"Cleartext credential in description — {sam}",
                    f"Password candidate: {C.RED}{C.BOLD}{cred}{C.RESET}\n"
                    f"Full description:   {raw_desc}\n"
                    f"\nRe-run authenticated:\n  {C.CYAN}{cmd}{C.RESET}",
                )
