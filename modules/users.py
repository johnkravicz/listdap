"""
Users module — full user enumeration with pentest-relevant attributes.
"""

from modules.base import BaseModule, ScanContext
from core.output import Severity, C
from utils.ldap_helpers import get_attr, get_int, get_list, get_raw, get_dn
from utils import exploit_cmds
from utils.highlight import analyze_description, extract_credentials, HIGH as DESC_HIGH, MEDIUM as DESC_MEDIUM
from utils.sids import bytes_to_sid
from utils.uac import (
    uac_has, uac_summary,
    UAC_DISABLED, UAC_LOCKOUT, UAC_NO_PREAUTH, UAC_PASSWD_NOTREQD,
    UAC_NO_EXPIRE_PWD, UAC_TRUSTED_DELEG, UAC_TRUSTED_TO_AUTH, UAC_PWD_EXPIRED,
    UAC_REVERSIBLE_PWD,
)

# AdminSDHolder-protected groups (SDProp stamps adminCount=1 on their transitive
# members). Domain-relative RIDs + builtin SIDs. Used to tell a current admin
# (legitimately adminCount=1) from an orphan whose privilege was removed.
_PROT_DOMAIN_RIDS = {512, 516, 518, 519, 521}  # DA, DCs, Schema, EA, RODC
_PROT_BUILTIN_SIDS = {
    "S-1-5-32-544",  # Administrators
    "S-1-5-32-548",  # Account Operators
    "S-1-5-32-549",  # Server Operators
    "S-1-5-32-550",  # Print Operators
    "S-1-5-32-551",  # Backup Operators
    "S-1-5-32-552",  # Replicator
}
# LDAP_MATCHING_RULE_IN_CHAIN — transitive (nested) group membership.
_IN_CHAIN = "1.2.840.113556.1.4.1941"
from utils.timestamp import filetime_to_str, days_since_filetime
from utils.enctypes import enctypes_summary, weakness as enc_weakness, has_rc4, has_des

# LDAP filter: user accounts only (exclude computers)
_USER_FILTER = "(&(objectCategory=person)(objectClass=user))"

_ATTRS = [
    "sAMAccountName", "displayName", "userPrincipalName",
    "userAccountControl", "memberOf",
    "lastLogonTimestamp", "pwdLastSet", "accountExpires",
    "servicePrincipalName", "description",
    "adminCount", "whenCreated", "primaryGroupID",
    "msDS-SupportedEncryptionTypes",
    "msDS-KeyCredentialLink",
]

# Free-text attributes (besides description) that commonly leak secrets — run
# through the same credential heuristic as description. `info` is the ADUC
# "Notes" field (a frequent offender); extensionAttribute1-15 are Exchange
# custom attributes often (ab)used to store misc data, including passwords.
_FREETEXT_ATTRS = ["info", "comment"] + [f"extensionAttribute{i}" for i in range(1, 16)]

# Attributes whose entire value IS (often) a secret — when present & readable
# they are a finding in themselves (userPassword is only populated when the
# domain enables it; it may hold cleartext or a {SCHEME}-prefixed hash).
_PASSWORD_ATTRS = ["userPassword", "unixUserPassword"]

_ATTRS = _ATTRS + _FREETEXT_ATTRS + _PASSWORD_ATTRS

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
        ctx.ldap_identity_count += len(entries)

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
        reversible      = []   # ENCRYPTED_TEXT_PWD_ALLOWED (cleartext recoverable)

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
                "primary_gid": get_int(entry, "primaryGroupID"),
                "dn":          get_dn(entry),
                "key_cred":    kc,
                "extra_creds": self._scan_cred_attrs(entry),
                "enc":         get_int(entry, "msDS-SupportedEncryptionTypes"),
            }
            user["enc_summary"] = enctypes_summary(user["enc"])
            user["enc_weak"]    = enc_weakness(user["enc"])
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
            if uac_has(uac, UAC_REVERSIBLE_PWD):
                reversible.append(user)

            # Last logon
            last_logon_val = user["last_logon"]
            if not last_logon_val or last_logon_val in ("0", ""):
                never_logged.append(user)
            else:
                days = days_since_filetime(last_logon_val)
                if days >= inactive_days:
                    inactive.append(user)

        # --- Quick Wins: credentials found in descriptions + other attributes ---
        self._qw_desc_credentials(ctx, all_users)
        self._qw_other_attr_credentials(ctx, all_users)

        attr_cred_users = [u for u in all_users if u.get("extra_creds")]

        # --- Summary counter ---
        out.counter("Users", len(all_users), {
            "disabled":        len(disabled),
            "locked":          len(locked),
            "AS-REP roastable": len(asrep),
            "Kerberoastable":  len(kerberoastable),
            "passwd_notreqd":  len(passwd_notreqd),
            "shadow creds":    len(shadow_creds),
            "secrets in attrs": len(attr_cred_users),
            "adminCount=1":    len(admin_count),
            "reversible pwd":  len(reversible),
        })

        # --- Secrets found in attributes other than description ---
        if attr_cred_users:
            out.subsection("Secrets in attributes (info / comment / extensionAttribute / userPassword)")
            rows = []
            for u in attr_cred_users:
                for fc in u["extra_creds"]:
                    rows.append([u["sam"], fc["attr"], fc["display"]])
            out.table(["Username", "Attribute", "Value"], rows, indent=4)

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
            rows = [[u["sam"], self._enc_cell(u), u["description"]] for u in asrep]
            out.table(["Username", "Enc", "Description"], rows,
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
                rows.append([u["sam"], spn_str, self._enc_cell(u), u["description"]])
            out.table(["Username", "SPNs", "Enc", "Description"], rows,
                      highlight_fn=lambda r: _row_color(r[0], C.YELLOW))
            ctx.quick_wins.add(
                Severity.HIGH,
                f"Kerberoasting — {len(kerberoastable)} account(s)",
                "Accounts: " + ", ".join(u["sam"] for u in kerberoastable) + "\n"
                + exploit_cmds.kerberoast(ctx),
            )

        # --- Shadow credentials (inline flag; the `shadow` module parses &
        #     risk-scores these — no Quick Win here to avoid duplication) ---
        if shadow_creds:
            out.subsection("Shadow Credentials (msDS-KeyCredentialLink)")
            rows = [[u["sam"], str(len(u["key_cred"])) + " key(s)"] for u in shadow_creds]
            out.table(["Username", "Key Credentials"], rows,
                      highlight_fn=lambda r: C.YELLOW)
            out.info("See the SHADOW CREDENTIALS section for parsed key detail "
                     "(creation time / device) and risk scoring.")

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

        # --- adminCount=1 + AdminSDHolder orphan detection ---
        if admin_count:
            self._report_admincount(ctx, admin_count)

        # --- Reversible password encryption (cleartext recoverable) ---
        if reversible:
            self._report_reversible(ctx, reversible)

        # --- Weak Kerberos encryption (msDS-SupportedEncryptionTypes) ---
        self._report_enctypes(ctx, all_users, kerberoastable, asrep)

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

    @staticmethod
    def _scan_cred_attrs(entry) -> list:
        """Scan free-text + password attributes (besides description) for secrets.

        Returns a list of dicts: {attr, raw, sev, display, pwd_attr?, hashed?}.
        Only HIGH/MEDIUM free-text findings are kept (LOW keyword-only is dropped
        to limit noise); password attributes are always a finding when present.
        """
        found = []
        for attr in _FREETEXT_ATTRS:
            val = get_attr(entry, attr)
            if not val:
                continue
            display, sev = analyze_description(val)
            if sev in (DESC_HIGH, DESC_MEDIUM):
                found.append({"attr": attr, "raw": val, "sev": sev, "display": display})
        for attr in _PASSWORD_ATTRS:
            for val in get_list(entry, attr):
                if not val:
                    continue
                hashed = val.startswith("{")
                found.append({
                    "attr": attr, "raw": val, "sev": DESC_HIGH,
                    "pwd_attr": True, "hashed": hashed,
                    "display": (f"{C.YELLOW}{val}{C.RESET}" if hashed
                                else f"{C.RED}{C.BOLD}{val}{C.RESET}"),
                })
        return found

    @staticmethod
    def _qw_other_attr_credentials(ctx: ScanContext, all_users: list) -> None:
        """Quick Wins for secrets found in attributes other than description:
        info / comment / extensionAttribute1-15 / userPassword / unixUserPassword."""
        dc      = ctx.conn.dc_info
        dc_ip   = getattr(ctx.args, "dc", dc.ip or dc.hostname)
        domain  = ctx.domain or dc.domain
        ldaps   = getattr(ctx.args, "ldaps", False)
        proto   = "--ldaps " if ldaps else ""

        for u in all_users:
            for fc in u.get("extra_creds", []):
                sam, attr, raw = u["sam"], fc["attr"], fc["raw"]

                # userPassword / unixUserPassword: the whole value is the secret.
                if fc.get("pwd_attr"):
                    if fc.get("hashed"):
                        ctx.quick_wins.add(
                            Severity.HIGH,
                            f"Password hash in {attr} — {sam}",
                            f"{attr} holds a hashed secret: {raw}\n"
                            "Crack it offline (scheme is in the {…} prefix → hashcat/john).",
                        )
                    else:
                        cmd = (f"python3 listdap.py -d {domain} -dc {dc_ip} "
                               f"{proto}-u {sam} -p '{raw}'")
                        ctx.quick_wins.add(
                            Severity.CRITICAL,
                            f"Cleartext credential in {attr} — {sam}",
                            f"Password: {C.RED}{C.BOLD}{raw}{C.RESET}\n"
                            f"\nRe-run authenticated:\n  {C.CYAN}{cmd}{C.RESET}",
                        )
                    continue

                # Free-text attrs: extract keyword+value / hash candidates.
                creds = extract_credentials(raw)
                for cred in creds:
                    cmd = (f"python3 listdap.py -d {domain} -dc {dc_ip} "
                           f"{proto}-u {sam} -p '{cred}'")
                    ctx.quick_wins.add(
                        Severity.CRITICAL,
                        f"Cleartext credential in {attr} — {sam}",
                        f"Password candidate: {C.RED}{C.BOLD}{cred}{C.RESET}\n"
                        f"Full {attr}:   {raw}\n"
                        f"\nRe-run authenticated:\n  {C.CYAN}{cmd}{C.RESET}",
                    )
                if not creds:
                    # Flagged as sensitive but no cleanly-extractable token.
                    sev = Severity.HIGH if fc["sev"] == DESC_HIGH else Severity.MEDIUM
                    ctx.quick_wins.add(
                        sev,
                        f"Sensitive data in {attr} — {sam}",
                        f"{attr}: {raw}",
                    )

    # ---- Reversible password encryption -----------------------------------
    @staticmethod
    def _report_reversible(ctx: ScanContext, reversible: list) -> None:
        out = ctx.out
        out.subsection("Reversible Password Encryption (ENCRYPTED_TEXT_PWD_ALLOWED)")
        rows = [[u["sam"], uac_summary(u["uac"]) or "-", u["description"]]
                for u in reversible]
        out.table(["Username", "UAC Flags", "Description"], rows, indent=4,
                  highlight_fn=lambda r: C.RED)
        names = ", ".join(u["sam"] for u in reversible)
        ctx.quick_wins.add(
            Severity.HIGH,
            f"Reversible password encryption — {len(reversible)} account(s)",
            "These accounts store their password reversibly (RC4 under the SYSKEY), "
            "so a DCSync / secretsdump recovers the CLEARTEXT password, not just the "
            "NT hash (look under the 'ClearText' / Kerberos-keys section):\n  "
            + names + "\n" + exploit_cmds.dcsync(ctx),
        )

    # ---- AdminSDHolder orphans --------------------------------------------
    def _report_admincount(self, ctx: ScanContext, admin_count: list) -> None:
        out = ctx.out
        out.subsection("AdminSDHolder Protected (adminCount=1)")

        protected = self._protected_member_dns(ctx)   # set, or None if undetermined

        def _is_protected(u) -> bool:
            if u["primary_gid"] in _PROT_DOMAIN_RIDS:
                return True
            return protected is not None and u["dn"].lower() in protected

        orphans, legit = [], []
        for u in admin_count:
            if u["sam"].lower() == "krbtgt":
                legit.append(u)
                continue
            (legit if _is_protected(u) else orphans).append(u)

        def _status(u) -> str:
            if u["sam"].lower() == "krbtgt":
                return "yes (krbtgt)"
            if protected is None:
                return "unknown"
            return "ORPHAN" if u in orphans else "yes"

        rows = [[u["sam"], _status(u), uac_summary(u["uac"]) or "-", u["description"]]
                for u in admin_count]
        out.table(["Username", "Still protected", "UAC Flags", "Description"], rows,
                  indent=4,
                  highlight_fn=lambda r: C.YELLOW if r[1] == "ORPHAN" else None)

        if protected is None:
            out.info("Could not resolve current protected-group membership "
                     "(transitive query unavailable) — orphan detection skipped.")
            return

        if orphans:
            ctx.quick_wins.add(
                Severity.MEDIUM,
                f"AdminSDHolder orphans — {len(orphans)} stale privileged account(s)",
                "These carry adminCount=1 but are no longer a (transitive) member of "
                "any protected group. They were privileged once → expect residual "
                "access, a stale locked-down ACL (inheritance still disabled), or an "
                "adminCount persistence marker. Review each:\n  "
                + ", ".join(u["sam"] for u in orphans),
            )

    @staticmethod
    def _protected_member_dns(ctx: ScanContext):
        """Lowercased DNs of every (transitive) member of AdminSDHolder-protected
        groups. Returns None when the membership can't be determined (so callers
        skip orphan judgement rather than over-report)."""
        groups = ctx.conn.search("(objectClass=group)", ["objectSid"])
        if not groups:
            return None
        dsid = ctx.domain_sid
        prot_dns = []
        for g in groups:
            raw = get_raw(g, "objectSid")
            sid = bytes_to_sid(raw) if raw else ""
            is_prot = sid in _PROT_BUILTIN_SIDS
            if not is_prot and dsid and sid.startswith(dsid + "-"):
                try:
                    is_prot = int(sid[len(dsid) + 1:]) in _PROT_DOMAIN_RIDS
                except ValueError:
                    is_prot = False
            if is_prot:
                prot_dns.append(get_dn(g))
        if not prot_dns:
            return None

        clause = "".join(f"(memberOf:{_IN_CHAIN}:={dn})" for dn in prot_dns)
        res = ctx.conn.search(
            f"(&(objectCategory=person)(objectClass=user)(|{clause}))",
            ["distinguishedName"],
        )
        members = {get_dn(r).lower() for r in res if get_dn(r)}
        # A domain always has at least Administrator protected; an empty result
        # means the transitive-match query was unsupported/failed, not that no
        # account is protected → signal 'undetermined'.
        return members or None

    @staticmethod
    def _enc_cell(u: dict) -> str:
        """Coloured msDS-SupportedEncryptionTypes summary for a table cell:
        red when DES is enabled, yellow when RC4 is reachable, plain for AES-only."""
        summary = u.get("enc_summary", "")
        enc     = u.get("enc", 0)
        if has_des(enc):
            return f"{C.RED}{C.BOLD}{summary}{C.RESET}"
        if u.get("enc_weak"):          # RC4-only / RC4+AES / RC4-default
            return f"{C.YELLOW}{summary}{C.RESET}"
        return summary

    @staticmethod
    def _report_enctypes(ctx: ScanContext, all_users: list,
                         kerberoastable: list, asrep: list) -> None:
        """Flag accounts with weak Kerberos encryption (DES enabled, or RC4
        reachable on a roastable account → fast crack / downgrade)."""
        out = ctx.out

        des = [u for u in all_users
               if has_des(u["enc"]) and not uac_has(u["uac"], UAC_DISABLED)]
        # RC4-reachable accounts that are actually roastable (SPN or no-preauth):
        # that is where RC4 directly buys a fast-cracking hash.
        roastable = {u["sam"]: u for u in kerberoastable}
        roastable.update({u["sam"]: u for u in asrep})
        rc4_roast = [u for u in roastable.values()
                     if u["enc_weak"] in ("RC4-only", "RC4+AES", "RC4-default")]

        if not des and not rc4_roast:
            return

        out.subsection("Weak Kerberos Encryption (msDS-SupportedEncryptionTypes)")

        if des:
            print(f"    {C.RED}{C.BOLD}DES enabled{C.RESET} (trivially crackable):")
            out.table(["Username", "Supported etypes"],
                      [[u["sam"], u["enc_summary"]] for u in des],
                      highlight_fn=lambda r: C.RED, indent=6)
            ctx.quick_wins.add(
                Severity.HIGH,
                f"DES Kerberos encryption enabled on {len(des)} account(s)",
                "These accounts advertise DES — any Kerberos material for them is "
                "trivially crackable (and DES-only breaks modern defaults):\n  "
                + ", ".join(u["sam"] for u in des)
                + "\nRoast/crack as usual; the recovered key is near-instant to break.",
            )

        if rc4_roast:
            print(f"    {C.YELLOW}RC4-reachable + roastable{C.RESET} "
                  f"(fast-cracking hash / AES downgrade):")
            out.table(["Username", "Roast", "Supported etypes"],
                      [[u["sam"],
                        "SPN" if u["spns"] else ("AS-REP" if uac_has(u["uac"], UAC_NO_PREAUTH) else "-"),
                        u["enc_summary"]] for u in rc4_roast],
                      highlight_fn=lambda r: C.YELLOW, indent=6)
            ctx.quick_wins.add(
                Severity.MEDIUM,
                f"RC4 Kerberos surface on {len(rc4_roast)} roastable account(s)",
                "Roastable accounts that still accept RC4: request an RC4 ticket to "
                "get an etype-23 hash (hashcat -m 13100 / -m 18200, fast) instead of "
                "slow AES — a downgrade even when AES is also supported:\n  "
                + ", ".join(u["sam"] for u in rc4_roast),
            )
