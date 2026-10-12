"""
LAPS module — detect LAPS deployment and identify readable passwords.
Supports both legacy LAPS (ms-Mcs-AdmPwd) and Windows LAPS (msLAPS-Password).
"""

from modules.base import BaseModule, ScanContext
from core.output import Severity, C
from utils.ldap_helpers import get_attr, get_list, get_raw
from utils.timestamp import filetime_to_str

# Legacy LAPS attributes
_LEGACY_ATTRS = ["sAMAccountName", "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime"]
# Windows LAPS (2023+) attributes
_WIN_LAPS_ATTRS = ["sAMAccountName", "msLAPS-Password", "msLAPS-PasswordExpirationTime",
                   "msLAPS-EncryptedPassword"]


class LAPSModule(BaseModule):
    name        = "laps"
    description = "LAPS deployment detection and readable password enumeration"

    def run(self, ctx: ScanContext) -> None:
        out = ctx.out
        out.section("LAPS")

        self._check_legacy_laps(ctx)
        self._check_windows_laps(ctx)

    def _check_legacy_laps(self, ctx: ScanContext) -> None:
        out = ctx.out

        # Check schema — does ms-Mcs-AdmPwd exist?
        entries = ctx.conn.search(
            "(objectClass=computer)",
            _LEGACY_ATTRS,
        )

        if not entries:
            return

        deployed  = 0
        readable  = []

        for entry in entries:
            sam = get_attr(entry, "sAMAccountName").rstrip("$")
            pwd = get_attr(entry, "ms-Mcs-AdmPwd")
            exp = get_attr(entry, "ms-Mcs-AdmPwdExpirationTime")

            if exp:
                deployed += 1

            if pwd:
                readable.append({
                    "sam":     sam,
                    "password": str(pwd),
                    "expires": filetime_to_str(exp) if exp else "unknown",
                })

        if deployed == 0 and not readable:
            out.info("Legacy LAPS (ms-Mcs-AdmPwd): not detected / not deployed")
            return

        out.subsection("Legacy LAPS (ms-Mcs-AdmPwd)")
        if deployed:
            out.success(f"Legacy LAPS deployed on ~{deployed} computer(s)")
        if readable:
            out.critical(f"{len(readable)} LAPS password(s) readable with current credentials!")
            rows = [[r["sam"], r["password"], r["expires"]] for r in readable]
            out.table(["Computer", "Local Admin Password", "Expires"], rows,
                      highlight_fn=lambda r: C.RED)
            ctx.quick_wins.add(
                Severity.CRITICAL,
                f"LAPS passwords readable — {len(readable)} computer(s)",
                "Accounts: " + ", ".join(r["sam"] for r in readable),
            )
        else:
            out.info("LAPS passwords not readable with current credentials")

    def _check_windows_laps(self, ctx: ScanContext) -> None:
        out = ctx.out

        entries = ctx.conn.search(
            "(objectClass=computer)",
            _WIN_LAPS_ATTRS,
        )

        if not entries:
            return

        deployed = 0
        readable = []

        for entry in entries:
            sam = get_attr(entry, "sAMAccountName").rstrip("$")
            pwd = get_attr(entry, "msLAPS-Password")
            enc = get_raw(entry, "msLAPS-EncryptedPassword")
            exp = get_attr(entry, "msLAPS-PasswordExpirationTime")

            if exp or enc:
                deployed += 1

            if pwd:
                readable.append({
                    "sam":      sam,
                    "password": str(pwd),
                    "expires":  filetime_to_str(exp) if exp else "unknown",
                })

        if deployed == 0 and not readable:
            return  # Windows LAPS not deployed, skip silently

        out.subsection("Windows LAPS (msLAPS-Password)")
        if deployed:
            out.success(f"Windows LAPS deployed on ~{deployed} computer(s)")
        if readable:
            out.critical(f"{len(readable)} Windows LAPS password(s) readable!")
            rows = [[r["sam"], r["password"], r["expires"]] for r in readable]
            out.table(["Computer", "Local Admin Password", "Expires"], rows,
                      highlight_fn=lambda r: C.RED)
            ctx.quick_wins.add(
                Severity.CRITICAL,
                f"Windows LAPS passwords readable — {len(readable)} computer(s)",
                "Accounts: " + ", ".join(r["sam"] for r in readable),
            )
        else:
            out.info("Windows LAPS passwords not readable with current credentials")
