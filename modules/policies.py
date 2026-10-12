"""
Password policies module — default domain policy + Fine-Grained Password Policies (FGPP).
Includes spray planning advice.
"""

from modules.base import BaseModule, ScanContext
from core.output import Severity, C
from utils.ldap_helpers import get_attr, get_int, get_list, SCOPE_BASE

# Default domain password policy is stored on the domain object
_DOMAIN_ATTRS = [
    "minPwdLength", "maxPwdAge", "minPwdAge",
    "lockoutThreshold", "lockoutDuration", "lockoutObservationWindow",
    "pwdHistoryLength", "pwdProperties",
]

# Fine-Grained Password Policy
_FGPP_FILTER = "(objectClass=msDS-PasswordSettings)"
_FGPP_ATTRS  = [
    "name", "msDS-PasswordSettingsPrecedence",
    "msDS-MinimumPasswordLength", "msDS-MaximumPasswordAge",
    "msDS-LockoutThreshold", "msDS-LockoutDuration",
    "msDS-LockoutObservationWindow", "msDS-PasswordHistoryLength",
    "msDS-PasswordComplexityEnabled", "msDS-PasswordReversibleEncryptionEnabled",
    "msDS-PSOAppliesTo",
]

_PWD_PROPS = {
    0x00: "None",
    0x01: "Complexity disabled",
    0x02: "Reversible encryption enabled",
}


def _pwd_props_str(value: int) -> str:
    parts = []
    if value & 0x01:
        parts.append("No complexity requirement")
    else:
        parts.append("Complexity required")
    if value & 0x02:
        parts.append("Reversible encryption")
    return ", ".join(parts) if parts else str(value)


def _interval_to_str(interval_value) -> str:
    """Convert a negative 100ns interval to human-readable."""
    try:
        v = int(interval_value)
    except (TypeError, ValueError):
        return "unknown"
    if v == 0:
        return "0 (none)"
    if v == -9223372036854775808:  # 0x8000000000000000 — never
        return "never"
    seconds = abs(v) / 1e7
    if seconds < 60:
        return f"{int(seconds)}s"
    if seconds < 3600:
        return f"{int(seconds / 60)}m"
    if seconds < 86400:
        return f"{int(seconds / 3600)}h"
    return f"{int(seconds / 86400)}d"


def _spray_advice(threshold: int, out) -> None:
    """Print password spraying advice based on lockout threshold."""
    if threshold == 0:
        out.success("No lockout threshold — unlimited spraying possible (be loud!)")
        return
    safe = max(1, threshold - 2)
    out.info(
        f"Lockout threshold: {threshold} attempts → "
        f"safe spray: {safe} attempt(s) per account per observation window"
    )
    if threshold <= 3:
        out.warning("Very low threshold — spray carefully (max 1 attempt per reset window)")


class PoliciesModule(BaseModule):
    name        = "policies"
    description = "Default and fine-grained password policies + spray planning"

    def run(self, ctx: ScanContext) -> None:
        out = ctx.out
        out.section("PASSWORD POLICIES")

        self._default_policy(ctx)
        self._fgpp(ctx)

    def _default_policy(self, ctx: ScanContext) -> None:
        out     = ctx.out
        entries = ctx.conn.search(
            ldap_filter="(objectClass=domain)",
            attributes=_DOMAIN_ATTRS,
            base=ctx.base_dn,
            scope=SCOPE_BASE,
        )
        if not entries:
            out.warning("Could not read domain password policy")
            return

        entry   = entries[0]
        min_len = get_int(entry, "minPwdLength")
        max_age = get_attr(entry, "maxPwdAge")
        history = get_int(entry, "pwdHistoryLength")
        lockout_threshold   = get_int(entry, "lockoutThreshold")
        lockout_duration    = get_attr(entry, "lockoutDuration")
        lockout_window      = get_attr(entry, "lockoutObservationWindow")
        pwd_props           = get_int(entry, "pwdProperties")

        out.subsection("Default Domain Password Policy")
        out.kv("Min. Password Length",    str(min_len))
        out.kv("Password History",        f"{history} passwords remembered")
        out.kv("Max. Password Age",       _interval_to_str(max_age))
        out.kv("Complexity",              _pwd_props_str(pwd_props))
        out.kv("Lockout Threshold",       str(lockout_threshold) if lockout_threshold else "0 (disabled)")
        out.kv("Lockout Duration",        _interval_to_str(lockout_duration))
        out.kv("Lockout Obs. Window",     _interval_to_str(lockout_window))

        out.subsection("Spray Planning")
        _spray_advice(lockout_threshold, out)

        if lockout_threshold == 0:
            ctx.quick_wins.add(
                Severity.HIGH,
                "No account lockout policy",
                "Unlimited password spraying / brute-force is possible without locking accounts.",
            )
        if min_len < 8:
            ctx.quick_wins.add(
                Severity.MEDIUM,
                f"Weak minimum password length ({min_len})",
                "Short passwords are easier to crack after a hash dump.",
            )
        if pwd_props & 0x01:  # complexity disabled
            ctx.quick_wins.add(
                Severity.MEDIUM,
                "Password complexity disabled",
                "Users may set simple dictionary passwords.",
            )

    def _fgpp(self, ctx: ScanContext) -> None:
        out     = ctx.out
        # FGPP lives under the Password Settings Container
        pso_base = f"CN=Password Settings Container,CN=System,{ctx.base_dn}"
        entries  = ctx.conn.search(_FGPP_FILTER, _FGPP_ATTRS, base=pso_base)

        if not entries:
            return

        out.subsection(f"Fine-Grained Password Policies ({len(entries)} PSO(s))")
        for entry in entries:
            name       = get_attr(entry, "name")
            precedence = get_int(entry, "msDS-PasswordSettingsPrecedence")
            min_len    = get_int(entry, "msDS-MinimumPasswordLength")
            threshold  = get_int(entry, "msDS-LockoutThreshold")
            duration   = get_attr(entry, "msDS-LockoutDuration")
            window     = get_attr(entry, "msDS-LockoutObservationWindow")
            max_age    = get_attr(entry, "msDS-MaximumPasswordAge")
            complexity = get_attr(entry, "msDS-PasswordComplexityEnabled")
            applies_to = get_list(entry, "msDS-PSOAppliesTo")

            print()
            out.kv("PSO Name",       f"{C.YELLOW}{name}{C.RESET}")
            out.kv("Precedence",     str(precedence))
            out.kv("Min. Length",    str(min_len))
            out.kv("Complexity",     str(complexity))
            out.kv("Max. Age",       _interval_to_str(max_age))
            out.kv("Lockout Threshold", str(threshold) if threshold else "0 (disabled)")
            out.kv("Lockout Duration",  _interval_to_str(duration))
            out.kv("Obs. Window",    _interval_to_str(window))
            if applies_to:
                out.kv("Applies To", "")
                for obj in applies_to:
                    cn = obj.split(",")[0].split("=", 1)[-1]
                    print(f"        {C.CYAN}•{C.RESET} {cn}")

            # Spray advice per PSO
            _spray_advice(threshold, out)
