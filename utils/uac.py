"""
UserAccountControl (UAC) flag decoder.
Reference: https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties
"""

from typing import List

UAC_FLAGS = {
    0x00000001: "SCRIPT",
    0x00000002: "ACCOUNTDISABLE",
    0x00000008: "HOMEDIR_REQUIRED",
    0x00000010: "LOCKOUT",
    0x00000020: "PASSWD_NOTREQD",
    0x00000040: "PASSWD_CANT_CHANGE",
    0x00000080: "ENCRYPTED_TEXT_PWD_ALLOWED",
    0x00000100: "TEMP_DUPLICATE_ACCOUNT",
    0x00000200: "NORMAL_ACCOUNT",
    0x00000800: "INTERDOMAIN_TRUST_ACCOUNT",
    0x00001000: "WORKSTATION_TRUST_ACCOUNT",
    0x00002000: "SERVER_TRUST_ACCOUNT",
    0x00010000: "DONT_EXPIRE_PASSWORD",
    0x00020000: "MNS_LOGON_ACCOUNT",
    0x00040000: "SMARTCARD_REQUIRED",
    0x00080000: "TRUSTED_FOR_DELEGATION",
    0x00100000: "NOT_DELEGATED",
    0x00200000: "USE_DES_KEY_ONLY",
    0x00400000: "DONT_REQ_PREAUTH",
    0x00800000: "PASSWORD_EXPIRED",
    0x01000000: "TRUSTED_TO_AUTH_FOR_DELEGATION",
    0x04000000: "PARTIAL_SECRETS_ACCOUNT",
}

# Flags relevant to pentest — flagged with a label
PENTEST_FLAGS = {
    0x00000002: ("disabled",              "ACCOUNT_DISABLED"),
    0x00000010: ("locked",                "ACCOUNT_LOCKED"),
    0x00000020: ("passwd_notreqd",        "PASSWD_NOTREQD"),
    0x00010000: ("no_expire_pwd",         "DONT_EXPIRE_PASSWORD"),
    0x00040000: ("smartcard_required",    "SMARTCARD_REQUIRED"),
    0x00080000: ("unconstrained_deleg",   "TRUSTED_FOR_DELEGATION"),
    0x00400000: ("no_preauth",            "DONT_REQ_PREAUTH"),
    0x00800000: ("pwd_expired",           "PASSWORD_EXPIRED"),
    0x01000000: ("constrained_deleg",     "TRUSTED_TO_AUTH_FOR_DELEGATION"),
}


def decode_uac(value) -> List[str]:
    """Return a list of flag names set in the UAC value."""
    try:
        v = int(value)
    except (TypeError, ValueError):
        return []
    return [name for flag, name in UAC_FLAGS.items() if v & flag]


def uac_has(value, flag: int) -> bool:
    """Test a single UAC flag."""
    try:
        return bool(int(value) & flag)
    except (TypeError, ValueError):
        return False


# Convenience constants
UAC_DISABLED          = 0x00000002
UAC_LOCKOUT           = 0x00000010
UAC_PASSWD_NOTREQD    = 0x00000020
UAC_NO_EXPIRE_PWD     = 0x00010000
UAC_SMARTCARD         = 0x00040000
UAC_TRUSTED_DELEG     = 0x00080000   # Unconstrained delegation
UAC_NO_PREAUTH        = 0x00400000   # AS-REP roastable
UAC_PWD_EXPIRED       = 0x00800000
UAC_TRUSTED_TO_AUTH   = 0x01000000   # Constrained delegation (S4U2Proxy)
UAC_WORKSTATION       = 0x00001000
UAC_SERVER_TRUST      = 0x00002000   # Domain Controllers


def uac_summary(value) -> str:
    """Return a compact summary string of notable UAC flags for display."""
    try:
        v = int(value)
    except (TypeError, ValueError):
        return ""
    parts = []
    if v & UAC_DISABLED:        parts.append("DISABLED")
    if v & UAC_LOCKOUT:         parts.append("LOCKED")
    if v & UAC_NO_PREAUTH:      parts.append("NO_PREAUTH")
    if v & UAC_PASSWD_NOTREQD:  parts.append("PASSWD_NOTREQD")
    if v & UAC_NO_EXPIRE_PWD:   parts.append("NO_EXPIRE_PWD")
    if v & UAC_TRUSTED_DELEG:   parts.append("UNCONSTRAINED_DELEG")
    if v & UAC_TRUSTED_TO_AUTH: parts.append("CONSTRAINED_DELEG")
    if v & UAC_PWD_EXPIRED:     parts.append("PWD_EXPIRED")
    return ", ".join(parts)
