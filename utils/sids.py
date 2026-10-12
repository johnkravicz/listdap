"""
Well-known SID resolution and SID utilities.
"""

import re

# Well-known SIDs (static, no DC query needed)
WELL_KNOWN_SIDS = {
    "S-1-0-0":   "Null Authority",
    "S-1-1-0":   "Everyone",
    "S-1-2-0":   "Local",
    "S-1-3-0":   "Creator Owner",
    "S-1-3-1":   "Creator Group",
    "S-1-5-1":   "Dialup",
    "S-1-5-2":   "Network",
    "S-1-5-3":   "Batch",
    "S-1-5-4":   "Interactive",
    "S-1-5-6":   "Service",
    "S-1-5-7":   "Anonymous",
    "S-1-5-9":   "Enterprise Domain Controllers",
    "S-1-5-10":  "Self",
    "S-1-5-11":  "Authenticated Users",
    "S-1-5-12":  "Restricted Code",
    "S-1-5-13":  "Terminal Server Users",
    "S-1-5-14":  "Remote Interactive Logon",
    "S-1-5-15":  "This Organization",
    "S-1-5-17":  "IUSR",
    "S-1-5-18":  "Local System",
    "S-1-5-19":  "Local Service",
    "S-1-5-20":  "Network Service",
    "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-32-545": "BUILTIN\\Users",
    "S-1-5-32-546": "BUILTIN\\Guests",
    "S-1-5-32-547": "BUILTIN\\Power Users",
    "S-1-5-32-548": "BUILTIN\\Account Operators",
    "S-1-5-32-549": "BUILTIN\\Server Operators",
    "S-1-5-32-550": "BUILTIN\\Print Operators",
    "S-1-5-32-551": "BUILTIN\\Backup Operators",
    "S-1-5-32-552": "BUILTIN\\Replicators",
    "S-1-5-32-554": "BUILTIN\\Pre-Windows 2000 Compatible Access",
    "S-1-5-32-555": "BUILTIN\\Remote Desktop Users",
    "S-1-5-32-556": "BUILTIN\\Network Configuration Operators",
    "S-1-5-32-558": "BUILTIN\\Performance Monitor Users",
    "S-1-5-32-559": "BUILTIN\\Performance Log Users",
    "S-1-5-32-562": "BUILTIN\\Distributed COM Users",
    "S-1-5-32-568": "BUILTIN\\IIS_IUSRS",
    "S-1-5-32-569": "BUILTIN\\Cryptographic Operators",
    "S-1-5-32-573": "BUILTIN\\Event Log Readers",
    "S-1-5-32-574": "BUILTIN\\Certificate Service DCOM Access",
    "S-1-5-32-575": "BUILTIN\\RDS Remote Access Servers",
    "S-1-5-32-576": "BUILTIN\\RDS Endpoint Servers",
    "S-1-5-32-579": "BUILTIN\\Access Control Assistance Operators",
    "S-1-5-32-580": "BUILTIN\\Remote Management Users",
}

# Relative identifiers for domain SIDs (appended to domain SID)
DOMAIN_RELATIVE_SIDS = {
    "500": "Administrator",
    "501": "Guest",
    "502": "KRBTGT",
    "512": "Domain Admins",
    "513": "Domain Users",
    "514": "Domain Guests",
    "515": "Domain Computers",
    "516": "Domain Controllers",
    "517": "Cert Publishers",
    "518": "Schema Admins",
    "519": "Enterprise Admins",
    "520": "Group Policy Creator Owners",
    "521": "Read-Only Domain Controllers",
    "522": "Cloneable Domain Controllers",
    "525": "Protected Users",
    "526": "Key Admins",
    "527": "Enterprise Key Admins",
    "553": "RAS and IAS Servers",
    "571": "Allowed RODC Password Replication Group",
    "572": "Denied RODC Password Replication Group",
}

# High-value groups by RID (used for highlighting)
HIGH_VALUE_RIDS = {"512", "518", "519", "526", "527"}
# High-value builtin groups
HIGH_VALUE_BUILTIN = {
    "S-1-5-32-544",  # Administrators
    "S-1-5-32-548",  # Account Operators
    "S-1-5-32-549",  # Server Operators
    "S-1-5-32-550",  # Print Operators
    "S-1-5-32-551",  # Backup Operators
}


# Optional LDAP-backed resolver for SIDs not covered by the static tables
# (custom users/groups, e.g. service accounts at RID >= 1000). Installed once
# at scan start via set_sid_resolver(); results are cached (including misses).
_sid_resolver = None          # callable(sid: str) -> Optional[str]
_sid_cache: Dict[str, str] = {}


def set_sid_resolver(fn) -> None:
    """Install a callable(sid) -> name|None used as a fallback in resolve_sid."""
    global _sid_resolver
    _sid_resolver = fn


def clear_sid_cache() -> None:
    _sid_cache.clear()


# Already-privileged principals whose control / replication rights are expected
# by default (so they are not "findings"). Shared by the ACL-based checks in
# acls.py (DCSync, sensitive objects) and adcs.py (ESC4/ESC7).
PRIVILEGED_RIDS = {
    "498",  # Enterprise Read-only Domain Controllers
    "500",  # Administrator
    "502",  # krbtgt
    "512",  # Domain Admins
    "516",  # Domain Controllers
    "518",  # Schema Admins
    "519",  # Enterprise Admins
    "520",  # Group Policy Creator Owners
    "521",  # Read-only Domain Controllers
}
PRIVILEGED_WELL_KNOWN = {
    "S-1-5-32-544",  # BUILTIN\Administrators
    "S-1-5-32-548",  # Account Operators
    "S-1-5-32-549",  # Server Operators
    "S-1-5-32-550",  # Print Operators
    "S-1-5-32-551",  # Backup Operators
    "S-1-5-9",       # Enterprise Domain Controllers
    "S-1-5-18",      # Local System
}


def is_privileged_sid(sid: str, domain_sid: str = "") -> bool:
    """True if the SID is an already-privileged principal.

    Such principals legitimately hold DCSync / object-control rights, so ACL
    checks skip them and only report the same right held by a non-privileged
    principal (which is the actual escalation).
    """
    if sid in PRIVILEGED_WELL_KNOWN:
        return True
    if domain_sid and sid.startswith(domain_sid + "-"):
        return sid[len(domain_sid) + 1:] in PRIVILEGED_RIDS
    return False


def resolve_sid(sid: str, domain_sid: str = "") -> str:
    """Resolve a SID string to a human-readable name.

    Order: static well-known SIDs → domain-relative well-known RIDs → optional
    LDAP lookup (sAMAccountName) → raw SID. LDAP results are cached.
    """
    if not sid:
        return sid

    # Static well-known SIDs
    if sid in WELL_KNOWN_SIDS:
        return WELL_KNOWN_SIDS[sid]

    # Domain-relative SID (well-known RIDs: 500, 512, 513, …)
    if domain_sid and sid.startswith(domain_sid + "-"):
        rid = sid[len(domain_sid) + 1:]
        if rid in DOMAIN_RELATIVE_SIDS:
            return DOMAIN_RELATIVE_SIDS[rid]

    # LDAP fallback for custom principals
    if sid in _sid_cache:
        return _sid_cache[sid]
    if _sid_resolver is not None:
        name = None
        try:
            name = _sid_resolver(sid)
        except Exception:
            name = None
        _sid_cache[sid] = name or sid   # cache misses as the raw SID too
        return _sid_cache[sid]

    return sid


def sid_string_to_bytes(sid: str) -> bytes:
    """Convert a string SID (S-1-5-21-…-1000) to its binary form."""
    parts = sid.split("-")
    revision  = int(parts[1])
    authority = int(parts[2])
    sub_auths = [int(p) for p in parts[3:]]
    out = bytes([revision, len(sub_auths)])
    out += authority.to_bytes(6, byteorder="big")
    for sa in sub_auths:
        out += sa.to_bytes(4, byteorder="little")
    return out


def sid_to_ldap_filter(sid: str) -> str:
    """Escape a string SID for use in an LDAP filter: (objectSid=\\01\\05…)."""
    return "".join(f"\\{b:02x}" for b in sid_string_to_bytes(sid))


def make_ldap_sid_resolver(conn):
    """Build a resolver closure that looks up a SID's sAMAccountName over LDAP.

    `conn` is an LDAPConnection (duck-typed: .search(filter, attrs, base=…),
    .base_dn, .domain). Returns "DOMAIN\\name" when found, else None.
    """
    base_dn = getattr(conn, "base_dn", "") or ""
    domain  = getattr(conn, "domain", "") or ""

    from utils.ldap_helpers import get_attr, SCOPE_BASE

    def _resolve(sid: str):
        # Bind by the AD SID DN form: impacket's filter compiler mangles binary
        # (objectSid=\xx..) values (it UTF-8 re-encodes high bytes), so a
        # base-scope read of "<SID=...>" is the reliable way to resolve a SID.
        try:
            entries = conn.search("(objectClass=*)", ["sAMAccountName"],
                                  base=f"<SID={sid}>", scope=SCOPE_BASE)
        except Exception:
            return None
        if not entries:
            return None
        sam = get_attr(entries[0], "sAMAccountName")
        if not sam:
            return None
        return f"{domain}\\{sam}" if domain else sam

    return _resolve


def bytes_to_sid(raw: bytes) -> str:
    """Convert a binary SID (bytes) to its string representation."""
    if not raw or len(raw) < 8:
        return ""
    revision     = raw[0]
    sub_count    = raw[1]
    authority    = int.from_bytes(raw[2:8], byteorder="big")
    sub_auths    = []
    for i in range(sub_count):
        offset = 8 + i * 4
        if offset + 4 > len(raw):
            break
        sub_auths.append(int.from_bytes(raw[offset:offset+4], byteorder="little"))
    return f"S-{revision}-{authority}-" + "-".join(str(s) for s in sub_auths)


def is_high_value_sid(sid: str, domain_sid: str = "") -> bool:
    """Return True if the SID belongs to a high-value group."""
    if sid in HIGH_VALUE_BUILTIN:
        return True
    if domain_sid and sid.startswith(domain_sid + "-"):
        rid = sid[len(domain_sid) + 1:]
        return rid in HIGH_VALUE_RIDS
    return False
