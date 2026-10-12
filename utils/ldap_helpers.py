"""
Common LDAP query helpers — thin wrappers around ldap3.
"""

from typing import List, Optional, Dict, Any
import ldap3
from ldap3.protocol.microsoft import security_descriptor_control

# OWNER (1) + GROUP (2) + DACL (4). SACL (8) is intentionally excluded: reading
# it requires SeSecurityPrivilege, and requesting it as a low-priv user makes
# the DC return the security descriptor without the DACL. Without this control
# the DACL comes back empty for non-admins, breaking ACL-based checks
# (ESC1/2/3 enrollment rights, ESC4/ESC7 dangerous ACLs, DCSync).
_SD_FLAGS_OWNER_GROUP_DACL = 0x07


def _first(entry, attr: str, default=None):
    """Extract first value of an ldap3 attribute, or default."""
    try:
        v = entry[attr].value
        if isinstance(v, list):
            return v[0] if v else default
        return v if v is not None else default
    except Exception:
        return default


def _all_values(entry, attr: str) -> list:
    """Extract all values of an ldap3 attribute as a list."""
    try:
        v = entry[attr].value
        if isinstance(v, list):
            return v
        return [v] if v is not None else []
    except Exception:
        return []


def ldap_search(
    conn: ldap3.Connection,
    base: str,
    ldap_filter: str,
    attributes: List[str],
    scope=ldap3.SUBTREE,
) -> List[Any]:
    """
    Perform an LDAP search and return a list of entries.
    Handles errors gracefully — returns [] on failure.
    """
    # When a security descriptor is requested, attach the SD_FLAGS control so a
    # non-admin actually receives the DACL (see _SD_FLAGS_OWNER_GROUP_DACL).
    controls = None
    if any(a.lower() == "ntsecuritydescriptor" for a in attributes):
        controls = security_descriptor_control(sdflags=_SD_FLAGS_OWNER_GROUP_DACL)

    try:
        conn.search(
            search_base=base,
            search_filter=ldap_filter,
            search_scope=scope,
            attributes=attributes,
            controls=controls,
        )
        return list(conn.entries)
    except ldap3.core.exceptions.LDAPOperationResult as e:
        return []
    except Exception:
        return []


def get_attr(entry, attr: str, default="") -> str:
    """Get a string attribute from an ldap3 entry."""
    v = _first(entry, attr, default)
    return str(v) if v not in (None, default) else str(default)


def get_int(entry, attr: str, default: int = 0) -> int:
    """Get an integer attribute from an ldap3 entry."""
    try:
        return int(_first(entry, attr, default))
    except (TypeError, ValueError):
        return default


def get_list(entry, attr: str) -> List[str]:
    """Get a multi-valued attribute as a list of strings."""
    return [str(v) for v in _all_values(entry, attr) if v is not None]


def get_dn(entry) -> str:
    """Get the distinguished name of an entry."""
    try:
        return entry.entry_dn
    except Exception:
        return ""


def domain_to_basedn(domain: str) -> str:
    """Convert 'corp.local' → 'DC=corp,DC=local'."""
    return ",".join(f"DC={part}" for part in domain.split("."))


def basedn_to_domain(base_dn: str) -> str:
    """Convert 'DC=corp,DC=local' → 'corp.local'."""
    parts = []
    for component in base_dn.split(","):
        component = component.strip()
        if component.upper().startswith("DC="):
            parts.append(component[3:])
    return ".".join(parts)


def escape_filter_chars(s: str) -> str:
    """Escape special characters in an LDAP filter value (RFC 4515)."""
    replacements = {
        "\\": "\\5c",
        "*":  "\\2a",
        "(":  "\\28",
        ")":  "\\29",
        "\0": "\\00",
    }
    for char, escaped in replacements.items():
        s = s.replace(char, escaped)
    return s
