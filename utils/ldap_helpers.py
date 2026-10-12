"""
Common LDAP query helpers — built on impacket's LDAP client.

A search returns a list of *records*. A record is a plain dict:
    { "_dn": "<distinguishedName>", "<attr-lowercased>": [b"val", ...], ... }

Attribute names are lowercased; values are kept as raw bytes. The get_* helpers
decode them on demand (str / int / list), and get_raw* returns the bytes
(used for binary attributes: objectSid, nTSecurityDescriptor, …).
"""

from typing import List, Optional, Dict, Any

from impacket.ldap import ldap as _ldap, ldapasn1 as _asn1

# Scope identifiers used by callers (strings — no ldap3 dependency).
SCOPE_BASE     = "base"
SCOPE_ONELEVEL = "onelevel"
SCOPE_SUBTREE  = "subtree"

_SCOPE_MAP = {
    SCOPE_BASE:     "baseObject",
    SCOPE_ONELEVEL: "singleLevel",
    SCOPE_SUBTREE:  "wholeSubtree",
}

# OWNER (1) + GROUP (2) + DACL (4). SACL (8) is excluded: reading it needs
# SeSecurityPrivilege, and requesting it as a low-priv user makes the DC return
# the SD without the DACL. Without this control the DACL comes back empty for
# non-admins, breaking ACL-based checks (ESC1/2/3 enrollment, ESC4/ESC7, DCSync).
_SD_FLAGS_OWNER_GROUP_DACL = 0x07


# ---------------------------------------------------------------------------
# Record parsing
# ---------------------------------------------------------------------------

def _parse_entries(resp) -> List[Dict[str, Any]]:
    records = []
    for item in resp or []:
        if not isinstance(item, _asn1.SearchResultEntry):
            continue
        rec: Dict[str, Any] = {"_dn": str(item["objectName"])}
        for attribute in item["attributes"]:
            name = str(attribute["type"]).lower()
            rec[name] = [bytes(v) for v in attribute["vals"]]
        records.append(rec)
    return records


def ldap_search(
    conn,
    base: str,
    ldap_filter: str,
    attributes: List[str],
    scope: str = SCOPE_SUBTREE,
) -> List[Dict[str, Any]]:
    """Run an LDAP search via impacket; return a list of records ([] on error).

    - Attaches the SD_FLAGS control when a security descriptor is requested so a
      non-admin actually receives the DACL.
    - Pages subtree/one-level searches so large containers are not truncated.
    """
    controls = []
    if any(a.lower() == "ntsecuritydescriptor" for a in attributes):
        controls.append(_asn1.SDFlagsControl(
            criticality=True, flags=_SD_FLAGS_OWNER_GROUP_DACL))
    if scope != SCOPE_BASE:
        controls.append(_ldap.SimplePagedResultsControl(criticality=True, size=1000))

    scope_obj = _asn1.Scope(_SCOPE_MAP.get(scope, "wholeSubtree"))

    try:
        resp = conn.search(
            searchBase=base,
            scope=scope_obj,
            searchFilter=ldap_filter,
            attributes=attributes,
            searchControls=controls or None,
        )
        return _parse_entries(resp)
    except _ldap.LDAPSearchError as e:
        # impacket attaches partial results to the exception for some errors
        return _parse_entries(getattr(e, "answers", None))
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Attribute accessors (operate on a record dict)
# ---------------------------------------------------------------------------

def _decode(v: bytes) -> str:
    try:
        return v.decode("utf-8")
    except Exception:
        return v.decode("latin-1", "replace")


def get_attr(rec, attr: str, default: str = "") -> str:
    """First value of an attribute as a decoded string, or default."""
    try:
        vals = rec.get(attr.lower())
        if vals:
            return _decode(vals[0])
    except Exception:
        pass
    return default


def get_int(rec, attr: str, default: int = 0) -> int:
    try:
        return int(get_attr(rec, attr, str(default)))
    except (TypeError, ValueError):
        return default


def get_list(rec, attr: str) -> List[str]:
    try:
        return [_decode(v) for v in rec.get(attr.lower(), [])]
    except Exception:
        return []


def get_raw(rec, attr: str) -> Optional[bytes]:
    """First value of an attribute as raw bytes (binary attrs), or None."""
    try:
        vals = rec.get(attr.lower())
        if vals:
            return vals[0]
    except Exception:
        pass
    return None


def get_raw_all(rec, attr: str) -> List[bytes]:
    """All values of an attribute as raw bytes."""
    try:
        return list(rec.get(attr.lower(), []))
    except Exception:
        return []


def get_dn(rec) -> str:
    try:
        return rec.get("_dn", "")
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# DN / domain helpers (unchanged)
# ---------------------------------------------------------------------------

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
