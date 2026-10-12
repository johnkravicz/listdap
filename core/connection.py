"""
LDAP connection wrapper — built on top of ldap3.
Handles server info extraction (base DN, domain, DC version, functional levels).
"""

from dataclasses import dataclass, field
from typing import Optional, List
import ldap3

from core.auth import Authenticator, AuthResult, AuthError
from utils.ldap_helpers import domain_to_basedn, basedn_to_domain, ldap_search, get_attr


# ---------------------------------------------------------------------------
# Functional level mapping
# ---------------------------------------------------------------------------

FUNCTIONAL_LEVELS = {
    0: "Windows 2000",
    1: "Windows Server 2003 Interim",
    2: "Windows Server 2003",
    3: "Windows Server 2008",
    4: "Windows Server 2008 R2",
    5: "Windows Server 2012",
    6: "Windows Server 2012 R2",
    7: "Windows Server 2016 / 2019 / 2022",
}


def _level_str(value) -> str:
    try:
        return FUNCTIONAL_LEVELS.get(int(value), f"Unknown ({value})")
    except (TypeError, ValueError):
        return "Unknown"


# ---------------------------------------------------------------------------
# Server info
# ---------------------------------------------------------------------------

@dataclass
class DCInfo:
    hostname:           str = ""
    ip:                 str = ""
    base_dn:            str = ""
    domain:             str = ""
    forest_dn:          str = ""
    dns_hostname:       str = ""
    domain_func_level:  str = ""
    forest_func_level:  str = ""
    schema_dn:          str = ""
    config_dn:          str = ""
    domain_sid:         str = ""
    # FSMO roles — filled in by the domain module
    pdc_emulator:       str = ""
    rid_master:         str = ""
    infra_master:       str = ""
    schema_master:      str = ""
    domain_naming_master: str = ""


def _extract_dc_info(server: ldap3.Server, host: str) -> DCInfo:
    """Parse the rootDSE to extract DC metadata."""
    info = DCInfo(ip=host, hostname=host)

    if server.info is None:
        return info

    si = server.info

    # Build 'other' dict first — si.other is a CaseInsensitiveDict({key: [val, ...]})
    other = {}
    if hasattr(si, "other") and si.other:
        other = dict(si.other)

    def _o(key):
        v = other.get(key, [""])
        if isinstance(v, list):
            return str(v[0]) if v else ""
        return str(v) if v else ""

    # Naming contexts
    ncs = getattr(si, "naming_contexts", None) or []
    ncs = [str(nc) for nc in ncs]

    # Default naming context (domain base DN)
    dnc = _o("defaultNamingContext")
    if not dnc and ncs:
        # Heuristic: shortest non-CN= NC is usually the domain partition
        domain_ncs = [nc for nc in ncs if not nc.startswith("CN=")]
        dnc = min(domain_ncs, key=len) if domain_ncs else ncs[0]

    info.base_dn = str(dnc)
    info.domain  = basedn_to_domain(info.base_dn)

    info.schema_dn       = _o("schemaNamingContext")
    info.config_dn       = _o("configurationNamingContext")
    info.forest_dn       = _o("rootDomainNamingContext")
    info.dns_hostname    = _o("dnsHostName")

    try:
        info.domain_func_level = _level_str(int(_o("domainFunctionality")))
    except (ValueError, TypeError):
        info.domain_func_level = _o("domainFunctionality") or "Unknown"

    try:
        info.forest_func_level = _level_str(int(_o("forestFunctionality")))
    except (ValueError, TypeError):
        info.forest_func_level = _o("forestFunctionality") or "Unknown"

    if info.dns_hostname:
        info.hostname = info.dns_hostname

    return info


# ---------------------------------------------------------------------------
# LDAPConnection
# ---------------------------------------------------------------------------

class LDAPConnection:
    """
    Wraps an ldap3 Connection with metadata about the DC and auth used.
    """

    def __init__(
        self,
        conn:        ldap3.Connection,
        auth_result: AuthResult,
        dc_info:     DCInfo,
    ):
        self._conn       = conn
        self.auth_result = auth_result
        self.dc_info     = dc_info

    @property
    def base_dn(self) -> str:
        return self.dc_info.base_dn

    @property
    def domain(self) -> str:
        return self.dc_info.domain

    def search(
        self,
        ldap_filter:  str,
        attributes:   List[str],
        base:         Optional[str] = None,
        scope=ldap3.SUBTREE,
    ) -> List:
        """Run a search and return ldap3 entries."""
        return ldap_search(
            self._conn,
            base or self.base_dn,
            ldap_filter,
            attributes,
            scope=scope,
        )

    def raw_conn(self) -> ldap3.Connection:
        return self._conn

    def close(self) -> None:
        try:
            self._conn.unbind()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def connect(
    host:        str,
    domain:      str      = "",
    username:    str      = "",
    password:    str      = "",
    ccache:      str      = "",
    no_kerberos: bool     = False,
    use_tls:     bool     = False,
    port:        int      = 0,
    dc_ip:       str      = "",
) -> LDAPConnection:
    """
    Establish an LDAP connection using the best available auth method.
    Returns an LDAPConnection ready to use.
    Raises AuthError on complete failure.
    """
    if port == 0:
        port = 636 if use_tls else 389

    auth = Authenticator(
        host=host,
        port=port,
        use_tls=use_tls,
        domain=domain,
        username=username,
        password=password,
        ccache=ccache,
        no_kerberos=no_kerberos,
        dc_ip=dc_ip or host,
    )

    conn, auth_result = auth.authenticate()
    dc_info = _extract_dc_info(conn.server, host)

    # If domain not parsed from rootDSE but provided by user, fill it in
    if not dc_info.base_dn and domain:
        dc_info.base_dn = domain_to_basedn(domain)
        dc_info.domain  = domain

    return LDAPConnection(conn, auth_result, dc_info)
