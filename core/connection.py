"""
LDAP connection wrapper — built on impacket's LDAP client.
Holds DC metadata (base DN, domain, functional levels) read from the rootDSE.
"""

from dataclasses import dataclass
from typing import Optional

from core.auth import Authenticator, AuthResult, AuthError
from utils.ldap_helpers import (
    domain_to_basedn, basedn_to_domain, ldap_search, SCOPE_SUBTREE,
)


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
# DC metadata
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


def _extract_dc_info(auth: Authenticator, host: str) -> DCInfo:
    """Build DCInfo from the rootDSE the authenticator read."""
    info = DCInfo(ip=host, hostname=host)
    rd = auth.rootdse or {}

    def _o(key: str) -> str:
        v = rd.get(key, [""])
        return v[0] if v else ""

    info.base_dn = auth.base_dn or _o("defaultNamingContext")
    info.domain  = auth.domain or basedn_to_domain(info.base_dn)
    info.config_dn    = _o("configurationNamingContext")
    info.schema_dn    = _o("schemaNamingContext")
    info.forest_dn    = _o("rootDomainNamingContext")
    info.dns_hostname = _o("dnsHostName")

    dfl = _o("domainFunctionality")
    ffl = _o("forestFunctionality")
    info.domain_func_level = _level_str(dfl) if dfl else "Unknown"
    info.forest_func_level = _level_str(ffl) if ffl else "Unknown"

    if info.dns_hostname:
        info.hostname = info.dns_hostname
    return info


# ---------------------------------------------------------------------------
# LDAPConnection
# ---------------------------------------------------------------------------

class LDAPConnection:
    """Wraps a bound impacket LDAPConnection with DC/auth metadata."""

    def __init__(self, conn, auth_result: AuthResult, dc_info: DCInfo):
        self._conn       = conn
        self.auth_result = auth_result
        self.dc_info     = dc_info

    @property
    def base_dn(self) -> str:
        return self.dc_info.base_dn

    @property
    def domain(self) -> str:
        return self.dc_info.domain

    def search(self, ldap_filter: str, attributes, base: Optional[str] = None,
               scope: str = SCOPE_SUBTREE):
        """Run a search; returns a list of record dicts (see utils.ldap_helpers)."""
        return ldap_search(self._conn, base or self.base_dn, ldap_filter,
                           list(attributes), scope)

    def raw_conn(self):
        return self._conn

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def connect(
    host:        str,
    domain:      str  = "",
    username:    str  = "",
    password:    str  = "",
    ccache:      str  = "",
    no_kerberos: bool = False,
    use_tls:     bool = False,
    port:        int  = 0,
    dc_ip:       str  = "",
) -> LDAPConnection:
    """Establish an LDAP connection using the best available auth method."""
    if port == 0:
        port = 636 if use_tls else 389

    auth = Authenticator(
        host=host, port=port, use_tls=use_tls, domain=domain,
        username=username, password=password, ccache=ccache,
        no_kerberos=no_kerberos, dc_ip=dc_ip or host,
    )
    conn, auth_result = auth.authenticate()
    dc_info = _extract_dc_info(auth, host)

    if not dc_info.base_dn and domain:
        dc_info.base_dn = domain_to_basedn(domain)
        dc_info.domain  = domain

    return LDAPConnection(conn, auth_result, dc_info)
