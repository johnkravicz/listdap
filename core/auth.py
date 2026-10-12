"""
Authentication — built on impacket's LDAP client.

Priority order (each on a fresh connection):
  1. Kerberos via an explicit ccache / $KRB5CCNAME
  2. NTLM (GSS-SPNEGO, signed+sealed — works against signing-enforcing DCs)
  3. Kerberos from username+password (impacket derives AES; no gssapi/krb5.conf)
  4. SIMPLE bind (username + password)
  5. Anonymous (last resort; rootDSE only)

Unlike the previous ldap3 backend, impacket negotiates LDAP signing, so DCs that
enforce signing/channel binding authenticate normally. No system MIT Kerberos,
no gssapi, no temporary krb5.conf, no SPN-canonicalisation workarounds.
"""

import os
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple

from impacket.ldap import ldap as _ldap, ldapasn1 as _asn1

from utils.ldap_helpers import basedn_to_domain


class AuthType(Enum):
    KERBEROS  = "Kerberos"
    NTLM      = "NTLM"
    SIMPLE    = "SIMPLE"
    ANONYMOUS = "Anonymous"


@dataclass
class AuthResult:
    auth_type:   AuthType
    username:    str = ""
    domain:      str = ""
    ccache_path: str = ""
    note:        str = ""
    fallback_reasons: list = None

    def __post_init__(self):
        if self.fallback_reasons is None:
            self.fallback_reasons = []


class AuthError(Exception):
    pass


# ---------------------------------------------------------------------------
# rootDSE discovery (anonymous)
# ---------------------------------------------------------------------------

_ROOTDSE_ATTRS = [
    "defaultNamingContext", "configurationNamingContext", "schemaNamingContext",
    "rootDomainNamingContext", "dnsHostName", "domainFunctionality",
    "forestFunctionality",
]


def read_rootdse(conn) -> dict:
    """Read the rootDSE as {attr: [str, ...]} (works pre-authentication)."""
    try:
        resp = conn.search(
            searchBase="", scope=_asn1.Scope("baseObject"),
            searchFilter="(objectClass=*)", attributes=_ROOTDSE_ATTRS,
        )
    except Exception:
        return {}
    out = {}
    for item in resp:
        if not isinstance(item, _asn1.SearchResultEntry):
            continue
        for a in item["attributes"]:
            out[str(a["type"])] = [bytes(v).decode("utf-8", "replace") for v in a["vals"]]
    return out


# ---------------------------------------------------------------------------
# Authenticator
# ---------------------------------------------------------------------------

class Authenticator:
    def __init__(
        self,
        host:        str,
        port:        int,
        use_tls:     bool,
        domain:      str = "",
        username:    str = "",
        password:    str = "",
        ccache:      str = "",
        no_kerberos: bool = False,
        dc_ip:       str = "",
    ):
        self.host        = host
        self.port        = port
        self.use_tls     = use_tls
        self.domain      = domain
        self.username    = username
        self.password    = password
        self.ccache      = ccache
        self.no_kerberos = no_kerberos
        self.dc_ip       = dc_ip or host

        # Populated during authenticate()
        self.base_dn  = ""
        self.dc_fqdn  = ""
        self.rootdse  = {}

    # -- connection factory --------------------------------------------------
    def _new_conn(self, host: str = ""):
        """Build an impacket LDAPConnection.

        The URL host becomes the Kerberos target (SPN ldap/<host>), while the
        socket always connects to dc_ip. For Kerberos we pass the DC FQDN so the
        SPN is ldap/<fqdn> (ldap/<ip> is not in the KDC); the socket still hits
        dc_ip, so the FQDN need not resolve locally.
        """
        h = host or self.host
        scheme = "ldaps" if self.use_tls else "ldap"
        default = 636 if self.use_tls else 389
        hostport = h if self.port in (0, default) else f"{h}:{self.port}"
        return _ldap.LDAPConnection(f"{scheme}://{hostport}", self.base_dn, self.dc_ip)

    # -- discovery -----------------------------------------------------------
    def _discover(self):
        try:
            conn = self._new_conn()
        except Exception:
            return
        self.rootdse = read_rootdse(conn)
        dnc = (self.rootdse.get("defaultNamingContext") or [""])[0]
        if dnc:
            self.base_dn = dnc
            if not self.domain:
                self.domain = basedn_to_domain(dnc)
        fqdn = (self.rootdse.get("dnsHostName") or [""])[0]
        if fqdn:
            self.dc_fqdn = fqdn
        try:
            conn.close()
        except Exception:
            pass

    # -- auth strategies -----------------------------------------------------
    def authenticate(self) -> Tuple[object, AuthResult]:
        errors: List[str] = []
        krb_skip: List[str] = []

        self._discover()
        if not self.base_dn and self.domain:
            from utils.ldap_helpers import domain_to_basedn
            self.base_dn = domain_to_basedn(self.domain)

        has_creds = bool(self.username)
        ccache = self.ccache or os.environ.get("KRB5CCNAME", "")

        # 1. Kerberos via explicit ccache / $KRB5CCNAME
        if has_creds and not self.no_kerberos and ccache:
            if self.ccache:
                os.environ["KRB5CCNAME"] = self.ccache
            try:
                conn = self._kerberos_bind(use_cache=True)
                return conn, AuthResult(AuthType.KERBEROS, self.username, self.domain,
                                        ccache_path=ccache, note="ccache / $KRB5CCNAME")
            except Exception as e:
                krb_skip.append(f"Kerberos (ccache) failed: {e}")
                errors.append(str(e))

        # 2. NTLM (signed)
        if has_creds and self.password:
            try:
                conn = self._ntlm_bind()
                return conn, AuthResult(AuthType.NTLM, self.username, self.domain,
                                        note="GSS-SPNEGO, signed",
                                        fallback_reasons=krb_skip)
            except Exception as e:
                errors.append(f"NTLM failed: {e}")

        # 3. Kerberos from username + password (impacket derives AES)
        if has_creds and self.password and not self.no_kerberos:
            try:
                conn = self._kerberos_bind(use_cache=False)
                return conn, AuthResult(AuthType.KERBEROS, self.username, self.domain,
                                        note="TGT acquired via impacket (AES)")
            except Exception as e:
                errors.append(f"Kerberos (password) failed: {e}")

        # 4. SIMPLE bind
        if has_creds and self.password:
            try:
                conn = self._simple_bind()
                return conn, AuthResult(AuthType.SIMPLE, self.username, self.domain)
            except Exception as e:
                errors.append(f"SIMPLE failed: {e}")

        # 5. Anonymous (unbound connection — rootDSE only)
        try:
            conn = self._new_conn()
            reasons = []
            if has_creds:
                reasons = [
                    "Authenticated bind failed with the supplied credentials — "
                    "check the username/password/domain.",
                ] + [f"[attempt] {e}" for e in errors]
            return conn, AuthResult(AuthType.ANONYMOUS, fallback_reasons=reasons)
        except Exception as e:
            errors.append(f"Anonymous failed: {e}")

        raise AuthError("All authentication strategies failed:\n  " + "\n  ".join(errors))

    # -- binds ---------------------------------------------------------------
    def _ntlm_bind(self):
        conn = self._new_conn()
        conn.login(self.username, self.password, self.domain)  # GSS-SPNEGO, signed
        return conn

    def _simple_bind(self):
        conn = self._new_conn()
        conn.login(self.username, self.password, self.domain,
                   authenticationChoice="simple")
        return conn

    def _kerberos_bind(self, use_cache: bool):
        # Target the DC FQDN so the requested SPN is ldap/<fqdn> (not ldap/<ip>).
        conn = self._new_conn(host=self.dc_fqdn or self.host)
        conn.kerberosLogin(
            self.username,
            "" if use_cache else self.password,
            self.domain,
            kdcHost=self.dc_ip,
            useCache=use_cache,
        )
        return conn
