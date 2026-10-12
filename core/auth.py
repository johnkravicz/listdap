"""
Authentication strategies for LDAP connections.

Priority order (authenticated):
  1. Kerberos GSSAPI  (ccache file / KRB5CCNAME env / auto-acquired TGT)
  2. NTLM             (fallback when Kerberos fails or --no-kerberos)
  3. SIMPLE           (guest / plain bind)
  4. Anonymous

TGT acquisition (when only username+password is supplied):
  1. impacket (getTGT)
  2. subprocess kinit (fallback)
"""

import os
import subprocess
import tempfile
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple

# Suppress impacket noise
logging.getLogger("impacket").setLevel(logging.CRITICAL)

import ldap3
from ldap3 import SASL, GSSAPI, NTLM, SIMPLE, ANONYMOUS

try:
    from impacket.krb5.kerberosv5 import getKerberosTGT
    from impacket.krb5.types import Principal
    from impacket.krb5 import constants
    from impacket.krb5.asn1 import TGS_REP
    import impacket.krb5.ccache as impacket_ccache
    HAS_IMPACKET = True
except ImportError:
    HAS_IMPACKET = False


class AuthType(Enum):
    ANONYMOUS  = "Anonymous"
    SIMPLE     = "Simple (plaintext)"
    NTLM       = "NTLM"
    KERBEROS   = "Kerberos (GSSAPI)"


@dataclass
class AuthResult:
    auth_type:   AuthType
    username:    str = ""
    domain:      str = ""
    ccache_path: str = ""         # path to the ccache used (if Kerberos)
    note:        str = ""         # e.g., "TGT acquired via impacket"
    fallback_reasons: list = None # why higher-priority methods were skipped

    def __post_init__(self):
        if self.fallback_reasons is None:
            self.fallback_reasons = []


class AuthError(Exception):
    pass


# ---------------------------------------------------------------------------
# TGT acquisition
# ---------------------------------------------------------------------------

def _acquire_tgt_impacket(username: str, password: str, domain: str, dc_ip: str) -> str:
    """
    Acquire a TGT using impacket and save it to a temp ccache file.
    Returns the path to the ccache file.
    """
    if not HAS_IMPACKET:
        raise AuthError("impacket not available")

    userName = Principal(
        username,
        type=constants.PrincipalNameType.NT_PRINCIPAL.value
    )
    try:
        tgt, cipher, old_session_key, session_key = getKerberosTGT(
            userName,
            password,
            domain,
            None,  # lm hash
            None,  # nt hash
            None,  # aes key
            dc_ip,
        )
    except Exception as e:
        raise AuthError(f"impacket TGT failed: {e}")

    # Write ccache
    cc = impacket_ccache.CCache()
    cc.fromTGT(tgt, old_session_key, session_key)
    fd, ccache_path = tempfile.mkstemp(prefix="listdap_", suffix=".ccache")
    os.close(fd)
    cc.saveFile(ccache_path)
    return ccache_path


def _acquire_tgt_kinit(username: str, password: str, domain: str) -> str:
    """
    Acquire a TGT using kinit subprocess.
    Returns the path to the ccache file.
    """
    fd, ccache_path = tempfile.mkstemp(prefix="listdap_", suffix=".ccache")
    os.close(fd)

    principal = f"{username}@{domain.upper()}"
    env = os.environ.copy()
    env["KRB5CCNAME"] = ccache_path

    result = subprocess.run(
        ["kinit", principal],
        input=password.encode(),
        capture_output=True,
        env=env,
        timeout=30,
    )
    if result.returncode != 0:
        os.unlink(ccache_path)
        raise AuthError(
            f"kinit failed: {result.stderr.decode().strip() or result.stdout.decode().strip()}"
        )
    return ccache_path


def acquire_tgt(username: str, password: str, domain: str, dc_ip: str) -> Tuple[str, str]:
    """
    Try impacket first, then kinit.
    Returns (ccache_path, method_note).
    Raises AuthError if both fail.
    """
    errors = []

    if HAS_IMPACKET:
        try:
            path = _acquire_tgt_impacket(username, password, domain, dc_ip)
            return path, "TGT acquired via impacket"
        except AuthError as e:
            errors.append(str(e))

    try:
        path = _acquire_tgt_kinit(username, password, domain)
        return path, "TGT acquired via kinit"
    except (AuthError, FileNotFoundError) as e:
        errors.append(str(e))

    raise AuthError("TGT acquisition failed:\n  " + "\n  ".join(errors))


# ---------------------------------------------------------------------------
# ldap3 server / connection factory
# ---------------------------------------------------------------------------

def make_server(host: str, port: int, use_tls: bool) -> ldap3.Server:
    if use_tls:
        tls = ldap3.Tls(validate=0)  # no cert validation for pentest
        return ldap3.Server(host, port=port, use_ssl=True, tls=tls, get_info=ldap3.ALL)
    return ldap3.Server(host, port=port, use_ssl=False, get_info=ldap3.ALL)


# ---------------------------------------------------------------------------
# Authentication strategies
# ---------------------------------------------------------------------------

def _write_krb5_conf(domain: str, kdc_ip: str) -> str:
    """
    Write a minimal krb5.conf for the given domain/KDC and return its path.
    This is required because MIT Kerberos (GSSAPI) ignores /etc/hosts and
    needs an explicit realm → KDC mapping.
    """
    realm = domain.upper()
    content = f"""[libdefaults]
    default_realm = {realm}
    dns_lookup_realm = false
    dns_lookup_kdc = false
    forwardable = true
    rdns = false

[realms]
    {realm} = {{
        kdc = {kdc_ip}
        admin_server = {kdc_ip}
    }}

[domain_realm]
    {domain.lower()} = {realm}
    .{domain.lower()} = {realm}
"""
    fd, path = tempfile.mkstemp(prefix="listdap_krb5_", suffix=".conf")
    os.close(fd)
    with open(path, "w") as f:
        f.write(content)
    return path


def _try_kerberos(
    server: ldap3.Server,
    ccache_path: str,
    domain: str = "",
    kdc_ip: str = "",
    fqdn: str = "",
) -> ldap3.Connection:
    """
    Attempt Kerberos GSSAPI bind using the given ccache file.

    - A temporary krb5.conf is generated so MIT Kerberos resolves the KDC
      without relying on DNS SRV records or a pre-existing /etc/krb5.conf.
    - If fqdn is provided, the GSSAPI bind uses it as the server hostname
      so the SPN (ldap/<fqdn>@REALM) is correctly resolved. Connecting to
      an IP directly would fail because the SPN is registered against the FQDN.
    """
    saved_env = {
        "KRB5CCNAME":  os.environ.get("KRB5CCNAME"),
        "KRB5_CONFIG": os.environ.get("KRB5_CONFIG"),
    }
    krb5_conf_path = None

    try:
        os.environ["KRB5CCNAME"] = ccache_path

        if domain and kdc_ip:
            krb5_conf_path = _write_krb5_conf(domain, kdc_ip)
            os.environ["KRB5_CONFIG"] = krb5_conf_path

        # Use FQDN as server hostname so GSSAPI constructs the correct SPN.
        # The original server object may use an IP; create a new one with FQDN.
        bind_server = server
        if fqdn and fqdn != server.host:
            bind_server = ldap3.Server(
                fqdn,
                port=server.port,
                use_ssl=server.ssl,
                tls=server.tls,
                get_info=ldap3.ALL,
            )

        conn = ldap3.Connection(
            bind_server,
            authentication=SASL,
            sasl_mechanism=GSSAPI,
            auto_bind=ldap3.AUTO_BIND_NO_TLS,
        )
        if not conn.bind():
            raise AuthError(f"Kerberos bind failed: {conn.result}")
        return conn
    except Exception as e:
        raise AuthError(f"Kerberos GSSAPI failed: {e}")
    finally:
        for key, val in saved_env.items():
            if val is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = val
        if krb5_conf_path and os.path.exists(krb5_conf_path):
            os.unlink(krb5_conf_path)


def _try_ntlm(
    server: ldap3.Server, username: str, password: str, domain: str
) -> ldap3.Connection:
    """Attempt NTLM bind."""
    user = f"{domain}\\{username}" if domain else username
    try:
        conn = ldap3.Connection(
            server,
            user=user,
            password=password,
            authentication=NTLM,
            auto_bind=ldap3.AUTO_BIND_NO_TLS,
        )
        if not conn.bind():
            raise AuthError(f"NTLM bind failed: {conn.result}")
        return conn
    except ldap3.core.exceptions.LDAPException as e:
        raise AuthError(f"NTLM failed: {e}")


def _try_simple(
    server: ldap3.Server, username: str, password: str
) -> ldap3.Connection:
    """Attempt simple (plaintext) bind."""
    try:
        conn = ldap3.Connection(
            server,
            user=username,
            password=password,
            authentication=SIMPLE,
            auto_bind=ldap3.AUTO_BIND_NO_TLS,
        )
        if not conn.bind():
            raise AuthError(f"Simple bind failed: {conn.result}")
        return conn
    except ldap3.core.exceptions.LDAPException as e:
        raise AuthError(f"Simple bind failed: {e}")


def _try_anonymous(server: ldap3.Server) -> ldap3.Connection:
    """Attempt anonymous bind."""
    try:
        conn = ldap3.Connection(
            server,
            authentication=ANONYMOUS,
            auto_bind=ldap3.AUTO_BIND_NO_TLS,
        )
        if not conn.bind():
            raise AuthError(f"Anonymous bind failed: {conn.result}")
        return conn
    except ldap3.core.exceptions.LDAPException as e:
        raise AuthError(f"Anonymous bind failed: {e}")


# ---------------------------------------------------------------------------
# Domain discovery (anonymous rootDSE read)
# ---------------------------------------------------------------------------

def _discover_domain(server: ldap3.Server) -> tuple:
    """
    Perform a minimal anonymous bind to read the rootDSE.
    Returns (domain, fqdn) e.g. ('corp.local', 'dc01.corp.local').
    Both values may be empty strings on failure.
    """
    from utils.ldap_helpers import basedn_to_domain
    try:
        conn = ldap3.Connection(
            server,
            authentication=ANONYMOUS,
            auto_bind=ldap3.AUTO_BIND_NO_TLS,
        )
        conn.bind()
        if server.info and hasattr(server.info, "other") and server.info.other:
            other = server.info.other
            domain = ""
            fqdn   = ""
            dnc_list = other.get("defaultNamingContext", [])
            if dnc_list:
                domain = basedn_to_domain(str(dnc_list[0]))
            dns_list = other.get("dnsHostName", [])
            if dns_list:
                fqdn = str(dns_list[0])
            conn.unbind()
            return domain, fqdn
        conn.unbind()
    except Exception:
        pass
    return "", ""


# ---------------------------------------------------------------------------
# Main authenticator
# ---------------------------------------------------------------------------

class Authenticator:
    """
    Orchestrates authentication attempts based on provided credentials.
    """

    def __init__(
        self,
        host:        str,
        port:        int,
        use_tls:     bool,
        domain:      str      = "",
        username:    str      = "",
        password:    str      = "",
        ccache:      str      = "",      # explicit --ccache path
        no_kerberos: bool     = False,
        dc_ip:       str      = "",      # used for TGT acquisition
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
        self.dc_fqdn     = ""   # filled during domain discovery

    def authenticate(self) -> Tuple[ldap3.Connection, AuthResult]:
        """
        Try authentication strategies in order.
        Returns (connection, AuthResult).
        Raises AuthError if all strategies fail.
        """
        server   = make_server(self.host, self.port, self.use_tls)
        errors   = []    # all failures accumulated
        krb_skip = []    # reasons Kerberos was not attempted / failed

        has_creds = bool(self.username)

        # ---- Domain discovery ----
        # Always discover the FQDN (needed for Kerberos SPN).
        # Also discover the domain if not provided by the user.
        discovered_domain, discovered_fqdn = _discover_domain(server)
        if has_creds and not self.domain and discovered_domain:
            self.domain = discovered_domain
        if discovered_fqdn:
            self.dc_fqdn = discovered_fqdn

        # ---- Kerberos path ----
        if has_creds and self.no_kerberos:
            krb_skip.append("Kerberos disabled by --no-kerberos")
        elif has_creds:
            ccache_path, note = self._resolve_ccache(errors)
            if ccache_path:
                try:
                    conn = _try_kerberos(server, ccache_path, self.domain, self.dc_ip,
                                         fqdn=self.dc_fqdn)
                    return conn, AuthResult(
                        auth_type=AuthType.KERBEROS,
                        username=self.username,
                        domain=self.domain,
                        ccache_path=ccache_path,
                        note=note,
                    )
                except AuthError as e:
                    krb_skip.append(f"Kerberos GSSAPI bind failed: {e}")
                    errors.append(str(e))
            else:
                # _resolve_ccache collected the specific reasons in errors
                krb_skip.extend(
                    e for e in errors
                    if e not in krb_skip
                )

        # ---- NTLM / SIMPLE (plaintext or TLS per --ldaps) ----
        if has_creds:
            res = self._creds_bind(server, krb_skip, errors)
            if res:
                return res
            # ldap3 cannot sign/seal a plaintext LDAP bind, so a DC that
            # ENFORCES LDAP signing rejects NTLM/SIMPLE on 389. TLS provides the
            # required integrity, so transparently retry over LDAPS (636).
            if not self.use_tls:
                try:
                    tls_server = make_server(self.host, 636, True)
                    res = self._creds_bind(
                        tls_server, krb_skip, errors,
                        note="escalated to LDAPS — plaintext bind rejected "
                             "(DC likely enforces LDAP signing)",
                    )
                    if res:
                        return res
                except Exception as e:
                    errors.append(f"LDAPS escalation failed: {e}")

        # ---- Anonymous (last resort) ----
        try:
            conn = _try_anonymous(server)
            reasons = []
            if has_creds:
                reasons = [
                    "Authenticated bind failed with the supplied credentials.",
                    "If the creds are correct, the DC likely enforces LDAP "
                    "signing/channel binding — ldap3 cannot sign plaintext LDAP.",
                    "Retry with --ldaps, or use Kerberos (impacket-getTGT + --ccache).",
                ]
            return conn, AuthResult(auth_type=AuthType.ANONYMOUS,
                                    fallback_reasons=reasons)
        except AuthError as e:
            errors.append(str(e))

        raise AuthError(
            "All authentication strategies failed:\n  " + "\n  ".join(errors)
        )

    def _creds_bind(self, server, krb_skip, errors, note=""):
        """Try NTLM then SIMPLE against `server`; return (conn, AuthResult) or None."""
        try:
            conn = _try_ntlm(server, self.username, self.password, self.domain)
            return conn, AuthResult(
                auth_type=AuthType.NTLM,
                username=self.username,
                domain=self.domain,
                fallback_reasons=list(krb_skip),
                note=note,
            )
        except AuthError as e:
            errors.append(str(e))
        if self.password:
            try:
                conn = _try_simple(server, self.username, self.password)
                return conn, AuthResult(
                    auth_type=AuthType.SIMPLE,
                    username=self.username,
                    note=note,
                )
            except AuthError as e:
                errors.append(str(e))
        return None

    def _resolve_ccache(self, errors: list) -> Tuple[str, str]:
        """
        Determine which ccache to use.
        Returns (ccache_path, note) or ("", "") if unavailable.
        """
        # 1. Explicit --ccache argument
        if self.ccache:
            if os.path.exists(self.ccache):
                return self.ccache, "ccache from --ccache"
            errors.append(f"ccache file not found: {self.ccache}")
            return "", ""

        # 2. KRB5CCNAME environment variable
        env_ccache = os.environ.get("KRB5CCNAME", "")
        if env_ccache:
            # Strip file: prefix if present
            path = env_ccache.removeprefix("FILE:")
            if os.path.exists(path):
                return path, "ccache from $KRB5CCNAME"
            # Could be a directory cache or kernel — pass as-is
            return env_ccache, "ccache from $KRB5CCNAME"

        # 3. Auto-acquire TGT if username+password provided
        if self.username and self.password and self.domain:
            try:
                path, note = acquire_tgt(self.username, self.password, self.domain, self.dc_ip)
                return path, note
            except AuthError as e:
                errors.append(str(e))
                return "", ""

        return "", ""
