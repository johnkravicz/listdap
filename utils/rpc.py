"""
DCE/RPC enumeration over SMB named pipes (and the endpoint mapper).

listdap is LDAP-first; this module is the opportunistic RPC complement. It is
what makes listdap useful against DCs where the anonymous/authenticated LDAP
bind can read the rootDSE but not the directory objects (RestrictAnonymous on
the LDAP side), while SAMR/LSAT over SMB still leak users, groups and policy.

Transport mirrors utils/ca_rrp.py: an impacket DCE/RPC transport over \\pipe,
reusing the same credentials as the LDAP side (password, pass-the-hash
LM:NT, or a Kerberos ccache). Authentication precedence per connection:
  1. Kerberos (ccache / $KRB5CCNAME) when requested and available
  2. NTLM with password or NT hash (pass-the-hash)
  3. Null session (empty user + empty password)

⚠️ Gotcha (validated live): a *null* SMB3 session is rejected with
STATUS_INVALID_PARAMETER unless a non-empty domain is supplied in the
credentials. impacket's samrdump works because it passes the domain; a bare
set_credentials('', '', '', ...) does not. We always thread the discovered
domain (e.g. "shadow.gate") into the null bind.

Every pipe degrades gracefully: a bind failure or STATUS_ACCESS_DENIED is
returned as a reason string, never raised past the collector, so one blocked
pipe (common: LSAT null denied while SAMR null allowed) does not abort the rest.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Tuple
import os


# ---------------------------------------------------------------------------
# Connection parameters (derived from the live session / args)
# ---------------------------------------------------------------------------

@dataclass
class RpcParams:
    dc_ip:     str
    domain:    str = ""
    dc_fqdn:   str = ""
    username:  str = ""
    password:  str = ""
    lmhash:    str = ""
    nthash:    str = ""
    ccache:    str = ""
    kerberos:  bool = False          # prefer Kerberos (ccache) for the bind
    timeout:   int = 6

    @property
    def is_null(self) -> bool:
        """True when no usable secret is present → attempt a null session."""
        return not (self.password or self.nthash or self.ccache or self.kerberos)


def params_from_ctx(ctx) -> RpcParams:
    """Build RpcParams from a ScanContext (reuses the LDAP-side credentials)."""
    a = ctx.args
    dc_info = ctx.conn.dc_info
    user = (getattr(a, "username", "") or "").split("@")[0]
    ccache = getattr(a, "ccache", "") or os.environ.get("KRB5CCNAME", "")
    # Domain for the SMB bind: prefer the discovered NetBIOS/DNS domain.
    domain = ctx.domain or (getattr(a, "domain", "") or "")
    return RpcParams(
        dc_ip=getattr(a, "dc", "") or dc_info.ip,
        domain=domain,
        dc_fqdn=getattr(dc_info, "dns_hostname", "") or getattr(dc_info, "hostname", ""),
        username=user,
        password=getattr(a, "password", "") or "",
        lmhash=getattr(a, "lmhash", "") or "",
        nthash=getattr(a, "nthash", "") or "",
        ccache=ccache,
        kerberos=bool(ccache) and not getattr(a, "no_kerberos", False),
    )


# ---------------------------------------------------------------------------
# DCE/RPC transport factory
# ---------------------------------------------------------------------------

def connect_pipe(p: RpcParams, pipe: str, uuid, port: int = 445):
    """Open and bind a DCE/RPC interface over an SMB named pipe.

    Returns (dce, None) on success or (None, reason) on failure. `pipe` is the
    bare name (e.g. "samr"), `uuid` the MSRPC interface UUID.
    """
    try:
        from impacket.dcerpc.v5 import transport
    except Exception as e:  # pragma: no cover
        return None, f"impacket unavailable ({e})"

    remote = p.dc_fqdn if p.kerberos and p.dc_fqdn else p.dc_ip
    stringbinding = r"ncacn_np:%s[\pipe\%s]" % (remote, pipe)
    try:
        rt = transport.DCERPCTransportFactory(stringbinding)
        rt.set_dport(port)
        rt.setRemoteHost(p.dc_ip)          # socket always targets the DC IP
        try:
            rt.set_connect_timeout(p.timeout)
        except Exception:
            pass
        if hasattr(rt, "set_credentials"):
            # NB: domain MUST be non-empty even for a null session (see header).
            rt.set_credentials(
                p.username, p.password, p.domain or "WORKGROUP",
                p.lmhash, p.nthash, None,
            )
        if p.kerberos:
            if p.ccache:
                os.environ["KRB5CCNAME"] = p.ccache
            rt.set_kerberos(True, p.dc_ip)
        dce = rt.get_dce_rpc()
        dce.connect()
        dce.bind(uuid)
        return dce, None
    except Exception as e:
        return None, _reason(e)


def _reason(e: Exception) -> str:
    s = str(e)
    for code, label in (
        ("STATUS_ACCESS_DENIED", "access denied"),
        ("STATUS_LOGON_FAILURE", "logon failure (bad creds)"),
        ("STATUS_ACCOUNT_DISABLED", "account disabled"),
        ("rpc_s_access_denied", "access denied"),
        ("STATUS_INVALID_PARAMETER", "invalid parameter (null session refused?)"),
    ):
        if code in s:
            return f"{label} ({code})"
    return s


# ---------------------------------------------------------------------------
# SAMR — users, groups, aliases, domain password policy
# ---------------------------------------------------------------------------

@dataclass
class SamrUser:
    rid:   int
    name:  str
    uac:   int = 0
    description: str = ""
    pwd_last_set: str = ""


def samr_flag_summary(uac: int) -> str:
    """Decode SAMR USER_* account-control bits (NOT the LDAP UAC layout).

    SAMR exposes its own flag set via SamrQueryInformationUser; the bit values
    differ from the directory's userAccountControl, so this cannot reuse
    utils/uac.py. Only pentest-relevant flags are surfaced.
    """
    from impacket.dcerpc.v5 import samr
    checks = [
        (samr.USER_ACCOUNT_DISABLED,        "DISABLED"),
        (samr.USER_PASSWORD_NOT_REQUIRED,   "PASSWD_NOTREQD"),
        (samr.USER_DONT_EXPIRE_PASSWORD,    "NO_EXPIRE_PWD"),
        (samr.USER_ACCOUNT_AUTO_LOCKED,     "LOCKED"),
        (getattr(samr, "USER_DONT_REQUIRE_PREAUTH", 0x10000), "NO_PREAUTH"),
        (getattr(samr, "USER_TRUSTED_FOR_DELEGATION", 0x80000), "UNCONSTRAINED_DELEG"),
    ]
    return ", ".join(name for bit, name in checks if bit and (uac & bit))


@dataclass
class SamrDomainPolicy:
    min_length:   Optional[int] = None
    history:      Optional[int] = None
    max_age_days: Optional[float] = None
    min_age_days: Optional[float] = None
    lockout_threshold: Optional[int] = None
    complexity:   Optional[bool] = None


@dataclass
class SamrResult:
    feasible:  bool = False
    auth_kind: str = ""              # "null" | "authenticated" | "kerberos"
    reason:    str = ""
    domains:   List[str] = field(default_factory=list)
    users:     List[SamrUser] = field(default_factory=list)
    groups:    List[Tuple[int, str]] = field(default_factory=list)
    aliases:   List[Tuple[int, str]] = field(default_factory=list)
    policy:    Optional[SamrDomainPolicy] = None


def _filetime_to_days(ft) -> Optional[float]:
    """SAMR negative-FILETIME duration (100ns ticks) → days, or None if 'never'."""
    try:
        val = (ft["HighPart"] << 32) + (ft["LowPart"] & 0xFFFFFFFF)
    except Exception:
        return None
    # durations are stored as negative values; 0 or min-int means "never"
    if val == 0:
        return 0.0
    # two's complement to signed 64-bit
    if val >= 0x8000000000000000:
        val -= 0x10000000000000000
    secs = abs(val) / 1e7
    if secs >= 3.15e9:   # ~ "never" (close to max)
        return None
    return round(secs / 86400, 1)


def samr_enumerate(p: RpcParams) -> SamrResult:
    """Enumerate users, groups, aliases and the password policy over \\samr."""
    from impacket.dcerpc.v5 import samr
    from impacket.dcerpc.v5.rpcrt import DCERPCException

    res = SamrResult()
    dce, reason = connect_pipe(p, "samr", samr.MSRPC_UUID_SAMR)
    if dce is None:
        res.reason = reason
        return res
    res.feasible = True
    res.auth_kind = ("kerberos" if p.kerberos else
                     "authenticated" if not p.is_null else "null")
    try:
        sh = samr.hSamrConnect(dce)["ServerHandle"]
        domains = samr.hSamrEnumerateDomainsInSamServer(dce, sh)["Buffer"]["Buffer"]
        res.domains = [d["Name"] for d in domains]
        # The first domain is the account domain (skip "Builtin" for users).
        account_domain = res.domains[0] if res.domains else None
        if account_domain is None:
            return res

        sid = samr.hSamrLookupDomainInSamServer(dce, sh, account_domain)["DomainId"]
        dh = samr.hSamrOpenDomain(dce, serverHandle=sh, domainId=sid)["DomainHandle"]

        _samr_users(dce, dh, res)
        _samr_policy(dce, dh, res)
        res.groups = _samr_enum(dce, dh, samr.hSamrEnumerateGroupsInDomain)
        res.aliases = _samr_enum(dce, dh, samr.hSamrEnumerateAliasesInDomain)
    except DCERPCException as e:
        res.reason = _reason(e)
    except Exception as e:
        res.reason = _reason(e)
    finally:
        try:
            dce.disconnect()
        except Exception:
            pass
    return res


def _samr_enum(dce, dh, fn) -> List[Tuple[int, str]]:
    """Generic paged RID/name enumeration (groups, aliases)."""
    from impacket.dcerpc.v5 import samr
    out, ctx, status = [], 0, 0x105  # STATUS_MORE_ENTRIES
    while status == 0x105:
        try:
            r = fn(dce, dh, enumerationContext=ctx)
        except Exception as e:
            if "STATUS_MORE_ENTRIES" not in str(e):
                break
            r = e.get_packet()
        for e in r["Buffer"]["Buffer"]:
            out.append((e["RelativeId"], e["Name"]))
        ctx = r["EnumerationContext"]
        status = r["ErrorCode"]
    return out


def _samr_users(dce, dh, res: SamrResult) -> None:
    """Enumerate users, then fetch per-user detail (UAC, description, pwd set)."""
    from impacket.dcerpc.v5 import samr
    from impacket.dcerpc.v5.samr import USER_INFORMATION_CLASS

    raw, ctx, status = [], 0, 0x105
    while status == 0x105:
        try:
            r = samr.hSamrEnumerateUsersInDomain(dce, dh, enumerationContext=ctx)
        except Exception as e:
            if "STATUS_MORE_ENTRIES" not in str(e):
                break
            r = e.get_packet()
        for e in r["Buffer"]["Buffer"]:
            raw.append((e["RelativeId"], e["Name"]))
        ctx = r["EnumerationContext"]
        status = r["ErrorCode"]

    for rid, name in raw:
        u = SamrUser(rid=rid, name=name)
        try:
            oh = samr.hSamrOpenUser(dce, dh, userId=rid)["UserHandle"]
            info = samr.hSamrQueryInformationUser2(
                dce, oh, USER_INFORMATION_CLASS.UserAllInformation
            )["Buffer"]["All"]
            u.uac = int(info["UserAccountControl"])
            u.description = str(info["AdminComment"]) or str(info["UserComment"])
            pls = info["PasswordLastSet"]
            ft = (pls["HighPart"] << 32) + pls["LowPart"]
            u.pwd_last_set = "<never>" if ft == 0 else _samr_time(ft)
            samr.hSamrCloseHandle(dce, oh)
        except Exception:
            pass
        res.users.append(u)


def _samr_time(filetime: int) -> str:
    from datetime import datetime, timezone
    try:
        secs = filetime / 1e7 - 11644473600
        return datetime.fromtimestamp(secs, tz=timezone.utc).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return "unknown"


def _samr_policy(dce, dh, res: SamrResult) -> None:
    from impacket.dcerpc.v5 import samr
    pol = SamrDomainPolicy()
    try:
        info = samr.hSamrQueryInformationDomain2(
            dce, dh, samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation
        )["Buffer"]["Password"]
        pol.min_length = int(info["MinPasswordLength"])
        pol.history = int(info["PasswordHistoryLength"])
        pol.max_age_days = _filetime_to_days(info["MaxPasswordAge"])
        pol.min_age_days = _filetime_to_days(info["MinPasswordAge"])
        # DOMAIN_PASSWORD_COMPLEX = 0x1
        pol.complexity = bool(int(info["PasswordProperties"]) & 0x1)
    except Exception:
        pass
    try:
        lock = samr.hSamrQueryInformationDomain2(
            dce, dh, samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation
        )["Buffer"]["Lockout"]
        pol.lockout_threshold = int(lock["LockoutThreshold"])
    except Exception:
        pass
    res.policy = pol


# ---------------------------------------------------------------------------
# LSAT / LSARPC — policy, domain SID, trusts, SID lookups, RID cycling
# ---------------------------------------------------------------------------

@dataclass
class LsaResult:
    feasible:    bool = False
    auth_kind:   str = ""
    reason:      str = ""
    server_role: str = ""
    domain:      str = ""
    domain_sid:  str = ""
    whoami:      str = ""
    trusts:      List[Tuple[str, str]] = field(default_factory=list)   # (name, sid)
    principals:  List[Tuple[int, str, str]] = field(default_factory=list)  # (rid, name, kind)


_SID_TYPE = {
    1: "user", 2: "group", 3: "domain", 4: "alias",
    5: "well-known", 6: "deleted", 7: "invalid", 8: "unknown",
}


def lsa_enumerate(p: RpcParams, rid_ranges=None) -> LsaResult:
    """Query the LSA policy and, if possible, RID-cycle principals over \\lsarpc.

    rid_ranges defaults to the common pentest ranges (built-ins + custom RIDs).
    RID cycling is the fallback that enumerates principals when SAMR is blocked
    but LSAT name lookups are allowed (the two pipes carry independent ACLs).
    """
    from impacket.dcerpc.v5 import lsat, lsad
    from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED, RPC_SID

    if rid_ranges is None:
        rid_ranges = [(500, 550), (1000, 1500)]

    res = LsaResult()
    dce, reason = connect_pipe(p, "lsarpc", lsat.MSRPC_UUID_LSAT)
    if dce is None:
        res.reason = reason
        return res
    res.feasible = True
    res.auth_kind = ("kerberos" if p.kerberos else
                     "authenticated" if not p.is_null else "null")
    try:
        ph = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED)["PolicyHandle"]

        # Account domain name + SID
        try:
            ad = lsad.hLsarQueryInformationPolicy2(
                dce, ph, lsad.POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation
            )["PolicyInformation"]["PolicyAccountDomainInfo"]
            res.domain = str(ad["DomainName"])
            res.domain_sid = ad["DomainSid"].formatCanonical()
        except Exception as e:
            res.reason = res.reason or _reason(e)

        # Trusted domains
        try:
            td = lsad.hLsarEnumerateTrustedDomainsEx(dce, ph)
            for info in td["EnumerationBuffer"]["EnumerationBuffer"]:
                res.trusts.append((str(info["FlatName"]),
                                   info["Sid"].formatCanonical()))
        except Exception:
            pass

        # RID cycling against the account domain SID
        if res.domain_sid:
            res.principals = _lsa_rid_cycle(dce, ph, res.domain_sid, rid_ranges)
            # who-am-i: RID 500 translation already covered; the current user is
            # whatever the session authenticated as.
            if p.username:
                res.whoami = f"{res.domain}\\{p.username}" if res.domain else p.username
    except Exception as e:
        res.reason = res.reason or _reason(e)
    finally:
        try:
            dce.disconnect()
        except Exception:
            pass
    return res


def _lsa_rid_cycle(dce, ph, domain_sid, rid_ranges) -> List[Tuple[int, str, str]]:
    from impacket.dcerpc.v5 import lsat
    from impacket.dcerpc.v5.dtypes import RPC_SID

    found = []
    rids = [r for lo, hi in rid_ranges for r in range(lo, hi + 1)]
    # Batch lookups (impacket accepts a list of SIDs per call)
    for i in range(0, len(rids), 200):
        batch = rids[i:i + 200]
        sids = []
        for rid in batch:
            s = RPC_SID()
            s.fromCanonical(f"{domain_sid}-{rid}")
            sids.append(s)
        try:
            resp = lsat.hLsarLookupSids(
                dce, ph, sids, lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta
            )
        except Exception as e:
            # STATUS_SOME_NOT_MAPPED still carries the mapped entries
            if "STATUS_SOME_NOT_MAPPED" not in str(e) and "STATUS_NONE_MAPPED" not in str(e):
                break
            try:
                resp = e.get_packet()
            except Exception:
                continue
        try:
            names = resp["TranslatedNames"]["Names"]
            domains = resp["ReferencedDomains"]["Domains"]
        except Exception:
            continue
        for rid, tn in zip(batch, names):
            use = int(tn["Use"])
            if use in (7, 8):   # SidTypeInvalid / SidTypeUnknown → not present
                continue
            name = str(tn["Name"])
            if name:
                found.append((rid, name, _SID_TYPE.get(use, "?")))
    return found


# ---------------------------------------------------------------------------
# SRVSVC — shares and sessions
# ---------------------------------------------------------------------------

@dataclass
class SrvResult:
    feasible: bool = False
    reason:   str = ""
    shares:   List[Tuple[str, str, str]] = field(default_factory=list)  # (name, type, remark)
    sessions: List[Tuple[str, str]] = field(default_factory=list)       # (client, user)


_SHARE_TYPE = {0: "disk", 1: "print", 2: "device", 3: "ipc"}


def srvsvc_enumerate(p: RpcParams) -> SrvResult:
    from impacket.dcerpc.v5 import srvs

    res = SrvResult()
    dce, reason = connect_pipe(p, "srvsvc", srvs.MSRPC_UUID_SRVS)
    if dce is None:
        res.reason = reason
        return res
    res.feasible = True
    try:
        resp = srvs.hNetrShareEnum(dce, 1)
        for sh in resp["InfoStruct"]["ShareInfo"]["Level1"]["Buffer"]:
            stype = int(sh["shi1_type"]) & 0x0FFFFFFF
            res.shares.append((
                str(sh["shi1_netname"]).rstrip("\x00"),
                _SHARE_TYPE.get(stype, str(stype)),
                str(sh["shi1_remark"]).rstrip("\x00"),
            ))
    except Exception as e:
        res.reason = _reason(e)
    try:
        resp = srvs.hNetrSessionEnum(dce, None, None, 10)
        for s in resp["InfoStruct"]["SessionInfo"]["Level10"]["Buffer"]:
            res.sessions.append((
                str(s["sesi10_cname"]).rstrip("\x00"),
                str(s["sesi10_username"]).rstrip("\x00"),
            ))
    except Exception:
        pass
    try:
        dce.disconnect()
    except Exception:
        pass
    return res


# ---------------------------------------------------------------------------
# WKSSVC — logged-on users, workstation info
# ---------------------------------------------------------------------------

@dataclass
class WkstResult:
    feasible:   bool = False
    reason:     str = ""
    logged_on:  List[str] = field(default_factory=list)   # DOMAIN\user
    info:       str = ""


def wkssvc_enumerate(p: RpcParams) -> WkstResult:
    from impacket.dcerpc.v5 import wkst

    res = WkstResult()
    dce, reason = connect_pipe(p, "wkssvc", wkst.MSRPC_UUID_WKST)
    if dce is None:
        res.reason = reason
        return res
    res.feasible = True
    try:
        resp = wkst.hNetrWkstaUserEnum(dce, 1)
        seen = set()
        for u in resp["UserInfo"]["WkstaUserInfo"]["Level1"]["Buffer"]:
            dom = str(u["wkui1_logon_domain"]).rstrip("\x00")
            usr = str(u["wkui1_username"]).rstrip("\x00")
            key = f"{dom}\\{usr}"
            if usr and key not in seen:
                seen.add(key)
                res.logged_on.append(key)
    except Exception as e:
        res.reason = _reason(e)
    try:
        dce.disconnect()
    except Exception:
        pass
    return res


# ---------------------------------------------------------------------------
# EPM — endpoint mapper dump (RPC attack-surface recon, over ncacn_ip_tcp:135)
# ---------------------------------------------------------------------------

@dataclass
class EpmResult:
    feasible:  bool = False
    reason:    str = ""
    endpoints: List[Tuple[str, str]] = field(default_factory=list)  # (binding, annotation)


def epm_dump(p: RpcParams) -> EpmResult:
    from impacket.dcerpc.v5 import epm

    res = EpmResult()
    try:
        entries = epm.hept_lookup(p.dc_ip)
    except Exception as e:
        res.reason = _reason(e)
        return res
    res.feasible = True
    for entry in entries:
        try:
            tower = entry["tower"]["Floors"]
            binding = epm.PrintStringBinding(entry["tower"]["Floors"])
            annotation = entry["annotation"][:-1].decode("latin-1", "replace") \
                if entry["annotation"] else ""
            res.endpoints.append((binding, annotation))
        except Exception:
            continue
    return res
