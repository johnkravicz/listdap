"""
sIDHistory module — accounts carrying SIDs in their sIDHistory attribute.

sIDHistory is a legitimate migration mechanism: when an account moves between
domains, its old SID is appended here so it keeps access to resources ACL'd to
the old identity. Offensively it is two things:

* **Stealth privilege / persistence.** A SID written into sIDHistory is injected
  into the account's token at logon exactly like a group membership — without the
  account appearing in any group. A *privileged* SID (Domain Admins, Administrators,
  Enterprise Admins, RID 500/512/519 …) in sIDHistory makes the account
  effectively Domain Admin while looking unprivileged. This is the classic
  mimikatz/DCShadow `sid-history` persistence IOC → CRITICAL.
* **Cross-domain / forest reach.** A sIDHistory SID from a *foreign* domain is a
  migration artifact or a SID-history-injection across a trust (relevant where
  SID filtering is not enforced) → HIGH.

Pure LDAP: sIDHistory is a multi-valued binary (array of SIDs), readable by any
authenticated user. No writes, no RPC.

⚠️ NOT VALIDATED LIVE (v2.7.0): implemented and unit-tested against mocked
   records, but never run against a real DC carrying populated sIDHistory.
"""

from modules.base import BaseModule, ScanContext
from core.output import Severity, C
from utils.ldap_helpers import get_attr, get_list, get_raw_all, get_dn
from utils.sids import (
    resolve_sid, bytes_to_sid, is_privileged_sid, is_high_value_sid,
    privileged_rid_of,
)

_FILTER = "(sIDHistory=*)"

_ATTRS = [
    "sAMAccountName", "objectClass", "objectSid", "sIDHistory",
    "memberOf", "adminCount", "userAccountControl",
]


def _obj_type(classes) -> str:
    cl = [c.lower() for c in classes]
    if "computer" in cl:
        return "computer"
    if "group" in cl:
        return "group"
    if "trusteddomain" in cl:
        return "trust"
    if "user" in cl:
        return "user"
    return cl[-1] if cl else "?"


def _is_foreign(sid: str, domain_sid: str) -> bool:
    """A full domain-account SID (S-1-5-21-…-RID) not from the current domain.

    Built-in / well-known SIDs (S-1-5-32-*, short S-1-5-x) are NOT 'foreign' —
    they are classified by privilege instead.
    """
    if not sid.startswith("S-1-5-21-"):
        return False
    if domain_sid and sid.startswith(domain_sid + "-"):
        return False
    return True


class SIDHistoryModule(BaseModule):
    name        = "sidhistory"
    description = "Accounts with sIDHistory (stealth privilege / persistence, cross-domain)"

    def run(self, ctx: ScanContext) -> None:
        out = ctx.out
        out.section("sIDHistory")

        try:
            entries = ctx.conn.search(_FILTER, _ATTRS)
        except Exception as e:
            out.warning(f"sIDHistory search failed: {e}")
            return

        if not entries:
            out.success("No accounts with sIDHistory set")
            return

        dsid = ctx.domain_sid
        rows          = []
        priv_find     = []   # (account, type, sid, name) — privileged in THIS domain
        fgn_priv_find = []   # (account, type, sid, name) — foreign SID w/ privileged RID
        fgn_find      = []   # (account, type, sid, name) — plain foreign SID

        for e in entries:
            sam  = get_attr(e, "sAMAccountName") or get_dn(e)
            typ  = _obj_type(get_list(e, "objectClass"))
            for raw in get_raw_all(e, "sIDHistory"):
                sid = bytes_to_sid(raw)
                if not sid:
                    continue
                name = resolve_sid(sid, dsid)
                priv = is_privileged_sid(sid, dsid) or is_high_value_sid(sid, dsid)
                fgn  = _is_foreign(sid, dsid)

                if priv:
                    flag = f"{C.RED}[PRIV]{C.RESET}"
                    priv_find.append((sam, typ, sid, name))
                elif fgn and privileged_rid_of(sid):
                    # Foreign SID whose RID is privileged (e.g. another domain's
                    # -512/-519): privileged in its own domain → cross-forest
                    # SID-history injection, more severe than a plain migration.
                    flag = f"{C.RED}[FOREIGN-PRIV]{C.RESET}"
                    fgn_priv_find.append((sam, typ, sid, name))
                elif fgn:
                    flag = f"{C.YELLOW}[FOREIGN]{C.RESET}"
                    fgn_find.append((sam, typ, sid, name))
                else:
                    flag = f"{C.GREY}migration{C.RESET}"
                rows.append([sam, typ, sid, name if name != sid else "-", flag])

        out.counter("Objects with sIDHistory", len(entries),
                    {"privileged SID": len(priv_find),
                     "foreign privileged SID": len(fgn_priv_find),
                     "foreign SID": len(fgn_find)})
        out.table(["Account", "Type", "sIDHistory SID", "Resolved", "Flag"],
                  rows, indent=4)

        # ---- Quick Wins ----
        if priv_find:
            lines = [f"  - {acct} ({typ}) carries {name or sid}  [{sid}]"
                     for (acct, typ, sid, name) in priv_find]
            ctx.quick_wins.add(
                Severity.CRITICAL,
                f"sIDHistory — {len(priv_find)} account(s) hold a PRIVILEGED SID",
                "A privileged SID in sIDHistory is injected into the token at logon "
                "like a group membership — the account is effectively privileged "
                "while appearing unprivileged (mimikatz/DCShadow sid-history "
                "persistence IOC). Anyone who controls the account inherits that "
                "privilege:\n" + "\n".join(lines) + "\n"
                "  # e.g. if you control one of these, you can DCSync:\n"
                f"  impacket-secretsdump '{self._cp_target(ctx)}' -just-dc",
            )
        if fgn_priv_find:
            lines = [f"  - {acct} ({typ}) carries foreign PRIVILEGED {name or sid}  [{sid}]"
                     for (acct, typ, sid, name) in fgn_priv_find]
            ctx.quick_wins.add(
                Severity.CRITICAL,
                f"sIDHistory — {len(fgn_priv_find)} account(s) hold a FOREIGN PRIVILEGED SID",
                "These sIDHistory SIDs are privileged in another domain (RID "
                "500/512/519/518/516…). That is the signature of a cross-forest "
                "SID-history injection: where SID filtering / quarantine is not "
                "enforced on the trust, the account wields that foreign domain's "
                "privilege. Verify the trust's SID filtering (see the trusts "
                "module) and the legitimacy of the migration:\n" + "\n".join(lines),
            )
        if fgn_find:
            lines = [f"  - {acct} ({typ}) carries foreign {name or sid}  [{sid}]"
                     for (acct, typ, sid, name) in fgn_find]
            ctx.quick_wins.add(
                Severity.HIGH,
                f"sIDHistory — {len(fgn_find)} account(s) hold a FOREIGN-domain SID",
                "A sIDHistory SID from another domain is a cross-domain migration "
                "artifact or a SID-history injection across a trust (impactful where "
                "SID filtering / quarantine is not enforced on the trust):\n"
                + "\n".join(lines),
            )

    @staticmethod
    def _cp_target(ctx) -> str:
        a = ctx.args
        user   = (getattr(a, "username", "") or "").split("@")[0]
        domain = ctx.domain or (getattr(a, "domain", "") or "")
        dc     = getattr(a, "dc", "") or ""
        up     = f"{domain}/{user}" if domain else user
        return f"{up}@{dc}"
