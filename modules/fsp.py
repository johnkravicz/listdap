"""
Foreign Security Principals module — cross-domain / forest members of local groups.

When a principal from a *trusted* domain is added to a group here, AD materialises
a `foreignSecurityPrincipal` object under `CN=ForeignSecurityPrincipals,<domain>`
whose CN / objectSid is the foreign SID, and the group's `member` points at it.
A foreign principal that lands (directly or via nesting) in a **privileged** group
is a cross-trust escalation / persistence path most audits miss: compromise that
principal in the *other* domain and you inherit the privilege here. Because the
membership is explicit, it works regardless of SID filtering (which only governs
*extra* injected SIDs).

This module:
  * enumerates the ForeignSecurityPrincipals container (skipping the benign
    well-known SIDs AD auto-creates there);
  * for each real foreign SID, finds every group it belongs to **transitively**
    (LDAP_MATCHING_RULE_IN_CHAIN) and classifies privilege via the groups catalog;
  * resolves the **source trust** (matches the SID's domain against enumerated
    trustedDomain SIDs) and notes the trust direction / SID-filtering posture;
  * flags privileged memberships (CRITICAL/HIGH) and stale / orphan FSPs (no
    group membership → cleanup / residue).

Pure LDAP.

⚠️ NOT VALIDATED LIVE (v2.17.0): implemented and unit-tested against mocked
   records, but never run against a real DC with populated trusts / FSPs.
"""

from modules.base import BaseModule, ScanContext
from core.output import Severity, C
from utils.ldap_helpers import get_attr, get_raw, get_dn, SCOPE_ONELEVEL
from utils.sids import bytes_to_sid, resolve_sid
from modules.groups import _catalog_match
from modules.trusts import (
    _sid_filtering_off_external, TA_FOREST_TRANSITIVE, TA_WITHIN_FOREST,
)

_IN_CHAIN = "1.2.840.113556.1.4.1941"

_SEV = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM, "INFO": Severity.INFO}
_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}


def _domain_of(sid: str) -> str:
    """'S-1-5-21-a-b-c-1105' → 'S-1-5-21-a-b-c' (the issuing domain SID)."""
    return sid.rsplit("-", 1)[0] if sid.count("-") > 4 else sid


class FSPModule(BaseModule):
    name        = "fsp"
    description = "Foreign Security Principals in privileged groups (cross-trust paths)"

    def run(self, ctx: ScanContext) -> None:
        out = ctx.out
        out.section("FOREIGN SECURITY PRINCIPALS")

        base = f"CN=ForeignSecurityPrincipals,{ctx.base_dn}"
        try:
            entries = ctx.conn.search(
                "(objectClass=foreignSecurityPrincipal)",
                ["objectSid"], base=base, scope=SCOPE_ONELEVEL)
        except Exception as e:
            out.warning(f"ForeignSecurityPrincipals search failed: {e}")
            return

        dsid = ctx.domain_sid
        foreign = []   # (sid, dn)
        for e in entries:
            raw = get_raw(e, "objectSid")
            sid = bytes_to_sid(raw) if raw else ""
            # Only real external domain principals: S-1-5-21-<other domain>-<rid>.
            # Well-known SIDs AD seeds the container with (S-1-5-4/11/9/17…) and any
            # principal of THIS domain are not cross-trust members.
            if not sid.startswith("S-1-5-21-"):
                continue
            if dsid and sid.startswith(dsid + "-"):
                continue
            foreign.append((sid, get_dn(e)))

        if not foreign:
            out.success("No external Foreign Security Principals present "
                        "(only well-known / none)")
            return

        trust_map = self._trust_map(ctx)

        rows = []
        findings = []   # dict per foreign principal in a privileged group
        orphans = []
        for sid, dn in foreign:
            groups = self._groups_of(ctx, dn, dsid)      # [(sam, label, sev)]
            src = trust_map.get(_domain_of(sid))
            src_lbl = src["name"] if src else "(unknown trust)"

            if not groups:
                orphans.append((sid, src_lbl))
                continue

            priv = [g for g in groups if g[1]]            # catalog hits only
            worst = min((_SEV_ORDER[g[2]] for g in priv), default=3)
            sev = next((k for k, v in _SEV_ORDER.items() if v == worst), "INFO")
            grp_str = ", ".join(g[0] for g in groups)
            rows.append([sid, src_lbl, grp_str, sev if priv else "INFO"])
            if priv:
                findings.append({"sid": sid, "src": src, "src_lbl": src_lbl,
                                 "groups": groups, "priv": priv, "sev": sev})

        if rows:
            out.subsection("External principals & their group membership")
            out.table(["Foreign SID", "Source trust", "Member of", "Severity"],
                      rows, indent=4,
                      highlight_fn=lambda r: C.RED if r[3] == "CRITICAL"
                      else (C.YELLOW if r[3] == "HIGH" else None))

        findings.sort(key=lambda f: _SEV_ORDER[f["sev"]])
        for f in findings:
            self._emit(ctx, f)

        if orphans:
            out.subsection("Orphan / stale FSPs (no group membership)")
            out.table(["Foreign SID", "Source trust"],
                      [[s, l] for (s, l) in orphans], indent=4)
            ctx.quick_wins.add(
                Severity.INFO,
                f"{len(orphans)} orphan Foreign Security Principal(s)",
                "These external SIDs have an FSP object but no current group "
                "membership — residue of a removed cross-domain grant (cleanup / "
                "historical access indicator):\n  "
                + ", ".join(s for (s, _l) in orphans),
            )

    # ----------------------------------------------------------- trust map
    @staticmethod
    def _trust_map(ctx: ScanContext) -> dict:
        """domain SID → {name, attrs} from trustedDomain objects."""
        out = {}
        try:
            trusts = ctx.conn.search(
                "(objectClass=trustedDomain)",
                ["trustPartner", "name", "securityIdentifier", "trustAttributes"])
        except Exception:
            return out
        for t in trusts:
            raw = get_raw(t, "securityIdentifier")
            sid = bytes_to_sid(raw) if raw else ""
            if not sid:
                continue
            try:
                attrs = int(get_attr(t, "trustAttributes") or "0")
            except ValueError:
                attrs = 0
            out[sid] = {
                "name": get_attr(t, "trustPartner") or get_attr(t, "name") or sid,
                "attrs": attrs,
            }
        return out

    # --------------------------------------------------- transitive groups
    @staticmethod
    def _groups_of(ctx: ScanContext, fsp_dn: str, dsid: str):
        """Groups (transitive) an FSP belongs to → [(sam, catalog_label, sev)]."""
        if not fsp_dn:
            return []
        res = ctx.conn.search(
            f"(&(objectClass=group)(member:{_IN_CHAIN}:={fsp_dn}))",
            ["sAMAccountName", "objectSid"])
        out = []
        for g in res:
            sam = get_attr(g, "sAMAccountName") or get_dn(g)
            raw = get_raw(g, "objectSid")
            gsid = bytes_to_sid(raw) if raw else ""
            hit = _catalog_match(gsid, sam, dsid)
            if hit:
                out.append((sam, hit[0], hit[1]))     # (sam, label, severity)
            else:
                out.append((sam, "", ""))
        return out

    # ----------------------------------------------------------- quick win
    def _emit(self, ctx: ScanContext, f: dict) -> None:
        src = f["src"]
        direction = ""
        filt_note = ""
        if src:
            a = src["attrs"]
            kind = ("forest trust" if a & TA_FOREST_TRANSITIVE else
                    ("intra-forest" if a & TA_WITHIN_FOREST else "external trust"))
            direction = f" via {kind} with {f['src_lbl']}"
            if _sid_filtering_off_external(a):
                filt_note = (" SID filtering is OFF on this external trust → the "
                             "principal can additionally inject arbitrary SIDs of "
                             "this domain (see the trusts finding).")
        priv_str = "; ".join(f"{sam} [{sev}: {label}]"
                             for (sam, label, sev) in f["priv"])
        ctx.quick_wins.add(
            _SEV[f["sev"]],
            f"Foreign principal in a privileged group{direction}",
            f"The external SID {f['sid']}{direction} is a (transitive) member of "
            f"privileged group(s): {priv_str}.\n"
            "Compromising this principal in its home domain grants that privilege "
            "here — an often-overlooked cross-trust escalation / persistence path."
            + filt_note + "\n"
            f"  # resolve / audit the principal from the trusted side; its RID: "
            f"{f['sid'].rsplit('-', 1)[-1]}",
        )
