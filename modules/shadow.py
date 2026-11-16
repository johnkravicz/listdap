"""
Shadow Credentials module — msDS-KeyCredentialLink analysis.

A populated msDS-KeyCredentialLink lets the holder of the matching private key
authenticate (PKINIT) as the target account and recover its NT hash. It is both a
legitimate mechanism (Windows Hello for Business device keys) and a favourite
**persistence / escalation backdoor** (Whisker / pyWhisker / Shadow Credentials,
and certificate-based RBCD). Telling them apart needs more than a presence flag,
so this module:

* parses the KEYCREDENTIALLINK_BLOB (utils.keycred) → key id, creation time,
  device id, usage/source — the **creation time** is the tell for a planted key;
* scores each object by target sensitivity: a key on krbtgt / a DC / an
  adminCount=1 or privileged-group account → CRITICAL IOC; on a computer account
  → HIGH (RBCD / shadow-cred artifact, uncommon otherwise); on a plain user →
  MEDIUM (likely WHfB — verify the device/time against enrollment).

Pure LDAP.

⚠️ NOT VALIDATED LIVE (v2.18.0): blob parsing + scoring unit-tested against
   synthetic blobs; not run against a real DC with populated keys.
"""

from modules.base import BaseModule, ScanContext
from core.output import Severity, C
from utils.ldap_helpers import get_attr, get_int, get_list, get_dn
from utils.keycred import parse_key_credentials
from utils.uac import uac_has, UAC_SERVER_TRUST
from modules.users import _is_priv_member

_FILTER = "(msDS-KeyCredentialLink=*)"
_ATTRS  = ["sAMAccountName", "msDS-KeyCredentialLink", "objectClass",
           "userAccountControl", "distinguishedName", "adminCount", "memberOf"]

_RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
_RISK_SEV   = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
               "MEDIUM": Severity.MEDIUM}


class ShadowModule(BaseModule):
    name        = "shadow"
    description = "Shadow Credentials (msDS-KeyCredentialLink) — parsed & risk-scored"

    def run(self, ctx: ScanContext) -> None:
        out = ctx.out
        out.section("SHADOW CREDENTIALS")

        entries = ctx.conn.search(_FILTER, _ATTRS)
        if not entries:
            out.success("No objects with msDS-KeyCredentialLink found")
            return

        objs = []
        for entry in entries:
            sam  = get_attr(entry, "sAMAccountName") or get_dn(entry)
            oc   = {c.lower() for c in get_list(entry, "objectClass")}
            uac  = get_int(entry, "userAccountControl")
            keys = parse_key_credentials(get_list(entry, "msDS-KeyCredentialLink"))
            is_computer = "computer" in oc

            priv = (sam.lower() == "krbtgt"
                    or get_int(entry, "adminCount") == 1
                    or _is_priv_member(get_list(entry, "memberOf"))
                    or uac_has(uac, UAC_SERVER_TRUST))   # DC

            if priv:
                risk = "CRITICAL"
            elif is_computer:
                risk = "HIGH"
            else:
                risk = "MEDIUM"

            objs.append({
                "sam": sam, "dn": get_attr(entry, "distinguishedName") or get_dn(entry),
                "kind": "Computer" if is_computer else "User",
                "keys": keys, "risk": risk, "priv": priv,
            })

        objs.sort(key=lambda o: _RISK_ORDER[o["risk"]])

        out.counter("Objects with Shadow Credentials", len(objs), {
            "privileged": sum(1 for o in objs if o["priv"]),
            "computers":  sum(1 for o in objs if o["kind"] == "Computer"),
        })

        # Detail table — one row per key so creation times are visible
        out.subsection("Key credentials")
        rows = []
        for o in objs:
            for k in (o["keys"] or [{}]):
                rows.append([
                    o["sam"], o["kind"],
                    k.get("created") or "?",
                    k.get("usage") or "-",
                    (k.get("device") or "")[:8] or "-",
                    o["risk"],
                ])
        out.table(["Object", "Kind", "Key created", "Usage", "Device", "Risk"],
                  rows, indent=4,
                  highlight_fn=lambda r: C.RED if r[5] == "CRITICAL"
                  else (C.YELLOW if r[5] == "HIGH" else None))

        # Quick Wins per risk tier
        from utils import exploit_cmds
        for tier in ("CRITICAL", "HIGH", "MEDIUM"):
            group = [o for o in objs if o["risk"] == tier]
            if not group:
                continue
            lines = []
            for o in group:
                created = ", ".join(k.get("created") or "?" for k in o["keys"]) or "?"
                lines.append(f"  - {o['sam']} ({o['kind']}, {len(o['keys'])} key(s), "
                             f"created {created})")
            if tier == "CRITICAL":
                headline = ("Key credentials on PRIVILEGED accounts (krbtgt / DC / "
                            "admin) — a planted key here is full compromise / "
                            "persistence. Verify each creation time against a known "
                            "enrollment:")
            elif tier == "HIGH":
                headline = ("Key credentials on computer accounts — uncommon outside "
                            "hybrid/WHfB; typically a Shadow-Credentials / RBCD "
                            "artifact:")
            else:
                headline = ("Key credentials on user accounts — often legitimate "
                            "Windows Hello for Business; treat a key whose creation "
                            "time / device does not match enrollment as a backdoor:")
            ctx.quick_wins.add(
                _RISK_SEV[tier],
                f"Shadow Credentials — {len(group)} {tier.lower()}-risk object(s)",
                "msDS-KeyCredentialLink → PKINIT as the target and NT-hash recovery.\n"
                + headline + "\n" + "\n".join(lines) + "\n"
                + exploit_cmds.shadow_creds(ctx, group[0]["sam"]),
            )
