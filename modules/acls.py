"""
ACLs module — DCSync rights and dangerous DACL permissions on sensitive objects.

Checks:
- DCSync: DS-Replication-Get-Changes + DS-Replication-Get-Changes-All on domain object
- GenericAll / GenericWrite / WriteDACL / WriteOwner on:
    * Domain Admins group
    * Domain object
    * AdminSDHolder
    * Domain Controllers OU
    * krbtgt account
"""

import struct
from dataclasses import dataclass, field
from modules.base import BaseModule, ScanContext
from core.output import Severity, C
from utils.ldap_helpers import get_attr, get_list, get_raw, get_dn, SCOPE_BASE
from utils.sids import resolve_sid, bytes_to_sid, WELL_KNOWN_SIDS, is_privileged_sid
from utils import exploit_cmds

# -----------------------------------------------------------------------
# ACE / DACL parsing (pure Python, no external libs)
# -----------------------------------------------------------------------

# Access mask bits — generic mapping
GENERIC_ALL          = 0x10000000
GENERIC_WRITE        = 0x40000000
WRITE_DACL           = 0x00040000
WRITE_OWNER          = 0x00080000
GENERIC_READ         = 0x80000000

# Access mask bits — specific rights (AD DS). A granted "Full Control" is often
# stored as the expanded specific mask (0x000F01FF), not the GENERIC_ALL bit.
RIGHT_DS_SELF           = 0x00000008   # validated write
RIGHT_DS_WRITE_PROP     = 0x00000020   # write property
RIGHT_DS_CONTROL_ACCESS = 0x00000100   # extended right
FULL_CONTROL            = 0x000F01FF    # all specific rights set == GenericAll

# Extended rights GUIDs
GUID_DS_REPL_GET_CHANGES     = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
GUID_DS_REPL_GET_CHANGES_ALL = "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2"
GUID_DS_REPL_GET_CHANGES_IN_FILTERED_SET = "89e95b76-444d-4c62-991a-0facbeda640c"

# Dangerous property / extended-right / validated-write GUIDs (for targeted,
# non-full-control write access held by the current account).
GUID_FORCE_CHANGE_PASSWORD = "00299570-246d-11d0-a768-00aa006e0529"  # extended
GUID_MEMBER                = "bf9679c0-0de6-11d0-a285-00aa003049e2"  # member / self-membership
GUID_SPN                   = "f3a64788-5306-11d1-a9c5-0000f80367c1"  # servicePrincipalName
GUID_KEY_CREDENTIAL_LINK   = "5b47d60f-6090-40b2-9f37-2a4de88f3063"  # msDS-KeyCredentialLink
GUID_ALLOWED_TO_ACT        = "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79"  # msDS-AllowedToActOnBehalfOf…

# Object type GUIDs for write property rights (partial list)
# These represent classes/attributes where GenericWrite is dangerous
DANGEROUS_WRITE_GUIDS = {
    GUID_DS_REPL_GET_CHANGES,
    GUID_DS_REPL_GET_CHANGES_ALL,
    GUID_DS_REPL_GET_CHANGES_IN_FILTERED_SET,
}

# ACE types
ACE_ACCESS_ALLOWED          = 0x00
ACE_ACCESS_ALLOWED_OBJECT   = 0x05
ACE_ACCESS_DENIED           = 0x01
ACE_ACCESS_DENIED_OBJECT    = 0x06

# Conditional (callback) ACE types — same binary layout (Mask/Flags/GUID/SID) as
# their non-callback base type, followed by a trailing conditional-expression
# blob we do not evaluate. Normalised to the base type on parse; the ACE is then
# tagged conditional=True so the effective-access engine can stay detection-safe.
ACE_ACCESS_ALLOWED_CALLBACK         = 0x09
ACE_ACCESS_DENIED_CALLBACK          = 0x0A
ACE_ACCESS_ALLOWED_CALLBACK_OBJECT  = 0x0B
ACE_ACCESS_DENIED_CALLBACK_OBJECT   = 0x0C
_CALLBACK_TO_BASE = {
    ACE_ACCESS_ALLOWED_CALLBACK:        ACE_ACCESS_ALLOWED,
    ACE_ACCESS_DENIED_CALLBACK:         ACE_ACCESS_DENIED,
    ACE_ACCESS_ALLOWED_CALLBACK_OBJECT: ACE_ACCESS_ALLOWED_OBJECT,
    ACE_ACCESS_DENIED_CALLBACK_OBJECT:  ACE_ACCESS_DENIED_OBJECT,
}

# ACE header flags
INHERIT_ONLY_ACE            = 0x08   # ACE applies to children only, NOT this object

# Well-known low-privilege SIDs to skip in output
_SKIP_SIDS = {
    "S-1-1-0",       # Everyone
    "S-1-5-11",      # Authenticated Users
    "S-1-5-9",       # Enterprise Domain Controllers
    "S-1-3-0",       # Creator Owner
    "S-1-5-10",      # Self
    "S-1-5-18",      # Local System
}


def _parse_guid(data: bytes) -> str:
    """Parse a 16-byte GUID to string representation."""
    if len(data) < 16:
        return ""
    p1 = struct.unpack_from("<IHH", data, 0)
    p2 = data[8:10]
    p3 = data[10:16]
    return (
        f"{p1[0]:08x}-{p1[1]:04x}-{p1[2]:04x}-"
        f"{p2.hex()}-{p3.hex()}"
    )


def _parse_sid_from_ace(data: bytes, offset: int) -> tuple:
    """Parse a SID starting at offset. Returns (sid_str, bytes_consumed)."""
    if offset + 8 > len(data):
        return "", 0
    revision   = data[offset]
    sub_count  = data[offset + 1]
    authority  = int.from_bytes(data[offset + 2:offset + 8], "big")
    size       = 8 + sub_count * 4
    if offset + size > len(data):
        return "", 0
    sub_auths = [
        int.from_bytes(data[offset + 8 + i*4:offset + 12 + i*4], "little")
        for i in range(sub_count)
    ]
    sid = f"S-{revision}-{authority}-" + "-".join(str(s) for s in sub_auths)
    return sid, size


def _parse_dacl(raw_sd: bytes, include_deny: bool = False) -> list:
    """
    Parse a Windows Security Descriptor (binary) and extract ACEs from DACL.
    Returns list of dicts: {type, mask, sid, object_type_guid}

    By default only ALLOW ACEs are returned (the long-standing contract relied
    on by every caller that reads ``ace["mask"]`` as a grant: gpo, adidns, adcs,
    gmsa). Pass ``include_deny=True`` to also get DENY ACEs — only the
    effective-access engine in this module (``_effective_access``), which
    distinguishes the two, asks for them.
    """
    aces = []
    if not raw_sd or len(raw_sd) < 20:
        return aces

    # Security Descriptor header
    # Revision(1) Sbz1(1) Control(2) OffOwner(4) OffGroup(4) OffSacl(4) OffDacl(4)
    try:
        revision, _, control = struct.unpack_from("<BBH", raw_sd, 0)
        off_dacl = struct.unpack_from("<I", raw_sd, 16)[0]
    except struct.error:
        return aces

    SE_DACL_PRESENT = 0x0004
    if not (control & SE_DACL_PRESENT) or off_dacl == 0:
        return aces

    if off_dacl + 8 > len(raw_sd):
        return aces

    # ACL header
    try:
        acl_revision, _, acl_size, ace_count = struct.unpack_from("<BBHH", raw_sd, off_dacl)
    except struct.error:
        return aces

    pos = off_dacl + 8  # skip ACL header (8 bytes)

    for _ in range(ace_count):
        if pos + 4 > len(raw_sd):
            break
        try:
            ace_type, ace_flags, ace_size = struct.unpack_from("<BBH", raw_sd, pos)
        except struct.error:
            break
        ace_data = raw_sd[pos:pos + ace_size]
        pos += ace_size

        # Normalise conditional (callback) ACEs to their base type; they carry the
        # same Mask/Flags/GUID/SID layout, so everything below is identical.
        conditional = ace_type in _CALLBACK_TO_BASE
        ace_type = _CALLBACK_TO_BASE.get(ace_type, ace_type)

        if ace_type not in (ACE_ACCESS_ALLOWED, ACE_ACCESS_ALLOWED_OBJECT,
                             ACE_ACCESS_DENIED, ACE_ACCESS_DENIED_OBJECT):
            continue
        if not include_deny and ace_type in (ACE_ACCESS_DENIED, ACE_ACCESS_DENIED_OBJECT):
            continue
        # INHERIT_ONLY ACEs are a template for child objects and grant NO access
        # on this object itself — counting them is a false positive.
        if ace_flags & INHERIT_ONLY_ACE:
            continue
        if len(ace_data) < 8:
            continue

        mask = struct.unpack_from("<I", ace_data, 4)[0]

        object_type_guid = ""
        if ace_type in (ACE_ACCESS_ALLOWED_OBJECT, ACE_ACCESS_DENIED_OBJECT):
            # Object ACE: flags(4) + optional object_type(16) + optional inherited_type(16) + SID
            if len(ace_data) < 12:
                continue
            obj_flags = struct.unpack_from("<I", ace_data, 8)[0]
            sid_offset = 12
            if obj_flags & 0x1:  # ObjectType present
                object_type_guid = _parse_guid(ace_data[12:28])
                sid_offset += 16
            if obj_flags & 0x2:  # InheritedObjectType present
                sid_offset += 16
            sid, _ = _parse_sid_from_ace(ace_data, sid_offset)
        else:
            sid, _ = _parse_sid_from_ace(ace_data, 8)

        if sid:
            aces.append({
                "type":             ace_type,
                "mask":             mask,
                "sid":              sid,
                "object_type_guid": object_type_guid,
                "conditional":      conditional,
            })

    return aces


def _is_allow(ace: dict) -> bool:
    return ace["type"] in (ACE_ACCESS_ALLOWED, ACE_ACCESS_ALLOWED_OBJECT)


def _is_deny(ace: dict) -> bool:
    return ace["type"] in (ACE_ACCESS_DENIED, ACE_ACCESS_DENIED_OBJECT)


def _covers_full(mask: int) -> bool:
    """A mask that amounts to full control (the generic bit or the expanded
    specific-rights mask 0x000F01FF — a real GenericAll is often stored as the
    latter, not the 0x10000000 generic bit)."""
    return bool(mask & GENERIC_ALL) or (mask & FULL_CONTROL) == FULL_CONTROL


@dataclass
class _Eff:
    """Effective access a set of trustees holds over one object, after ALLOW and
    DENY ACEs have been collapsed."""
    mask:         int  = 0       # effective general-right mask (GenericAll/WriteDACL/…)
    access_guids: set  = field(default_factory=set)  # extended rights granted (by GUID)
    write_guids:  set  = field(default_factory=set)  # write-property granted (by GUID)
    self_guids:   set  = field(default_factory=set)  # validated writes granted (by GUID)
    all_access:   bool = False   # all-extended-rights granted (CONTROL_ACCESS, no GUID)
    all_write:    bool = False   # write-all-properties granted (WRITE_PROP, no GUID)
    src:          dict = field(default_factory=dict)  # right-key → granting trustee SID


def _effective_access(aces: list, trustees: set) -> "_Eff":
    """Collapse an ordered ACE list into the access the given trustee SIDs
    effectively hold, honouring ACCESS_DENIED[_OBJECT] ACEs.

    Model: a right is granted iff an ALLOW ACE for a trustee grants it AND no
    DENY ACE for a trustee in the same set revokes it (DENY wins). This fixes
    the false positive where a lone ALLOW is reported even though a DENY on the
    same principal removes the right. Scope/limit: DENY is matched on the
    trustee SIDs we are given — not on implicit broad groups a principal only
    *transitively* belongs to (Everyone / Authenticated Users), nor on
    non-canonical ALLOW-before-DENY ordering (AD rewrites DACLs to canonical).
    """
    allow_general = deny_general = 0
    a_access, a_write, a_self = set(), set(), set()
    d_access, d_write, d_self = set(), set(), set()
    a_all_access = a_all_write = d_all_access = d_all_write = False
    src: dict = {}
    GEN_BITS = GENERIC_ALL | GENERIC_WRITE | WRITE_DACL | WRITE_OWNER

    for ace in aces:
        if ace["sid"] not in trustees:
            continue
        deny = _is_deny(ace)
        # A conditional (callback) DENY only denies when its expression evaluates
        # true — which we do not evaluate. Letting it suppress a grant would hide
        # a real path (false negative), so we ignore conditional DENYs. Conditional
        # ALLOWs are kept: they surface a potential grant worth reporting.
        if deny and ace.get("conditional"):
            continue
        mask = ace["mask"]
        guid = ace["object_type_guid"].lower()
        obj  = ace["type"] in (ACE_ACCESS_ALLOWED_OBJECT, ACE_ACCESS_DENIED_OBJECT)

        if obj and guid:
            # Object ACE: the right bit(s) apply to this GUID only.
            if deny:
                if mask & RIGHT_DS_CONTROL_ACCESS: d_access.add(guid)
                if mask & RIGHT_DS_WRITE_PROP:     d_write.add(guid)
                if mask & RIGHT_DS_SELF:           d_self.add(guid)
            else:
                if mask & RIGHT_DS_CONTROL_ACCESS: a_access.add(guid); src.setdefault(guid, ace["sid"])
                if mask & RIGHT_DS_WRITE_PROP:     a_write.add(guid);  src.setdefault(guid, ace["sid"])
                if mask & RIGHT_DS_SELF:           a_self.add(guid);   src.setdefault(guid, ace["sid"])
            # Any general bits carried alongside the GUID still apply generally.
            general = mask & GEN_BITS
            if general:
                if deny:
                    deny_general |= general
                else:
                    allow_general |= general
                    src.setdefault("general", ace["sid"])
        else:
            # Non-object ACE (or object ACE with no ObjectType): applies to all.
            if deny:
                deny_general |= mask
                if mask & RIGHT_DS_CONTROL_ACCESS: d_all_access = True
                if mask & RIGHT_DS_WRITE_PROP:     d_all_write = True
            else:
                allow_general |= mask
                if mask & GEN_BITS:
                    src.setdefault("general", ace["sid"])
                if mask & RIGHT_DS_CONTROL_ACCESS:
                    a_all_access = True; src.setdefault("all_access", ace["sid"])
                if mask & RIGHT_DS_WRITE_PROP:
                    a_all_write = True;  src.setdefault("all_write", ace["sid"])

    deny_full = _covers_full(deny_general)

    def _ok(g: str, allow_set: set, deny_set: set, deny_all: bool) -> bool:
        return (not deny_full) and (not deny_all) and (g not in deny_set) and (g in allow_set)

    return _Eff(
        mask         = 0 if deny_full else (allow_general & ~deny_general),
        access_guids = {g for g in a_access if _ok(g, a_access, d_access, d_all_access)},
        write_guids  = {g for g in a_write  if _ok(g, a_write,  d_write,  d_all_write)},
        self_guids   = {g for g in a_self   if _ok(g, a_self,   d_self,   False)},
        all_access   = a_all_access and not deny_full and not d_all_access,
        all_write    = a_all_write  and not deny_full and not d_all_write,
        src          = src,
    )


def _effective_danger(eff: "_Eff", check_dcsync: bool = False) -> tuple:
    """Single most-significant dangerous right in effective access (DENY-aware).
    Mirrors the old per-ACE _is_dangerous_ace contract: (is_dangerous, reason)."""
    if check_dcsync and (GUID_DS_REPL_GET_CHANGES in eff.access_guids
                         or GUID_DS_REPL_GET_CHANGES_ALL in eff.access_guids):
        return True, "DS-Replication-Get-Changes"
    if _covers_full(eff.mask):
        return True, "GenericAll"
    if eff.mask & WRITE_DACL:
        return True, "WriteDACL"
    if eff.mask & WRITE_OWNER:
        return True, "WriteOwner"
    if eff.mask & GENERIC_WRITE:
        return True, "GenericWrite"
    # Write-ALL-properties (no specific GUID) or a dangerous property (member).
    # A specific benign property write (many default ACEs) is NOT a finding.
    if eff.all_write:
        return True, "WriteAllProperties"
    if GUID_MEMBER in eff.write_guids:
        return True, "Write member"
    return False, ""


def _control_from_effective(eff: "_Eff") -> list:
    """Every dangerous right the effective access grants, as a list of
    (right_label, severity, impact, granting_sid). DENY-aware; recognises the
    expanded full-control mask and targeted write/extended rights."""
    g = eff.src
    if _covers_full(eff.mask):
        return [("GenericAll", "CRITICAL", "full control over the object", g.get("general"))]

    res = []
    if eff.mask & WRITE_DACL:
        res.append(("WriteDACL", "CRITICAL", "rewrite the DACL → grant self full control", g.get("general")))
    if eff.mask & WRITE_OWNER:
        res.append(("WriteOwner", "CRITICAL", "take ownership → then rewrite the DACL", g.get("general")))
    if eff.mask & GENERIC_WRITE:
        res.append(("GenericWrite", "HIGH", "write any attribute of the object", g.get("general")))

    # Targeted write-property
    if eff.all_write:
        res.append(("WriteAllProperties", "HIGH", "write any attribute of the object", g.get("all_write")))
    else:
        if GUID_KEY_CREDENTIAL_LINK in eff.write_guids:
            res.append(("Write msDS-KeyCredentialLink", "CRITICAL", "Shadow Credentials → recover NT hash", g.get(GUID_KEY_CREDENTIAL_LINK)))
        if GUID_ALLOWED_TO_ACT in eff.write_guids:
            res.append(("Write msDS-AllowedToActOnBehalfOfOtherIdentity", "CRITICAL", "RBCD → impersonate", g.get(GUID_ALLOWED_TO_ACT)))
        if GUID_SPN in eff.write_guids:
            res.append(("Write servicePrincipalName", "HIGH", "targeted Kerberoast", g.get(GUID_SPN)))
        if GUID_MEMBER in eff.write_guids:
            res.append(("Write member", "CRITICAL", "add members to the group", g.get(GUID_MEMBER)))

    # Validated write: self-membership
    if GUID_MEMBER in eff.self_guids:
        res.append(("Self-Membership", "HIGH", "add yourself to the group", g.get(GUID_MEMBER)))

    # Extended / control-access rights
    if eff.all_access:
        res.append(("AllExtendedRights", "CRITICAL", "incl. ForceChangePassword / DCSync", g.get("all_access")))
    else:
        if GUID_FORCE_CHANGE_PASSWORD in eff.access_guids:
            res.append(("ForceChangePassword", "CRITICAL", "reset the account's password", g.get(GUID_FORCE_CHANGE_PASSWORD)))
        if GUID_DS_REPL_GET_CHANGES in eff.access_guids or GUID_DS_REPL_GET_CHANGES_ALL in eff.access_guids:
            res.append(("DS-Replication-Get-Changes", "CRITICAL", "DCSync",
                        g.get(GUID_DS_REPL_GET_CHANGES) or g.get(GUID_DS_REPL_GET_CHANGES_ALL)))
    return res


# Most-specific → least-specific object class for labelling a target.
_OBJ_CLASS_LABEL = [
    ("msds-groupmanagedserviceaccount", "gMSA"),
    ("computer",                        "computer"),
    ("group",                           "group"),
    ("user",                            "user"),
]


def _obj_class(rec) -> str:
    classes = {c.lower() for c in get_list(rec, "objectClass")}
    for key, label in _OBJ_CLASS_LABEL:
        if key in classes:
            return label
    return "object"


# -----------------------------------------------------------------------
# Module
# -----------------------------------------------------------------------

class ACLsModule(BaseModule):
    name        = "acls"
    description = "DCSync rights, dangerous DACLs on sensitive objects, and outbound control held by the current account"

    def run(self, ctx: ScanContext) -> None:
        out = ctx.out
        out.section("ACLs — SENSITIVE PERMISSIONS")

        self._check_dcsync(ctx)
        self._check_sensitive_objects(ctx)
        self._check_current_user_rights(ctx)

    def _check_dcsync(self, ctx: ScanContext) -> None:
        """Check who has DS-Replication-Get-Changes-All on the domain object."""
        out = ctx.out
        out.subsection("DCSync Rights (DS-Replication-Get-Changes-All)")

        entries = ctx.conn.search(
            ldap_filter="(objectClass=domain)",
            attributes=["nTSecurityDescriptor"],
            base=ctx.base_dn,
            scope=SCOPE_BASE,
        )

        if not entries:
            out.warning("Could not read domain object ACL (insufficient permissions)")
            return

        dcsync_accounts = []

        raw_sd = get_raw(entries[0], "nTSecurityDescriptor")
        if not raw_sd:
            out.warning("Could not parse domain object security descriptor")
            return

        aces = _parse_dacl(raw_sd, include_deny=True)
        domain_sid = ctx.domain_sid

        # Effective replication rights per principal, honouring DENY ACEs: an
        # ALLOW GetChanges[-All] that a DENY on the same trustee revokes is NOT
        # a finding (_effective_access collapses ALLOW/DENY per trustee).
        candidates = {a["sid"] for a in aces if _is_allow(a) and a["sid"] not in _SKIP_SIDS}
        for sid in candidates:
            eff = _effective_access(aces, {sid})
            has_all   = GUID_DS_REPL_GET_CHANGES_ALL in eff.access_guids
            has_basic = GUID_DS_REPL_GET_CHANGES in eff.access_guids
            if not (has_all or has_basic):
                continue
            name = resolve_sid(sid, domain_sid)
            if has_all and has_basic:
                dcsync_accounts.append((name, sid, "FULL DCSync (GetChanges + GetChangesAll)"))
            elif has_all:
                dcsync_accounts.append((name, sid, "GetChangesAll"))
            else:
                dcsync_accounts.append((name, sid, "GetChanges only"))

        # Filter out already-privileged principals: DA/EA/DCs AND
        # BUILTIN\Administrators, Administrator, etc. all hold replication
        # rights by default — only a non-privileged holder is a finding.
        filtered = []
        for name, sid, rights in dcsync_accounts:
            if sid in _SKIP_SIDS:
                continue
            if is_privileged_sid(sid, domain_sid):
                continue
            filtered.append((name, sid, rights))

        if filtered:
            rows = [[name, sid, rights] for name, sid, rights in filtered]
            out.table(
                ["Account / Group", "SID", "Rights"],
                rows,
                highlight_fn=lambda r: C.RED if "FULL DCSync" in r[2] else C.YELLOW,
            )
            ctx.quick_wins.add(
                Severity.CRITICAL,
                f"Unexpected DCSync rights — {len(filtered)} principal(s)",
                "These accounts can dump all domain hashes (DCSync attack):\n"
                + "\n".join(f"  {n} ({s})" for n, s, _ in filtered)
                + "\nIf you control one of them (or already are privileged):\n"
                + exploit_cmds.dcsync(ctx),
            )
        else:
            out.success("No unexpected DCSync rights detected")

    def _check_sensitive_objects(self, ctx: ScanContext) -> None:
        """Check for dangerous permissions on high-value AD objects."""
        out = ctx.out
        out.subsection("Dangerous Permissions on Sensitive Objects")

        domain_sid = ctx.domain_sid
        base_dn    = ctx.base_dn

        # AdminSDHolder / krbtgt CNs are not localized; the privileged GROUP CNs are
        # ("Domain Admins" → "Admins du domaine" on a FR DC), so resolve those from
        # their SID/RID via the <SID=…> DN instead of hardcoding an English CN.
        targets = {
            "Domain object":   base_dn,
            "AdminSDHolder":   f"CN=AdminSDHolder,CN=System,{base_dn}",
            "krbtgt":          f"CN=krbtgt,CN=Users,{base_dn}",
        }
        if domain_sid:
            for rid, label in ((512, "Domain Admins group"),
                               (519, "Enterprise Admins group")):
                gdn = self._dn_by_sid(ctx, f"{domain_sid}-{rid}")
                if gdn:
                    targets[label] = gdn
        adm = self._dn_by_sid(ctx, "S-1-5-32-544")   # BUILTIN\Administrators
        if adm:
            targets["Administrators group"] = adm

        any_finding = False

        for label, dn in targets.items():
            entries = ctx.conn.search(
                ldap_filter="(objectClass=*)",
                attributes=["nTSecurityDescriptor", "distinguishedName"],
                base=dn,
                scope=SCOPE_BASE,
            )
            if not entries:
                continue

            raw_sd = get_raw(entries[0], "nTSecurityDescriptor")
            if not raw_sd:
                continue

            aces = _parse_dacl(raw_sd, include_deny=True)
            findings = []

            # Evaluate each non-privileged trustee's EFFECTIVE access (DENY-aware),
            # so a DENY revoking an ALLOW on the same principal is not a finding.
            candidates = {a["sid"] for a in aces if _is_allow(a) and a["sid"] not in _SKIP_SIDS}
            for sid in candidates:
                # Skip already-privileged principals (DA/EA/DCs/Administrators…).
                if is_privileged_sid(sid, domain_sid):
                    continue
                eff = _effective_access(aces, {sid})
                dangerous, reason = _effective_danger(eff)
                if dangerous:
                    name = resolve_sid(sid, domain_sid)
                    findings.append((name, sid, reason))

            if findings:
                any_finding = True
                print(f"\n    {C.YELLOW}{C.BOLD}[!] {label}{C.RESET}")
                rows = [[name, sid, reason] for name, sid, reason in findings]
                out.table(
                    ["Principal", "SID", "Permission"],
                    rows,
                    highlight_fn=lambda r: C.RED if r[2] in (
                        "GenericAll", "WriteDACL", "Write member") else C.YELLOW,
                    indent=8,
                )
                for name, sid, reason in findings:
                    ctx.quick_wins.add(
                        Severity.CRITICAL if reason in (
                            "GenericAll", "WriteDACL", "WriteOwner", "Write member")
                        else Severity.HIGH,
                        f"{reason} on {label} — {name}",
                        f"SID: {sid}\n"
                        f"This grants effective control over {label}.",
                    )

        if not any_finding:
            out.success("No dangerous permissions detected on sensitive objects")

    @staticmethod
    def _dn_by_sid(ctx: ScanContext, sid: str):
        """Resolve an object's DN from its SID via the <SID=…> base DN (locale-
        proof; binary objectSid filters don't work under impacket)."""
        try:
            res = ctx.conn.search("(objectClass=*)", ["distinguishedName"],
                                  base=f"<SID={sid}>", scope=SCOPE_BASE)
            if res:
                return get_dn(res[0]) or get_attr(res[0], "distinguishedName") or None
        except Exception:
            pass
        return None

    def _check_current_user_rights(self, ctx: ScanContext) -> None:
        """Find objects over which the *authenticated account* holds dangerous
        rights (outbound control / privilege-escalation paths)."""
        out = ctx.out
        out.subsection("Outbound Control — rights held by the current account")

        domain_sid = ctx.domain_sid
        my_sids    = set(ctx.current_user_sids)
        if not my_sids:
            out.info("Anonymous / unknown identity — skipping outbound ACL check")
            return

        # Match the user's own + group SIDs, but drop contextual (Everyone,
        # Self, …) and already-privileged SIDs: a DA holding GenericAll
        # everywhere is expected and would only generate noise.
        match = {s for s in my_sids
                 if s not in _SKIP_SIDS and not is_privileged_sid(s, domain_sid)}
        if not match:
            out.info("Current identity is already privileged — outbound control is "
                     "expected; nothing to escalate to")
            return

        entries = ctx.conn.search(
            ldap_filter="(|(objectClass=user)(objectClass=group))",
            attributes=["nTSecurityDescriptor", "sAMAccountName",
                        "objectClass", "distinguishedName"],
            base=ctx.base_dn,
        )

        # (target, type, right, severity, impact, sid) — dedup on (target, right)
        seen: set = set()
        findings: list = []
        for rec in entries:
            raw_sd = get_raw(rec, "nTSecurityDescriptor")
            if not raw_sd:
                continue
            target = get_attr(rec, "sAMAccountName") or get_dn(rec)
            tclass = _obj_class(rec)
            # Effective rights the current token holds over this object, with any
            # DENY ACE targeting the same token SIDs subtracted from the grant.
            eff = _effective_access(_parse_dacl(raw_sd, include_deny=True), match)
            for right, sev, impact, gsid in _control_from_effective(eff):
                key = (target.lower(), right)
                if key in seen:
                    continue
                seen.add(key)
                findings.append((target, tclass, right, sev, impact, gsid))

        if not findings:
            out.success("Current account holds no dangerous rights over other objects")
            return

        # CRITICAL first, then by target
        order = {"CRITICAL": 0, "HIGH": 1}
        findings.sort(key=lambda f: (order.get(f[3], 2), f[0].lower()))

        rows = [[t, tc, right, (resolve_sid(sid, domain_sid) if sid else "—"), impact]
                for t, tc, right, sev, impact, sid in findings]
        out.table(
            ["Target", "Type", "Right", "Granted via", "Impact"],
            rows,
            highlight_fn=lambda r: C.RED if r[2] in (
                "GenericAll", "WriteDACL", "WriteOwner", "ForceChangePassword",
                "Write msDS-KeyCredentialLink",
                "Write msDS-AllowedToActOnBehalfOfOtherIdentity",
                "Write member", "AllExtendedRights", "DS-Replication-Get-Changes",
            ) else C.YELLOW,
            indent=8,
        )

        for target, tclass, right, sev, impact, _sid in findings:
            severity = Severity.CRITICAL if sev == "CRITICAL" else Severity.HIGH
            ctx.quick_wins.add(
                severity,
                f"{right} over {tclass} '{target}' — held by current account",
                f"Impact: {impact}.\n"
                + exploit_cmds.acl_abuse(ctx, target, tclass, right),
            )
