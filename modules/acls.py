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
from modules.base import BaseModule, ScanContext
from core.output import Severity, C
from utils.ldap_helpers import get_attr, get_list, get_raw, SCOPE_BASE
from utils.sids import resolve_sid, bytes_to_sid, WELL_KNOWN_SIDS, is_privileged_sid

# -----------------------------------------------------------------------
# ACE / DACL parsing (pure Python, no external libs)
# -----------------------------------------------------------------------

# Access mask bits
GENERIC_ALL          = 0x10000000
GENERIC_WRITE        = 0x40000000
WRITE_DACL           = 0x00040000
WRITE_OWNER          = 0x00080000
GENERIC_READ         = 0x80000000

# Extended rights GUIDs
GUID_DS_REPL_GET_CHANGES     = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
GUID_DS_REPL_GET_CHANGES_ALL = "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2"
GUID_DS_REPL_GET_CHANGES_IN_FILTERED_SET = "89e95b76-444d-4c62-991a-0facbeda640c"

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


def _parse_dacl(raw_sd: bytes) -> list:
    """
    Parse a Windows Security Descriptor (binary) and extract ACEs from DACL.
    Returns list of dicts: {type, mask, sid, object_type_guid}
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

        if ace_type not in (ACE_ACCESS_ALLOWED, ACE_ACCESS_ALLOWED_OBJECT):
            continue
        if len(ace_data) < 8:
            continue

        mask = struct.unpack_from("<I", ace_data, 4)[0]

        object_type_guid = ""
        if ace_type == ACE_ACCESS_ALLOWED_OBJECT:
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
            })

    return aces


def _is_dangerous_ace(ace: dict, check_dcsync: bool = False) -> tuple:
    """
    Returns (is_dangerous, reason) for a given ACE.
    """
    mask = ace["mask"]
    guid = ace["object_type_guid"].lower()

    if check_dcsync:
        if guid in (GUID_DS_REPL_GET_CHANGES_ALL, GUID_DS_REPL_GET_CHANGES):
            return True, "DS-Replication-Get-Changes"

    if mask & GENERIC_ALL:
        return True, "GenericAll"
    if mask & WRITE_DACL:
        return True, "WriteDACL"
    if mask & WRITE_OWNER:
        return True, "WriteOwner"
    if mask & GENERIC_WRITE:
        return True, "GenericWrite"

    return False, ""


# -----------------------------------------------------------------------
# Module
# -----------------------------------------------------------------------

class ACLsModule(BaseModule):
    name        = "acls"
    description = "DCSync rights and dangerous DACL permissions on sensitive objects"

    def run(self, ctx: ScanContext) -> None:
        out = ctx.out
        out.section("ACLs — SENSITIVE PERMISSIONS")

        self._check_dcsync(ctx)
        self._check_sensitive_objects(ctx)

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

        aces = _parse_dacl(raw_sd)
        domain_sid = ctx.domain_sid

        # Track per-SID which replication rights are granted
        repl_rights: dict[str, set] = {}
        for ace in aces:
            sid  = ace["sid"]
            if sid in _SKIP_SIDS:
                continue
            guid = ace["object_type_guid"].lower()
            if guid in (GUID_DS_REPL_GET_CHANGES, GUID_DS_REPL_GET_CHANGES_ALL,
                        GUID_DS_REPL_GET_CHANGES_IN_FILTERED_SET):
                repl_rights.setdefault(sid, set()).add(guid)

        for sid, rights in repl_rights.items():
            name = resolve_sid(sid, domain_sid)
            has_all   = GUID_DS_REPL_GET_CHANGES_ALL in rights
            has_basic = GUID_DS_REPL_GET_CHANGES in rights
            if has_all and has_basic:
                dcsync_accounts.append((name, sid, "FULL DCSync (GetChanges + GetChangesAll)"))
            elif has_all:
                dcsync_accounts.append((name, sid, "GetChangesAll"))
            elif has_basic:
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
                + "\n".join(f"  {n} ({s})" for n, s, _ in filtered),
            )
        else:
            out.success("No unexpected DCSync rights detected")

    def _check_sensitive_objects(self, ctx: ScanContext) -> None:
        """Check for dangerous permissions on high-value AD objects."""
        out = ctx.out
        out.subsection("Dangerous Permissions on Sensitive Objects")

        domain_sid = ctx.domain_sid
        base_dn    = ctx.base_dn

        targets = {
            "Domain object":         base_dn,
            "Domain Admins group":   f"CN=Domain Admins,CN=Users,{base_dn}",
            "AdminSDHolder":         f"CN=AdminSDHolder,CN=System,{base_dn}",
            "krbtgt":                f"CN=krbtgt,CN=Users,{base_dn}",
        }

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

            aces = _parse_dacl(raw_sd)
            findings = []

            for ace in aces:
                sid = ace["sid"]
                if sid in _SKIP_SIDS:
                    continue
                # Skip already-privileged principals (DA/EA/DCs/Administrators…).
                if is_privileged_sid(sid, domain_sid):
                    continue

                dangerous, reason = _is_dangerous_ace(ace)
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
                    highlight_fn=lambda r: C.RED if r[2] in ("GenericAll", "WriteDACL") else C.YELLOW,
                    indent=8,
                )
                for name, sid, reason in findings:
                    ctx.quick_wins.add(
                        Severity.CRITICAL if reason in ("GenericAll", "WriteDACL", "WriteOwner")
                        else Severity.HIGH,
                        f"{reason} on {label} — {name}",
                        f"SID: {sid}\n"
                        f"This grants effective control over {label}.",
                    )

        if not any_finding:
            out.success("No dangerous permissions detected on sensitive objects")
