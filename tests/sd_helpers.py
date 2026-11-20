"""Builders for crafted binary Security Descriptors / ACEs, used by the DACL
tests. No DC and no external libs needed — we assemble the exact on-the-wire
bytes that `modules.acls._parse_dacl` consumes.

Layouts (MS-DTYP):
  * SD header: Revision(1) Sbz1(1) Control(2) OffOwner(4) OffGroup(4) OffSacl(4)
    OffDacl(4) — we zero owner/group/sacl and put the DACL at offset 20.
  * ACL header: Revision(1) Sbz1(1) AclSize(2) AceCount(2) Sbz2(2).
  * ACE: Type(1) Flags(1) Size(2) then Mask(4) [+ ObjectFlags(4) + GUIDs] + SID
    [+ trailing conditional-expression blob for callback ACEs].
"""
import os
import struct
import sys

# Make `modules` / `utils` importable when tests run from anywhere.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

SID_LOWPRIV = "S-1-5-21-111-222-333-1105"   # a stand-in non-privileged principal
COND_BLOB = b"artx\x00\x00\x00\x00"          # dummy conditional-expression trailer


def sid_bytes(sid: str) -> bytes:
    p = sid.split("-")
    rev, auth, subs = int(p[1]), int(p[2]), [int(x) for x in p[3:]]
    b = bytes([rev, len(subs)]) + auth.to_bytes(6, "big")
    for s in subs:
        b += struct.pack("<I", s)
    return b


def guid_bytes(guid: str) -> bytes:
    p = guid.split("-")
    return (struct.pack("<I", int(p[0], 16)) + struct.pack("<H", int(p[1], 16))
            + struct.pack("<H", int(p[2], 16)) + bytes.fromhex(p[3]) + bytes.fromhex(p[4]))


def ace(ace_type: int, mask: int, sid: str, *, guid: str | None = None,
        flags: int = 0x00, trailer: bytes = b"") -> bytes:
    """One ACE. Pass `guid` for the object form (adds ObjectFlags + ObjectType),
    `flags` for ACE header flags (e.g. INHERIT_ONLY 0x08), `trailer` for a
    callback ACE's conditional blob."""
    body = struct.pack("<I", mask)
    if guid is not None:
        body += struct.pack("<I", 0x1) + guid_bytes(guid)   # ObjectType present
    body += sid_bytes(sid) + trailer
    return struct.pack("<BBH", ace_type, flags, 4 + len(body)) + body


def sd(aces: list[bytes]) -> bytes:
    """Wrap ACEs into a DACL + a self-relative SD header."""
    acl_body = b"".join(aces)
    acl = struct.pack("<BBHHH", 2, 0, 8 + len(acl_body), len(aces), 0) + acl_body
    control = 0x8004  # SE_SELF_RELATIVE | SE_DACL_PRESENT
    return struct.pack("<BBH", 1, 0, control) + struct.pack("<IIII", 0, 0, 0, 20) + acl
