"""
msDS-KeyCredentialLink (KEYCREDENTIALLINK_BLOB) parser — MS-ADTS 2.2.20.

The attribute is a multi-valued DN-With-Binary: each value is the string
`B:<hexlen>:<hexdata>:<DN>`. The binary is a versioned, TLV-style structure:

    Version  uint32 (LE)        # 0x00000200
    then entries, each:
      Length  uint16 (LE)       # length of Value
      Id      uint8             # entry type
      Value   Length bytes

Entry ids of interest:
  0x01 KeyID            SHA256 of the public key (the Shadow-Credential handle)
  0x03 RawKeyMaterial   the public key
  0x04 KeyUsage         1 byte (0x01 = NGC / Shadow Creds)
  0x05 KeySource        1 byte (0x00 = AD)
  0x06 DeviceId         16-byte GUID
  0x08 KeyApproximateLastLogonTimeStamp  FILETIME (8 bytes LE)
  0x09 KeyCreationTime                   FILETIME (8 bytes LE)

Offensively, the **creation time** is the tell: a key minted recently on a
sensitive account is a planted backdoor (Whisker / pyWhisker / Shadow Credentials),
whereas a Windows-Hello-for-Business key tracks the user's device enrollment.
"""

import struct
from datetime import datetime, timedelta, timezone
from typing import List, Dict

_VERSION         = 0x00000200
_ID_KEYID        = 0x01
_ID_USAGE        = 0x04
_ID_SOURCE       = 0x05
_ID_DEVICEID     = 0x06
_ID_LASTLOGON    = 0x08
_ID_CREATED      = 0x09

_USAGE = {0x00: "AdminKey", 0x01: "NGC", 0x02: "FIDO", 0x03: "FEK"}
_SOURCE = {0x00: "AD", 0x01: "AzureAD"}

_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _filetime(raw: bytes) -> str:
    if len(raw) < 8:
        return ""
    try:
        val = struct.unpack("<Q", raw[:8])[0]
    except struct.error:
        return ""
    if not val:
        return ""
    try:
        return (_FT_EPOCH + timedelta(microseconds=val // 10)).strftime("%Y-%m-%d")
    except (OverflowError, OSError, ValueError):
        return ""


def _guid(raw: bytes) -> str:
    if len(raw) < 16:
        return ""
    a, b, c = struct.unpack_from("<IHH", raw, 0)
    d = raw[8:10]
    e = raw[10:16]
    return f"{a:08x}-{b:04x}-{c:04x}-{d.hex()}-{e.hex()}"


def _parse_blob(blob: bytes) -> Dict:
    out = {"key_id": "", "device": "", "created": "", "last_logon": "",
           "usage": "", "source": ""}
    if len(blob) < 4:
        return out
    pos = 4  # skip Version
    while pos + 3 <= len(blob):
        try:
            length, ident = struct.unpack_from("<HB", blob, pos)
        except struct.error:
            break
        pos += 3
        data = blob[pos:pos + length]
        if len(data) < length:
            break
        pos += length
        if ident == _ID_KEYID:
            out["key_id"] = data[:16].hex()        # short handle
        elif ident == _ID_DEVICEID:
            out["device"] = _guid(data)
        elif ident == _ID_CREATED:
            out["created"] = _filetime(data)
        elif ident == _ID_LASTLOGON:
            out["last_logon"] = _filetime(data)
        elif ident == _ID_USAGE and data:
            out["usage"] = _USAGE.get(data[0], f"0x{data[0]:02x}")
        elif ident == _ID_SOURCE and data:
            out["source"] = _SOURCE.get(data[0], f"0x{data[0]:02x}")
    return out


def parse_key_credentials(values: List[str]) -> List[Dict]:
    """Parse msDS-KeyCredentialLink DN-Binary values → list of key detail dicts.

    Malformed values are skipped. `values` are the decoded LDAP strings
    (`B:<len>:<hex>:<DN>`).
    """
    keys = []
    for v in values:
        if not v or not v.startswith("B:"):
            continue
        parts = v.split(":", 3)
        if len(parts) < 4:
            continue
        try:
            blob = bytes.fromhex(parts[2])
        except ValueError:
            continue
        keys.append(_parse_blob(blob))
    return keys
