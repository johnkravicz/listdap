"""
msDS-SupportedEncryptionTypes decoder (MS-KILE 2.2.7 KERB_ENCRYPTION_TYPE bits).

The attribute is a bitmask of the Kerberos etypes an account advertises support
for. Offensively it tells you how a ticket for the account can be requested and
how fast the resulting hash cracks:

* DES (0x01 / 0x02) — broken; a DES-only/enabled account is trivially crackable.
* RC4 (0x04) — the TGS/AS-REP comes back as etype 23 (`$krb5tgs$23$` /
  `$krb5asrep$23$`), cracked fast with hashcat -m 13100 / -m 18200; RC4 support
  also allows a downgrade from AES.
* AES128/AES256 (0x08 / 0x10 / 0x20) — strong; tickets crack far slower.

When the attribute is **unset (0)**, the account declares no etypes and the KDC
falls back to RC4 for it in common configurations → still RC4-roastable.
"""

from typing import Optional

ENC_DES_CRC    = 0x01   # DES-CBC-CRC
ENC_DES_MD5    = 0x02   # DES-CBC-MD5
ENC_RC4        = 0x04   # RC4-HMAC
ENC_AES128     = 0x08   # AES128-CTS-HMAC-SHA1-96
ENC_AES256     = 0x10   # AES256-CTS-HMAC-SHA1-96
ENC_AES256_SK  = 0x20   # AES256-CTS-HMAC-SHA1-96 (session key, 2022+)

_NAMES = [
    (ENC_DES_CRC,   "DES-CRC"),
    (ENC_DES_MD5,   "DES-MD5"),
    (ENC_RC4,       "RC4"),
    (ENC_AES128,    "AES128"),
    (ENC_AES256,    "AES256"),
    (ENC_AES256_SK, "AES256-SK"),
]

_DES = ENC_DES_CRC | ENC_DES_MD5
_AES = ENC_AES128 | ENC_AES256 | ENC_AES256_SK


def has_des(value: int) -> bool:
    return bool(value & _DES)


def has_rc4(value: int) -> bool:
    return bool(value & ENC_RC4)


def has_aes(value: int) -> bool:
    return bool(value & _AES)


def enctypes_summary(value: int) -> str:
    """Human-readable list of the enabled etypes, e.g. 'RC4, AES128, AES256'.

    0 renders as a note that the account defaults to RC4 at the KDC; unknown high
    bits are appended as a hex remainder.
    """
    if not value:
        return "unset (RC4 default)"
    parts = [name for bit, name in _NAMES if value & bit]
    known = 0
    for bit, _ in _NAMES:
        known |= bit
    extra = value & ~known
    if extra:
        parts.append(f"0x{extra:x}")
    return ", ".join(parts)


def weakness(value: int) -> Optional[str]:
    """Classify the account's Kerberos-crypto weakness, or None if strong.

    Returns one of: 'DES' (DES enabled), 'RC4-only' (RC4 and no AES),
    'RC4-default' (attribute unset → RC4 fallback), 'RC4+AES' (RC4 still allowed
    alongside AES → downgradeable). None when only AES is supported.
    """
    if has_des(value):
        return "DES"
    if value == 0:
        return "RC4-default"
    if has_rc4(value):
        return "RC4-only" if not has_aes(value) else "RC4+AES"
    return None
