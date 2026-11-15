"""
Managed-password (MSDS-MANAGEDPASSWORD_BLOB) parsing for gMSA / dMSA accounts.

When the authenticated identity is authorised to retrieve a managed service
account's password, the DC returns the `msDS-ManagedPassword` constructed
attribute as an MSDS-MANAGEDPASSWORD_BLOB (MS-ADTS 2.2.19). The blob carries the
*cleartext* current password as a UTF-16LE buffer; the account's NT hash is
simply MD4 over those raw bytes (no re-encoding — the buffer is already the
UTF-16LE form Windows hashes). That NT hash is directly usable for
pass-the-hash as the service account.

No network here: this only parses a blob already read over LDAP.
"""

from impacket.structure import Structure


class MSDS_MANAGEDPASSWORD_BLOB(Structure):
    """MS-ADTS 2.2.19 MSDS-MANAGEDPASSWORD_BLOB (same layout as gMSADumper)."""
    structure = (
        ('Version', '<H'),
        ('Reserved', '<H'),
        ('Length', '<L'),
        ('CurrentPasswordOffset', '<H'),
        ('PreviousPasswordOffset', '<H'),
        ('QueryPasswordIntervalOffset', '<H'),
        ('UnchangedPasswordIntervalOffset', '<H'),
        ('CurrentPassword', ':'),
        ('PreviousPassword', ':'),
        ('AlignmentPadding', ':'),
        ('QueryPasswordInterval', ':'),
        ('UnchangedPasswordInterval', ':'),
    )

    def fromString(self, data):
        Structure.fromString(self, data)
        # The current password runs from CurrentPasswordOffset up to the next
        # present section (previous password if set, else the interval field).
        if self['PreviousPasswordOffset'] == 0:
            end = self['QueryPasswordIntervalOffset']
        else:
            end = self['PreviousPasswordOffset']
        self['CurrentPassword'] = self.rawData[self['CurrentPasswordOffset']:end]
        if self['PreviousPasswordOffset'] != 0:
            self['PreviousPassword'] = self.rawData[
                self['PreviousPasswordOffset']:self['QueryPasswordIntervalOffset']]


def _md4(data: bytes) -> bytes:
    """MD4 digest, preferring pycryptodome (shipped with impacket) over hashlib
    (whose 'md4' is unavailable under OpenSSL 3 default providers)."""
    try:
        from Cryptodome.Hash import MD4
        return MD4.new(data).digest()
    except Exception:
        try:
            from Crypto.Hash import MD4   # pycrypto fallback
            return MD4.new(data).digest()
        except Exception:
            import hashlib
            return hashlib.new('md4', data).digest()


def nt_hash_from_blob(blob: bytes):
    """Return the lowercase hex NT hash from an MSDS-MANAGEDPASSWORD_BLOB, or
    None if the blob can't be parsed. The NT hash is MD4 over the raw UTF-16LE
    current-password buffer — do NOT re-encode the bytes."""
    if not blob:
        return None
    try:
        parsed = MSDS_MANAGEDPASSWORD_BLOB(blob)
        current = parsed['CurrentPassword']
        if not current:
            return None
        return _md4(current).hex()
    except Exception:
        return None
