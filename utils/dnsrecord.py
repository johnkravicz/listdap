"""
dnsRecord (DNS_RPC_RECORD) decoder for AD-integrated DNS.

Each `dnsNode` object stores one or more values in its multi-valued binary
`dnsRecord` attribute. A value is a DNS_RPC_RECORD blob (MS-DNSP 2.3.2.2): a
fixed 24-byte header followed by type-specific data. This module decodes the
common record types to a `(type_name, value)` pair for inventory / recon — no
DNS query, no zone transfer, just an LDAP read of the DNS partitions.

Header layout (little-endian except TtlSeconds which is big-endian):
    DataLength  H   # length of the Data section
    Type        H   # record type (1=A, 5=CNAME, 33=SRV, …)
    Version     B
    Rank        B
    Flags       H
    Serial      L
    TtlSeconds  >L
    Reserved    L
    TimeStamp   L   # 0 for static records, hours-since-1601 for aged records
    Data        …   # DataLength bytes

Only the Data decoding differs per type. Unknown / unhandled types are returned
as 'TYPE<n>' with a hex preview so nothing is silently dropped.
"""

import socket
import struct
from typing import List, Tuple

_HEADER_LEN = 24

# DNS record type numbers (MS-DNSP 2.2.2.1.1)
_TYPES = {
    0:  "ZERO",      # tombstone / node placeholder
    1:  "A",
    2:  "NS",
    5:  "CNAME",
    6:  "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    39: "DNAME",
}

# Types whose data is a single DNS_COUNT_NAME (a target hostname).
_NAME_TYPES = {"NS", "CNAME", "PTR", "DNAME"}


def _count_name(data: bytes, off: int) -> Tuple[str, int]:
    """Decode a DNS_COUNT_NAME at `off`. Returns (fqdn, bytes_consumed).

    Layout: Length(B) LabelCount(B) then LabelCount labels, each (len(B), chars).
    `Length` is the total byte count of the labels blob that follows the two
    header bytes.
    """
    if off + 2 > len(data):
        return "", 0
    total = data[off]
    labels = []
    p = off + 2                      # skip Length + LabelCount
    end = off + 2 + total
    while p < end and p < len(data):
        llen = data[p]
        p += 1
        if llen == 0 or p + llen > len(data):
            break
        labels.append(data[p:p + llen].decode("utf-8", "replace"))
        p += llen
    fqdn = ".".join(labels)
    return (fqdn + "." if fqdn else "."), (end - off)


def _decode_data(rtype: str, data: bytes) -> str:
    try:
        if rtype == "A" and len(data) >= 4:
            return socket.inet_ntop(socket.AF_INET, data[:4])
        if rtype == "AAAA" and len(data) >= 16:
            return socket.inet_ntop(socket.AF_INET6, data[:16])
        if rtype in _NAME_TYPES:
            name, _ = _count_name(data, 0)
            return name
        if rtype == "MX" and len(data) >= 2:
            pref = struct.unpack_from(">H", data, 0)[0]
            name, _ = _count_name(data, 2)
            return f"{pref} {name}"
        if rtype == "SRV" and len(data) >= 6:
            prio, weight, port = struct.unpack_from(">HHH", data, 0)
            name, _ = _count_name(data, 6)
            return f"{prio} {weight} {port} {name}"
        if rtype == "TXT":
            # one or more counted strings: len(B) + chars, back to back
            out, p = [], 0
            while p < len(data):
                slen = data[p]
                p += 1
                out.append(data[p:p + slen].decode("utf-8", "replace"))
                p += slen
            return " ".join(f'"{s}"' for s in out)
        if rtype == "SOA" and len(data) >= 20:
            # serial, refresh, retry, expire, minimum (5x >L) then 2 names
            prim, _ = _count_name(data, 20)
            return f"primary={prim}"
        if rtype == "ZERO":
            return "(tombstone)"
    except Exception:
        pass
    return "0x" + data[:16].hex()


def parse_record(blob: bytes) -> Tuple[str, str, int]:
    """Parse one DNS_RPC_RECORD blob → (type_name, value, timestamp).

    `timestamp` is the raw aging TimeStamp (0 = static). Returns ("", "", 0) on a
    malformed blob.
    """
    if not blob or len(blob) < _HEADER_LEN:
        return "", "", 0
    try:
        dlen, tnum = struct.unpack_from("<HH", blob, 0)
        ts = struct.unpack_from("<L", blob, 20)[0]
    except struct.error:
        return "", "", 0
    rtype = _TYPES.get(tnum, f"TYPE{tnum}")
    data = blob[_HEADER_LEN:_HEADER_LEN + dlen] if dlen else blob[_HEADER_LEN:]
    return rtype, _decode_data(rtype, data), ts


def parse_records(blobs: List[bytes]) -> List[Tuple[str, str, int]]:
    """Parse every value of a dnsRecord attribute; drops malformed entries."""
    out = []
    for b in blobs:
        rtype, val, ts = parse_record(b)
        if rtype:
            out.append((rtype, val, ts))
    return out
