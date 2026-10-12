"""
Read a CA's registry security descriptor over MS-RRP (remote registry).

ManageCA / ManageCertificates rights are stored in the CA host registry:
    HKLM\\SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\<CA>\\Security
as a REG_BINARY self-relative security descriptor — NOT in the CA's LDAP
object DACL. This mirrors how certipy reads CA permissions (RRP over SMB).

On that descriptor the access-mask bits are CA-specific:
    0x00000001  ManageCA            (CA administrator)
    0x00000002  ManageCertificates  (certificate manager / officer)
    0x00000200  Enroll

read_ca_security() returns (raw_sd_bytes, None) on success, or (None, reason)
so the caller can fall back to a weaker LDAP-based heuristic.
"""

from typing import Optional, Tuple
import os

CA_RIGHT_MANAGE_CA           = 0x00000001
CA_RIGHT_MANAGE_CERTIFICATES = 0x00000002
CA_RIGHT_ENROLL              = 0x00000200


def read_ca_security(
    host: str,
    dc_ip: str,
    ca_name: str,
    username: str = "",
    password: str = "",
    domain: str = "",
    ccache: str = "",
    timeout: int = 5,
) -> Tuple[Optional[bytes], Optional[str]]:
    """Fetch the CA 'Security' registry value as raw SD bytes, or (None, reason)."""
    try:
        from impacket.smbconnection import SMBConnection
        from impacket.dcerpc.v5 import rrp, transport
    except Exception as e:  # pragma: no cover
        return None, f"impacket unavailable ({e})"

    remote_name = host or dc_ip
    smb = None
    dce = None
    try:
        smb = SMBConnection(remoteName=remote_name, remoteHost=dc_ip, timeout=timeout)
        if password:
            smb.login(username, password, domain or "")
        else:
            # Kerberos via ccache (explicit path or $KRB5CCNAME already set)
            if ccache:
                os.environ["KRB5CCNAME"] = ccache
            smb.kerberosLogin(username, "", domain or "", useCache=True)
    except Exception as e:
        _close(smb, None)
        return None, f"SMB login failed ({e})"

    try:
        rpctransport = transport.SMBTransport(
            remote_name, dc_ip, filename=r"\winreg", smb_connection=smb
        )
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(rrp.MSRPC_UUID_RRP)
    except Exception as e:
        _close(smb, dce)
        return None, f"RRP bind failed — RemoteRegistry may be stopped ({e})"

    try:
        h_root = rrp.hOpenLocalMachine(dce)["phKey"]
        subkey = (
            r"SYSTEM\CurrentControlSet\Services\CertSvc\Configuration"
            "\\" + ca_name
        )
        h_key = rrp.hBaseRegOpenKey(dce, h_root, subkey)["phkResult"]
        resp = rrp.hBaseRegQueryValue(dce, h_key, "Security")
        # impacket returns (dwType, data)
        data = resp[1] if isinstance(resp, (tuple, list)) else resp
        if isinstance(data, str):
            data = data.encode("latin-1")
        if not data:
            return None, "empty Security value"
        return bytes(data), None
    except Exception as e:
        return None, f"registry read failed ({e})"
    finally:
        _close(smb, dce)


def _close(smb, dce) -> None:
    try:
        if dce is not None:
            dce.disconnect()
    except Exception:
        pass
    try:
        if smb is not None:
            smb.close()
    except Exception:
        pass
