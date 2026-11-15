"""
BitLocker module — recovery keys escrowed in AD (msFVE-RecoveryInformation).

When a machine escrows its BitLocker recovery information to AD, a child object
of class `msFVE-RecoveryInformation` is created under the computer object. It
carries the 48-digit **msFVE-RecoveryPassword** (the recovery key) and the key
package. By default only Domain Admins (and explicitly delegated principals) may
read the recovery password, but over-permissioned OUs / delegations routinely
expose it to low-privileged users — reading it yields offline access to the
encrypted volume (data theft, offline credential extraction, evil-maid).

Pure LDAP: the module searches for the recovery objects and reports the
password wherever the DC returns it (i.e. wherever the current identity may read
it). When the objects exist but the password is withheld, it still inventories
which machines escrow BitLocker and notes that reading needs delegated rights.

⚠️ NOT VALIDATED LIVE (v2.9.0): implemented and unit-tested against mocked
   records, but never run against a real DC holding msFVE-RecoveryInformation.
"""

from modules.base import BaseModule, ScanContext
from core.output import Severity, C
from utils.ldap_helpers import get_attr, get_dn

_FILTER = "(objectClass=msFVE-RecoveryInformation)"

_ATTRS = [
    "msFVE-RecoveryPassword", "msFVE-RecoveryGuid",
    "msFVE-VolumeGuid", "whenCreated", "name",
]


def _computer_from_dn(dn: str) -> str:
    """The recovery object is a child of the computer object: parent RDN's CN.

    DN form: CN=<timestamp>{<guid>},CN=<COMPUTER>,OU=…  → return <COMPUTER>.
    """
    if not dn or "," not in dn:
        return dn
    parent = dn.split(",", 1)[1]            # drop the recovery-object RDN
    first  = parent.split(",", 1)[0]        # the computer's RDN
    return first.split("=", 1)[-1] if "=" in first else parent


class BitLockerModule(BaseModule):
    name        = "bitlocker"
    description = "BitLocker recovery keys escrowed in AD (msFVE-RecoveryInformation)"

    def run(self, ctx: ScanContext) -> None:
        out = ctx.out
        out.section("BITLOCKER — RECOVERY KEYS")

        try:
            entries = ctx.conn.search(_FILTER, _ATTRS)
        except Exception as e:
            out.warning(f"BitLocker recovery search failed: {e}")
            return

        if not entries:
            out.info("No BitLocker recovery information escrowed in AD")
            return

        readable, withheld = [], []
        rows = []
        for e in entries:
            comp = _computer_from_dn(get_dn(e))
            guid = get_attr(e, "msFVE-RecoveryGuid")
            when = (get_attr(e, "whenCreated") or "")[:8]   # YYYYMMDD
            pw   = get_attr(e, "msFVE-RecoveryPassword")
            if pw:
                readable.append((comp, guid, pw))
                rows.append([comp, guid or "-", when or "-",
                             f"{C.RED}{C.BOLD}{pw}{C.RESET}"])
            else:
                withheld.append((comp, guid))
                rows.append([comp, guid or "-", when or "-",
                             f"{C.GREY}<not readable>{C.RESET}"])

        out.counter("BitLocker recovery objects", len(entries),
                    {"readable key": len(readable),
                     "escrowed (no read)": len(withheld)})
        out.subsection("Recovery information")
        out.table(["Computer", "Recovery GUID", "Created", "Recovery password"],
                  rows, indent=4)

        if readable:
            lines = [f"  - {comp}: {pw}  (GUID {guid or '?'})"
                     for (comp, guid, pw) in readable]
            ctx.quick_wins.add(
                Severity.CRITICAL,
                f"BitLocker — {len(readable)} recovery key(s) readable",
                "The current identity can read BitLocker recovery passwords from "
                "AD → offline access to the encrypted volume(s):\n"
                + "\n".join(lines) + "\n"
                "  # Windows: manage-bde -unlock <X>: -RecoveryPassword <48-digit>\n"
                "  # Linux (image/device): "
                "dislocker -r -p<48-digit> -V <device> -- /mnt/bl && "
                "mount -o loop,ro /mnt/bl/dislocker-file /mnt/clear",
            )

        if withheld and not readable:
            out.info(
                f"{len(withheld)} machine(s) escrow BitLocker to AD, but the "
                "recovery password is not readable by the current identity "
                "(needs Domain Admins or a delegated read on the computer object)."
            )
