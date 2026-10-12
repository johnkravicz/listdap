"""
Base module class and ScanContext.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional
from argparse import Namespace

import ldap3

from core.connection import LDAPConnection
from core.output import Output, QuickWinsCollector
from utils.dump import DumpManager
from utils.sids import bytes_to_sid


@dataclass
class ScanContext:
    conn:        LDAPConnection
    out:         Output
    quick_wins:  QuickWinsCollector
    args:        Namespace
    dump:        Optional[DumpManager] = None
    _current_user_sids: Optional[frozenset] = None

    @property
    def base_dn(self) -> str:
        return self.conn.base_dn

    @property
    def domain(self) -> str:
        return self.conn.domain

    @property
    def domain_sid(self) -> str:
        """Domain SID, fetched on demand.

        Normally populated by the domain module, but modules may run in any
        order (or in isolation via --modules), so resolve and cache it lazily
        here. Without it, SID → name resolution and RID-based low-priv checks
        (e.g. ESC1/2/3 enrollment rights) silently degrade.
        """
        sid = self.conn.dc_info.domain_sid
        if sid:
            return sid
        try:
            entries = self.conn.search(
                ldap_filter="(objectClass=domain)",
                attributes=["objectSid"],
                base=self.base_dn,
                scope=ldap3.BASE,
            )
            if entries:
                raw = entries[0]["objectSid"].raw_values
                if raw:
                    sid = bytes_to_sid(raw[0])
                    self.conn.dc_info.domain_sid = sid  # cache
        except Exception:
            pass
        return sid

    @property
    def current_user_sids(self) -> frozenset:
        """SIDs of the authenticated user: own objectSid + all token groups.

        Used to assess exploitability relative to the current identity (like
        certipy -vulnerable): a right granted directly to this user, or to any
        group they belong to (incl. nested, via the tokenGroups constructed
        attribute), counts as actionable. Empty for anonymous binds.
        """
        if self._current_user_sids is not None:
            return self._current_user_sids

        sids = set()
        user = (getattr(self.args, "username", "") or "").split("@")[0]
        try:
            if user:
                safe = user.replace("\\", "\\5c").replace("(", "\\28").replace(")", "\\29")
                res = self.conn.search(
                    ldap_filter=f"(sAMAccountName={safe})",
                    attributes=["distinguishedName", "objectSid"],
                    base=self.base_dn,
                )
                if res:
                    try:
                        raw = res[0]["objectSid"].raw_values
                        if raw:
                            sids.add(bytes_to_sid(raw[0]))
                    except Exception:
                        pass
                    dn = res[0].entry_dn
                    tg = self.conn.search(
                        ldap_filter="(objectClass=*)",
                        attributes=["tokenGroups"],
                        base=dn,
                        scope=ldap3.BASE,
                    )
                    if tg:
                        try:
                            for rv in tg[0]["tokenGroups"].raw_values:
                                s = bytes_to_sid(rv)
                                if s:
                                    sids.add(s)
                        except Exception:
                            pass
        except Exception:
            pass

        self._current_user_sids = frozenset(sids)
        return self._current_user_sids


class BaseModule(ABC):
    #: Short identifier used in --modules (e.g. "users")
    name: str = ""
    #: One-line description shown in help
    description: str = ""

    @abstractmethod
    def run(self, ctx: ScanContext) -> None: ...

    def __repr__(self) -> str:
        return f"<Module:{self.name}>"
