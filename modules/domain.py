"""
Domain module — general domain information, FSMO roles, domain SID.
"""

import ldap3

from modules.base import BaseModule, ScanContext
from utils.ldap_helpers import ldap_search, get_attr, get_int
from utils.sids import bytes_to_sid


class DomainModule(BaseModule):
    name        = "domain"
    description = "Domain info, functional levels, FSMO roles"

    def run(self, ctx: ScanContext) -> None:
        out  = ctx.out
        conn = ctx.conn
        dc   = conn.dc_info

        out.section("DOMAIN INFORMATION")

        # --- Basic info from rootDSE (already parsed at connect time) ---
        out.kv("Domain",               dc.domain or "(unknown)")
        out.kv("Base DN",              dc.base_dn)
        out.kv("Forest DN",            dc.forest_dn or "(unknown)")
        out.kv("DC Hostname",          dc.hostname)
        out.kv("Domain Func. Level",   dc.domain_func_level or "Unknown")
        out.kv("Forest Func. Level",   dc.forest_func_level or "Unknown")

        # --- Auth details ---
        auth = conn.auth_result
        out.kv("Auth Method",          auth.auth_type.value)
        if auth.note:
            out.kv("Auth Note",        auth.note)
        if auth.username:
            user_str = f"{auth.domain}\\{auth.username}" if auth.domain else auth.username
            out.kv("Authenticated as", user_str)

        # --- Domain object (objectSid, creation date) ---
        self._query_domain_object(ctx)

        # --- FSMO roles ---
        self._query_fsmo(ctx)

        # --- MachineAccountQuota ---
        self._query_maq(ctx)

        # --- Pre-Windows 2000 Compatible Access group ---
        self._query_pre2k(ctx)

    # ------------------------------------------------------------------

    def _query_domain_object(self, ctx: ScanContext) -> None:
        out  = ctx.out
        entries = ctx.conn.search(
            ldap_filter="(objectClass=domain)",
            attributes=["objectSid", "whenCreated", "ms-DS-MachineAccountQuota"],
            base=ctx.base_dn,
            scope=ldap3.BASE,
        )
        if not entries:
            return

        entry = entries[0]

        # Domain SID
        try:
            raw_sid = entry["objectSid"].raw_values
            if raw_sid:
                sid_str = bytes_to_sid(raw_sid[0])
                ctx.conn.dc_info.domain_sid = sid_str
                out.kv("Domain SID", sid_str)
        except Exception:
            pass

        # Creation date
        try:
            when = entry["whenCreated"].value
            if when:
                out.kv("Domain Created", str(when))
        except Exception:
            pass

    def _query_fsmo(self, ctx: ScanContext) -> None:
        out = ctx.out
        dc  = ctx.conn.dc_info

        out.subsection("FSMO Roles")

        # PDC Emulator, RID Master, Infrastructure Master — from domain partition
        entries = ctx.conn.search(
            ldap_filter="(fSMORoleOwner=*)",
            attributes=["fSMORoleOwner", "distinguishedName"],
        )
        for entry in entries:
            dn    = get_attr(entry, "distinguishedName")
            owner = get_attr(entry, "fSMORoleOwner")
            role  = self._guess_role(dn, ctx.base_dn, ctx.conn.dc_info.schema_dn,
                                     ctx.conn.dc_info.config_dn)
            if role:
                # owner is the NTDS Settings DN; strip to server name
                server = self._ntds_to_server(owner)
                out.kv(role, server)

        # Schema Master — from schema partition
        if dc.schema_dn:
            schema_entries = ctx.conn.search(
                ldap_filter="(fSMORoleOwner=*)",
                attributes=["fSMORoleOwner"],
                base=dc.schema_dn,
                scope=ldap3.BASE,
            )
            for e in schema_entries:
                owner = get_attr(e, "fSMORoleOwner")
                out.kv("Schema Master", self._ntds_to_server(owner))

        # Domain Naming Master — from partitions container in config
        if dc.config_dn:
            partitions_dn = f"CN=Partitions,{dc.config_dn}"
            part_entries = ctx.conn.search(
                ldap_filter="(fSMORoleOwner=*)",
                attributes=["fSMORoleOwner"],
                base=partitions_dn,
                scope=ldap3.BASE,
            )
            for e in part_entries:
                owner = get_attr(e, "fSMORoleOwner")
                out.kv("Domain Naming Master", self._ntds_to_server(owner))

    def _query_maq(self, ctx: ScanContext) -> None:
        out = ctx.out
        entries = ctx.conn.search(
            ldap_filter="(objectClass=domain)",
            attributes=["ms-DS-MachineAccountQuota"],
            base=ctx.base_dn,
            scope=ldap3.BASE,
        )
        if not entries:
            return
        maq = get_int(entries[0], "ms-DS-MachineAccountQuota", -1)
        if maq == -1:
            return
        if maq > 0:
            out.warning(f"MachineAccountQuota = {maq}  (any authenticated user can create {maq} machine accounts → RBCD vector)")
            from core.output import Severity
            ctx.quick_wins.add(
                Severity.HIGH,
                f"MachineAccountQuota = {maq}",
                "Any authenticated user can add machine accounts to the domain — enables RBCD attacks.",
            )
        else:
            out.success(f"MachineAccountQuota = {maq}  (safe)")

    def _query_pre2k(self, ctx: ScanContext) -> None:
        """Check if 'Pre-Windows 2000 Compatible Access' group has interesting members."""
        out     = ctx.out
        entries = ctx.conn.search(
            ldap_filter="(sAMAccountName=Pre-Windows 2000 Compatible Access)",
            attributes=["member", "distinguishedName"],
        )
        if not entries:
            return

        members = []
        try:
            m = entries[0]["member"].value
            if isinstance(m, list):
                members = m
            elif m:
                members = [m]
        except Exception:
            pass

        risky = [m for m in members if "S-1-1-0" in m or "S-1-5-7" in m
                 or "Everyone" in m or "Anonymous" in m]
        if risky or not members:
            return

        # Has non-trivial members — might be an issue depending on context
        out.subsection("Pre-Windows 2000 Compatible Access")
        out.info(f"{len(members)} member(s) in Pre-Windows 2000 Compatible Access group")

    @staticmethod
    def _guess_role(dn: str, base_dn: str, schema_dn: str, config_dn: str) -> str:
        dn_l = dn.lower()
        if base_dn and dn_l == base_dn.lower():
            return "PDC Emulator / RID Master"  # simplified
        if "ridmanager" in dn_l:
            return "RID Master"
        if "infrastructure" in dn_l:
            return "Infrastructure Master"
        return ""

    @staticmethod
    def _ntds_to_server(ntds_dn: str) -> str:
        """
        'CN=NTDS Settings,CN=DC01,CN=Servers,...' → 'DC01'
        """
        if not ntds_dn:
            return "(unknown)"
        parts = [p.strip() for p in ntds_dn.split(",")]
        # Find CN= after 'CN=NTDS Settings'
        for i, part in enumerate(parts):
            if part.upper() == "CN=NTDS SETTINGS" and i + 1 < len(parts):
                return parts[i + 1].split("=", 1)[-1]
        # Fallback: second CN
        cns = [p.split("=", 1)[-1] for p in parts if p.upper().startswith("CN=")]
        return cns[1] if len(cns) > 1 else ntds_dn
