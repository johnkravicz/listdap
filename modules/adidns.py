"""
ADIDNS module — Active Directory-integrated DNS enumeration & spoofing surface.

AD-integrated DNS zones live in LDAP application partitions
(`DC=DomainDnsZones,…`, `DC=ForestDnsZones,…`, legacy `CN=MicrosoftDNS,CN=System,…`)
and are readable by any authenticated user. Each zone is a `dnsZone` object; each
record is a `dnsNode` child whose binary `dnsRecord` attribute holds the type +
value. Two angles:

1. **Recon.** Parsing `dnsRecord` yields the full internal name→IP map (A/AAAA),
   services (SRV/CNAME), and often hosts that never appear in the computers
   module — all without a single DNS query or zone transfer.

2. **Spoofing / takeover.** By default the zone DACL grants *Authenticated Users*
   (and sometimes Everyone) the **Create Child** right → any user can add a new
   record (classic `wpad` / missing-name injection → NTLM coercion & relay,
   Kevin Robertson's Powermad / dirkjanm's dnstool.py). Where an individual
   record's DACL is writable by a non-privileged principal, that existing name
   can be **overwritten** (hijack a server's A record).

Pure LDAP: zone + node reads, `dnsRecord` parsing (utils.dnsrecord) and DACL
parsing (reuses modules.acls._parse_dacl). No writes.

Wildcard awareness (v2.14.0): a `*` record answers every unresolved name in a
zone, so its presence neutralises classic missing-name / wpad injection there but
makes the `*` itself a domain-wide takeover primitive.

Attack-surface framing (v2.20.0): the value is not the full record dump (recon
only — demoted behind `-v`) but the **gaps you can act on**. For every zone where
the current identity holds Create-Child, the module lists the high-value names
that are ABSENT and therefore *plantable* — `*` (CRITICAL, domain-wide catch-all),
`wpad` (HIGH, WPAD coercion), `isatap` (MEDIUM) — each with a ready dnstool.py /
Powermad command. A present `*` in a zone neutralises planting there (overwrite it
instead → see writable records).
"""

from modules.base import BaseModule, ScanContext
from core.output import Severity, C
from utils.ldap_helpers import get_attr, get_list, get_raw, get_raw_all, get_dn, SCOPE_SUBTREE
from utils.sids import resolve_sid, is_privileged_sid, is_high_value_sid, bytes_to_sid
from utils.dnsrecord import parse_records
from modules.acls import (
    _parse_dacl, GENERIC_ALL, GENERIC_WRITE, WRITE_DACL, WRITE_OWNER,
    RIGHT_DS_WRITE_PROP, FULL_CONTROL,
)

# ADS_RIGHT_DS_CREATE_CHILD — add a child object (here: a new DNS record).
CREATE_CHILD = 0x00000001

# Trustees that make a Create-Child grant broadly exploitable (any domain user /
# any machine can spoof). Domain-relative RIDs are matched separately.
_BROAD_WELL_KNOWN = {
    "S-1-1-0",       # Everyone
    "S-1-5-11",      # Authenticated Users
    "S-1-5-32-545",  # BUILTIN\Users
}
_BROAD_RIDS = {"513", "515", "545"}  # Domain Users, Domain Computers, (Users)

# Contextual / system trustees to ignore when scanning a record's own DACL:
# they are either noise (Creator Owner, Self) or already privileged.
_SKIP_SIDS = {
    "S-1-5-18",      # Local System
    "S-1-5-10",      # Self
    "S-1-3-0",       # Creator Owner
    "S-1-5-9",       # Enterprise Domain Controllers
}

# Any of these in a record's ACE mask = the trustee can overwrite the record.
_WRITE_BITS = (GENERIC_ALL | GENERIC_WRITE | WRITE_DACL | WRITE_OWNER
               | RIGHT_DS_WRITE_PROP)


def _is_broad(sid: str, domain_sid: str) -> bool:
    if sid in _BROAD_WELL_KNOWN:
        return True
    if domain_sid and sid.startswith(domain_sid + "-"):
        return sid[len(domain_sid) + 1:] in _BROAD_RIDS
    return False


def _rdn_value(dn: str) -> str:
    """Leftmost RDN value: 'DC=wpad,DC=corp.local,…' → 'wpad'."""
    if not dn:
        return ""
    first = dn.split(",", 1)[0]
    return first.split("=", 1)[-1] if "=" in first else first


def _zone_of(dn: str) -> str:
    """Zone name = the parent RDN value of a dnsNode DN."""
    if not dn or "," not in dn:
        return ""
    return _rdn_value(dn.split(",", 1)[1])


class ADIDNSModule(BaseModule):
    name        = "adidns"
    description = "AD-integrated DNS: records (recon) + zone/record spoofing surface"

    def run(self, ctx: ScanContext) -> None:
        out = ctx.out
        out.section("ADIDNS — AD-INTEGRATED DNS")

        partitions = self._partitions(ctx)
        zones: dict[str, dict] = {}   # zone DN -> {name, sd}
        nodes: list[dict] = []        # {name, zone, fqdn, records, sd}

        for base in partitions:
            entries = ctx.conn.search(
                "(|(objectClass=dnsZone)(objectClass=dnsNode))",
                ["name", "dc", "dnsRecord", "nTSecurityDescriptor", "objectClass"],
                base=base, scope=SCOPE_SUBTREE,
            )
            for e in entries:
                classes = {c.lower() for c in get_list(e, "objectClass")}
                dn = get_dn(e)
                if "dnszone" in classes:
                    zones[dn] = {
                        "name": get_attr(e, "dc") or get_attr(e, "name") or _rdn_value(dn),
                        "sd":   get_raw(e, "nTSecurityDescriptor"),
                    }
                elif "dnsnode" in classes:
                    recs = parse_records(get_raw_all(e, "dnsRecord"))
                    # drop pure tombstones (ZERO-only nodes)
                    if all(r[0] == "ZERO" for r in recs):
                        continue
                    label = get_attr(e, "dc") or _rdn_value(dn)
                    zone  = _zone_of(dn)
                    fqdn  = zone if label == "@" else f"{label}.{zone}"
                    nodes.append({
                        "name": label, "zone": zone, "fqdn": fqdn,
                        "records": recs, "sd": get_raw(e, "nTSecurityDescriptor"),
                    })

        if not zones and not nodes:
            out.info("No AD-integrated DNS zones readable (none present, or the "
                     "DNS partitions are not reachable by this identity)")
            return

        out.counter("DNS zones", len(zones), {"records": len(nodes)})

        wild_nodes = [n for n in nodes if n["name"] == "*"]
        wild_zones = {n["zone"].lower() for n in wild_nodes}

        # DNS-administrative groups legitimately hold write on every record/zone;
        # exclude them so a real low-priv finding is not drowned (and a writable
        # wildcard is not falsely escalated to CRITICAL via their default ACE).
        dns_sids = self._dns_admin_sids(ctx)

        self._dump_records(ctx, nodes)
        self._report_wildcards(ctx, wild_nodes)
        spoofable = self._spoofable_zones(ctx, zones, dns_sids)
        self._check_zone_create(ctx, spoofable)
        self._check_missing_names(ctx, spoofable, nodes, wild_zones)
        self._check_record_dacls(ctx, nodes, dns_sids)

    @staticmethod
    def _dns_admin_sids(ctx: ScanContext) -> set:
        """SIDs of the DNS-admin groups (write on DNS is expected / by design)."""
        sids = set()
        for name in ("DnsAdmins", "DnsUpdateProxy"):
            try:
                res = ctx.conn.search(f"(sAMAccountName={name})", ["objectSid"])
            except Exception:
                res = []
            if res:
                raw = get_raw(res[0], "objectSid")
                if raw:
                    sids.add(bytes_to_sid(raw))
        return sids

    # ------------------------------------------------------------------ bases
    def _partitions(self, ctx: ScanContext) -> list[str]:
        base = ctx.base_dn
        forest = getattr(ctx.conn.dc_info, "forest_dn", "") or base
        cands = [
            f"DC=DomainDnsZones,{base}",
            f"DC=ForestDnsZones,{forest}",
            f"CN=MicrosoftDNS,CN=System,{base}",   # legacy (pre-2003 / replicated)
        ]
        seen, out = set(), []
        for c in cands:
            k = c.lower()
            if k not in seen:
                seen.add(k)
                out.append(c)
        return out

    # --------------------------------------------------------------- records
    def _dump_records(self, ctx: ScanContext, nodes: list) -> None:
        out = ctx.out
        if not nodes:
            return
        out.subsection("DNS records (recon)")
        hosts = sorted({n["fqdn"] for n in nodes
                        for (t, _v, _s) in n["records"] if t in ("A", "AAAA")})
        if getattr(ctx.args, "verbose", False):
            rows = []
            for n in sorted(nodes, key=lambda x: (x["zone"], x["name"])):
                for rtype, val, _ts in n["records"]:
                    if rtype == "ZERO":
                        continue
                    hl = (rtype in ("A", "AAAA", "CNAME", "SRV"))
                    rows.append([
                        n["fqdn"],
                        f"{C.CYAN}{rtype}{C.RESET}" if hl else rtype,
                        val,
                    ])
            out.table(["Name", "Type", "Value"], rows, indent=4)
        else:
            out.info(f"{len(nodes)} record(s), {len(hosts)} A/AAAA host(s) "
                     "— full table with -v. Recon value: hosts not joined to AD "
                     "(appliances / Linux / net gear) that the computers module misses.")
        if hosts:
            ctx.quick_wins.add(
                Severity.INFO,
                f"ADIDNS — internal name→IP map leaked ({len(hosts)} host record(s))",
                "AD-integrated DNS is readable over LDAP → the full internal DNS "
                "map was dumped without a single DNS query or zone transfer. Cross-"
                "reference with the computers module for hosts not joined to AD "
                "(appliances, Linux, network gear):\n  "
                + ", ".join(hosts[:20]) + (" …" if len(hosts) > 20 else ""),
            )

    # ----------------------------------------------------------- wildcards
    @staticmethod
    def _wild_value(node: dict) -> str:
        return ", ".join(f"{t} {v}" for (t, v, _s) in node["records"] if t != "ZERO")

    def _report_wildcards(self, ctx: ScanContext, wild_nodes: list) -> None:
        out = ctx.out
        out.subsection("Wildcard records (*)")
        if not wild_nodes:
            out.info("No '*' wildcard record present "
                     "(→ a non-priv create-child right lets one be planted; see below)")
            return

        rows = [[n["zone"], self._wild_value(n) or "-"] for n in wild_nodes]
        out.table(["Zone", "Wildcard (*) value"], rows, indent=4,
                  highlight_fn=lambda r: C.YELLOW)

        ctx.quick_wins.add(
            Severity.MEDIUM,
            f"ADIDNS — wildcard (*) record present in {len(wild_nodes)} zone(s)",
            "A '*' record answers every otherwise-unresolved name in the zone. Two "
            "consequences:\n"
            "  - it already catches missing-name / wpad queries, so classic ADIDNS "
            "name-injection is largely neutralised in that zone;\n"
            "  - whoever can overwrite the '*' controls resolution of ALL unresolved "
            "names (domain-wide MITM) — cross-check the 'writable records' finding, "
            "and confirm the current target is expected:\n"
            + "\n".join(f"  - {n['zone']}: {self._wild_value(n) or '(no data)'}"
                        for n in wild_nodes),
        )

    # ----------------------------------------------------------- zone spoof
    # High-value names an attacker plants into a create-child zone; the value is
    # in their ABSENCE (missing = plantable). Severity assumes broad reach.
    _PLANTABLE = [
        ("*",      Severity.CRITICAL,
         "wildcard — a domain-wide catch-all answering EVERY otherwise-unresolved "
         "name in the zone (WPAD, typos, dead hosts) → mass NTLM coercion / MITM"),
        ("wpad",   Severity.HIGH,
         "WPAD — clients fetch http://wpad/wpad.dat for proxy config → force traffic "
         "through an attacker proxy → NTLM capture / relay"),
        ("isatap", Severity.MEDIUM,
         "ISATAP — auto-tunnel router host; planting it can draw IPv6-in-IPv4 "
         "traffic to an attacker"),
    ]

    @staticmethod
    def _downgrade(sev):
        return {Severity.CRITICAL: Severity.HIGH,
                Severity.HIGH: Severity.MEDIUM}.get(sev, sev)

    def _spoofable_zones(self, ctx: ScanContext, zones: dict,
                         dns_sids: set = frozenset()) -> list:
        """Zones whose DACL grants Create-Child to a non-privileged principal.
        Returns (zone_name, trustee_name, trustee_sid, broad)."""
        dsid = ctx.domain_sid
        spoofable = []
        for z in zones.values():
            if not z["sd"]:
                continue
            best = None
            for ace in _parse_dacl(z["sd"]):
                sid = ace["sid"]
                if (sid in _SKIP_SIDS or sid in dns_sids
                        or is_privileged_sid(sid, dsid) or is_high_value_sid(sid, dsid)):
                    continue
                if ace["mask"] & (CREATE_CHILD | GENERIC_ALL | GENERIC_WRITE):
                    broad = _is_broad(sid, dsid)
                    if best is None or (broad and not best[2]):  # prefer broadest
                        best = (sid, resolve_sid(sid, dsid), broad)
            if best:
                spoofable.append((z["name"], best[1], best[0], best[2]))
        return spoofable

    def _check_zone_create(self, ctx: ScanContext, spoofable: list) -> None:
        """The permission surface: who can create records in which zone. The
        actionable 'what to plant' lives in _check_missing_names."""
        out = ctx.out
        out.subsection("Zone Create-Child (record spoofing surface)")
        if not spoofable:
            out.success("No zone grants Create-Child to a non-privileged principal")
            return
        rows = [[zn, tname, tsid, "broad (any user)" if broad else "group-scoped"]
                for (zn, tname, tsid, broad) in spoofable]
        out.table(["Zone", "Trustee", "SID", "Reach"], rows, indent=4,
                  highlight_fn=lambda r: C.RED if "broad" in r[3] else C.YELLOW)
        out.info("→ what to plant in these zones: see 'Plantable missing names' below")

    def _check_missing_names(self, ctx: ScanContext, spoofable: list,
                             nodes: list, wild_zones: set) -> None:
        """For each create-child zone, the high-value names that are ABSENT (and
        therefore plantable) — the actionable gap, not a full record dump."""
        out = ctx.out
        out.subsection("Plantable missing names (interesting absent records)")
        if not spoofable:
            out.info("No create-child zone for this identity → nothing plantable")
            return

        desc_of = {n: d for (n, _s, d) in self._PLANTABLE}
        rows, findings = [], []   # findings: (zn, tname, tsid, name, sev, broad)
        skipped = []
        for (zn, tname, tsid, broad) in spoofable:
            # wpad/catch-all only bite in a CLIENT-facing forward zone. Reverse
            # (.arpa) and locator/service zones (_msdcs, _sites, _tcp…) are
            # technical — clients never resolve wpad there, so skip them.
            if zn.endswith(".arpa") or any(p.startswith("_") for p in zn.split(".")):
                skipped.append(zn)
                continue
            have = {n["name"].lower() for n in nodes if n["zone"] == zn}
            if zn.lower() in wild_zones:
                rows.append([zn, "*", f"{C.YELLOW}present{C.RESET}",
                             "wildcard already answers unresolved names → overwrite "
                             "it instead (see writable records)"])
                continue
            for (name, sev, desc) in self._PLANTABLE:
                if name in have:
                    rows.append([zn, name, f"{C.GREEN}present{C.RESET}", "-"])
                else:
                    rows.append([zn, name, f"{C.RED}ABSENT → plantable{C.RESET}", desc])
                    findings.append((zn, tname, tsid, name, sev, broad))

        if rows:
            out.table(["Zone", "Name", "Status", "Why it matters"], rows, indent=4)
        if skipped:
            out.info(f"Skipped {len(skipped)} technical zone(s) (clients don't "
                     "resolve wpad there): " + ", ".join(sorted(set(skipped))))
        if not findings:
            out.info("No high-value name is both absent and plantable here")
            return

        for (zn, tname, tsid, name, sev, broad) in findings:
            eff = sev if broad else self._downgrade(sev)
            rec = "'*'" if name == "*" else name
            who = "any user" if broad else tname
            ctx.quick_wins.add(
                eff,
                f"ADIDNS — plant missing '{name}' in zone {zn} ({who})",
                f"'{name}' is ABSENT from {zn} and this identity has Create-Child "
                f"there → it can be planted. {desc_of[name]}.\n"
                "  # dirkjanm dnstool.py (impacket):\n"
                f"  python3 dnstool.py -u '{self._upn(ctx)}' -p '<password>' "
                f"--action add --record {rec} --data <ATTACKER_IP> --type A "
                f"--zone {zn} {ctx.args.dc}\n"
                "  # or Powermad (domain-joined Windows host):\n"
                f"  Invoke-DNSUpdate -DNSType A -DNSName {name} -DNSData <ATTACKER_IP>\n"
                "  then coerce + relay (impacket-ntlmrelayx) / intercept the "
                "redirected auth.",
            )

    # ---------------------------------------------------- record overwrite
    def _check_record_dacls(self, ctx: ScanContext, nodes: list,
                            dns_sids: set = frozenset()) -> None:
        out = ctx.out
        out.subsection("Writable existing records (hijack)")
        dsid = ctx.domain_sid

        findings = []   # (fqdn, types, trustee, sid, is_wild)
        for n in nodes:
            if not n["sd"]:
                continue
            types = ",".join(sorted({t for (t, _v, _s) in n["records"]
                                     if t != "ZERO"}))
            is_wild = n["name"] == "*"
            for ace in _parse_dacl(n["sd"]):
                sid = ace["sid"]
                if (sid in _SKIP_SIDS or sid in dns_sids
                        or is_privileged_sid(sid, dsid) or is_high_value_sid(sid, dsid)):
                    continue
                mask = ace["mask"]
                if (mask & _WRITE_BITS) or (mask & FULL_CONTROL) == FULL_CONTROL:
                    findings.append((n["fqdn"], types or "-",
                                     resolve_sid(sid, dsid), sid, is_wild))
                    break   # one finding per record is enough

        if not findings:
            out.success("No existing record is writable by a non-privileged principal")
            return

        rows = [[("* " + fqdn) if w else fqdn, types, tname]
                for (fqdn, types, tname, _s, w) in findings]
        out.table(["Record", "Type(s)", "Writable by"], rows, indent=4,
                  highlight_fn=lambda r: C.RED)

        has_wild = any(w for (_f, _t, _n, _s, w) in findings)
        lines = [f"  - {fqdn} ({types}) writable by {tname}"
                 + ("   ⚠ WILDCARD → controls ALL unresolved names in the zone"
                    if w else "")
                 for (fqdn, types, tname, _s, w) in findings]
        ctx.quick_wins.add(
            Severity.CRITICAL if has_wild else Severity.HIGH,
            f"ADIDNS — {len(findings)} existing record(s) writable by non-priv principals"
            + (" (incl. a WILDCARD)" if has_wild else ""),
            "A non-privileged principal can overwrite these existing DNS records "
            "→ hijack a legitimate name (redirect a server's A record to an "
            "attacker host for coercion / MITM)."
            + (" A writable '*' wildcard is domain-wide: it hijacks resolution of "
               "every otherwise-unresolved name at once.\n" if has_wild else "\n")
            + "\n".join(lines) + "\n"
            "  # overwrite with dnstool.py --action modify:\n"
            f"  python3 dnstool.py -u '{self._upn(ctx)}' -p '<password>' "
            "--action modify --record <name> --data <ATTACKER_IP> --type A "
            "--zone <zone> " + ctx.args.dc,
        )

    # --------------------------------------------------------------- helpers
    @staticmethod
    def _upn(ctx: ScanContext) -> str:
        a = ctx.args
        user = (getattr(a, "username", "") or "").split("@")[0] or "<user>"
        dom  = ctx.domain or (getattr(a, "domain", "") or "")
        return f"{dom}\\{user}" if dom else user
