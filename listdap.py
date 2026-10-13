#!/usr/bin/env python3
"""
listdap — LDAP enumeration for offensive security assessments.

Usage examples:
  # Anonymous
  python3 listdap.py -d corp.local -dc 192.168.1.10

  # With credentials (Kerberos first, NTLM fallback)
  python3 listdap.py -d corp.local -dc 192.168.1.10 -u alice -p 'P@ssw0rd'

  # With existing ccache
  python3 listdap.py -d corp.local -dc 192.168.1.10 -u alice --ccache /tmp/alice.ccache

  # KRB5CCNAME already set
  KRB5CCNAME=/tmp/alice.ccache python3 listdap.py -d corp.local -dc 192.168.1.10 -u alice

  # LDAPS, specific modules only, dump users
  python3 listdap.py -d corp.local -dc 192.168.1.10 -u alice -p pass --ldaps \
      --modules users,groups,acls --dump /tmp/corp
"""

import sys
import os
import argparse
from argparse import Namespace

# Ensure repo root is on path when invoked from outside the directory
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

__version__ = "2.1.0"

from core.connection import connect
from core.auth import AuthError
from core.output import Output, QuickWinsCollector
from modules.base import ScanContext
from utils.dump import DumpManager

# Module registry — order matters (domain first, quick wins last)
from modules.domain      import DomainModule
from modules.users       import UsersModule
from modules.groups      import GroupsModule
from modules.computers   import ComputersModule
from modules.gpo         import GPOModule
from modules.policies    import PoliciesModule
from modules.trusts      import TrustsModule
from modules.delegations import DelegationsModule
from modules.acls        import ACLsModule
from modules.laps        import LAPSModule
from modules.adcs        import ADCSModule
from modules.shadow      import ShadowModule

ALL_MODULES = [
    DomainModule(),
    UsersModule(),
    GroupsModule(),
    ComputersModule(),
    GPOModule(),
    PoliciesModule(),
    TrustsModule(),
    DelegationsModule(),
    ACLsModule(),
    LAPSModule(),
    ADCSModule(),
    ShadowModule(),
]

MODULE_MAP = {m.name: m for m in ALL_MODULES}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="listdap",
        description="LDAP enumeration for offensive security assessments",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_epilog(),
    )

    p.add_argument("-V", "--version", action="version",
                   version=f"%(prog)s {__version__}")

    # Target
    tgt = p.add_argument_group("Target")
    tgt.add_argument("-d",  "--domain",  metavar="DOMAIN",  help="Domain name (e.g. corp.local)")
    tgt.add_argument("-dc", "--dc",      metavar="DC_IP",   required=True, help="Domain Controller IP or hostname")
    tgt.add_argument("--port",           metavar="PORT",    type=int, default=0,
                     help="LDAP port (default: 389 / 636 with --ldaps)")
    tgt.add_argument("--ldaps",          action="store_true", help="Use LDAPS (TLS)")
    tgt.add_argument("--gc",             action="store_true",
                     help="Use Global Catalog port (3268/3269 with --ldaps)")

    # Authentication
    auth = p.add_argument_group("Authentication")
    auth.add_argument("-u", "--username", metavar="USER",   help="Username")
    auth.add_argument("-p", "--password", metavar="PASS",   help="Password")
    auth.add_argument("--ccache",         metavar="FILE",   help="Path to Kerberos ccache file")
    auth.add_argument("--no-kerberos",    action="store_true",
                      help="Skip Kerberos, use NTLM directly")

    # Modules
    mods = p.add_argument_group("Modules")
    mods.add_argument(
        "--modules", metavar="MOD1,MOD2",
        help="Comma-separated list of modules to run (default: all). "
             "Available: " + ", ".join(MODULE_MAP.keys()),
    )

    # Output
    out = p.add_argument_group("Output")
    out.add_argument("--dump",    metavar="PREFIX",
                     help="Dump user lists to PREFIX_all_users.txt, PREFIX_spn_users.txt, PREFIX_np_users.txt")
    out.add_argument("-U", "--user-file", metavar="FILE",
                     help="Write all domain users (one login per line) to FILE, "
                          "ready for `nxc ... -u FILE`")
    out.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    out.add_argument("--inactive-days", type=int, default=90, metavar="DAYS",
                     help="Days threshold for inactive accounts (default: 90)")

    return p


def _epilog() -> str:
    lines = ["Available modules:"]
    for m in ALL_MODULES:
        lines.append(f"  {m.name:<16} {m.description}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser  = build_parser()
    args    = parser.parse_args()

    out = Output(verbose=args.verbose)

    # Banner
    print()
    print("  ██╗     ██╗███████╗████████╗██████╗  █████╗ ██████╗ ")
    print("  ██║     ██║██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██╔══██╗")
    print("  ██║     ██║███████╗   ██║   ██║  ██║███████║██████╔╝")
    print("  ██║     ██║╚════██║   ██║   ██║  ██║██╔══██║██╔═══╝ ")
    print("  ███████╗██║███████║   ██║   ██████╔╝██║  ██║██║     ")
    print("  ╚══════╝╚═╝╚══════╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝     ")
    print(f"  LDAP enumeration for offensive assessments · v{__version__}")
    print()

    # Resolve port (GC takes priority if --gc)
    port = args.port
    if port == 0:
        if args.gc:
            port = 3269 if args.ldaps else 3268
        else:
            port = 636 if args.ldaps else 389

    # Determine domain
    domain = args.domain or ""

    # Connect
    out.info(f"Connecting to {args.dc}:{port} ({'LDAPS' if args.ldaps else 'LDAP'})")

    try:
        conn = connect(
            host=args.dc,
            domain=domain,
            username=args.username or "",
            password=args.password or "",
            ccache=args.ccache or "",
            no_kerberos=args.no_kerberos,
            use_tls=args.ldaps,
            port=port,
            dc_ip=args.dc,
        )
    except AuthError as e:
        out.error(f"Authentication failed: {e}")
        return 1
    except Exception as e:
        out.error(f"Connection failed: {e}")
        return 1

    # Show auth banner
    dc   = conn.dc_info
    auth = conn.auth_result
    out.auth_banner(
        auth_type=auth.auth_type.value,
        target=f"{args.dc}:{port}",
        base_dn=dc.base_dn or "(unknown)",
    )

    # Explain auth escalation / fallback
    if auth.note:
        out.info(auth.note)
    if auth.fallback_reasons:
        from core.output import C
        if auth.auth_type.value.lower().startswith("anonymous"):
            out.warning("Authenticated bind failed — fell back to ANONYMOUS (read-only)")
        else:
            out.warning("Kerberos not used — fell back to " + auth.auth_type.value)
        for reason in auth.fallback_reasons:
            print(f"        {C.DIM}{C.YELLOW}↳ {reason}{C.RESET}")

    if not dc.base_dn:
        out.warning("Could not determine base DN from rootDSE. "
                    "Specify --domain to set it manually.")
        conn.close()
        return 1

    # Module selection
    if args.modules:
        selected_names = [m.strip() for m in args.modules.split(",")]
        unknown = [n for n in selected_names if n not in MODULE_MAP]
        if unknown:
            out.error(f"Unknown module(s): {', '.join(unknown)}")
            out.error(f"Available: {', '.join(MODULE_MAP.keys())}")
            conn.close()
            return 1
        selected = [MODULE_MAP[n] for n in selected_names]
    else:
        selected = ALL_MODULES

    # Dump manager (needed for --dump prefixed lists and/or --user-file)
    dump = DumpManager(args.dump) if (args.dump or args.user_file) else None

    # Scan context
    quick_wins = QuickWinsCollector()
    ctx = ScanContext(
        conn=conn,
        out=out,
        quick_wins=quick_wins,
        args=args,
        dump=dump,
    )

    # Enable LDAP-backed SID → sAMAccountName resolution for custom principals
    # (RID >= 1000) across all modules, with caching.
    from utils.sids import set_sid_resolver, make_ldap_sid_resolver
    set_sid_resolver(make_ldap_sid_resolver(conn))

    # Run modules
    errors = []
    for module in selected:
        try:
            module.run(ctx)
        except Exception as e:
            out.error(f"Module '{module.name}' failed: {e}")
            if args.verbose:
                import traceback
                traceback.print_exc()
            errors.append(module.name)

    # Quick Wins summary
    quick_wins.display(out)

    # Dump files
    if dump:
        print()
        written = []
        if args.dump:
            written += dump.write_files()
        if args.user_file:
            uf = dump.write_user_file(args.user_file)
            if uf:
                written.append(uf)
        if written:
            out.success("Dump files written:")
            for f in written:
                out.kv("  File", f)
        else:
            out.info("No users found to dump")

    print()
    conn.close()
    return 0 if not errors else 2


if __name__ == "__main__":
    sys.exit(main())
