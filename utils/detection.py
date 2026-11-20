"""Detection registry — single source of truth for listdap's own footprint.

Maps each listdap module to the artifacts it generates on a Domain Controller,
grounded in the Phase 5 lab measurement (see lab/results/phase5/). One registry
drives two views:

  * BLUE  (`blue_markdown` / `--blue`): the detection map — per module, which
    events fire, in which log, and under WHICH audit prerequisite (almost every
    object-level artifact needs a SACL or advanced-audit subcategory that is OFF
    by default, so each one carries its `condition`).
  * RED   (`module_signal` / `--stealth`): how loud each module is and why, so a
    stealth profile can throttle, reorder or skip the noisy ones.

IMPORTANT — honesty of the map:
  * `default_on=True`  -> visible on a stock Server 2025 DC (no tuning).
  * `default_on=False` -> needs the stated `condition`; invisible otherwise.
  * `tested=True`      -> observed live in Phase 5 on the lab DC.
  * `tested=False`     -> inferred / documented only (e.g. MDI: no sensor in lab).
Measured on a single Server 2025 DC with TARGETED SACLs; a differently-audited
DC will differ — the map states conditions, not guarantees.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Log(str, Enum):
    SEC = "Security"
    SYSMON = "Microsoft-Windows-Sysmon/Operational"
    DS = "Directory Service"
    MDI = "Microsoft Defender for Identity (alert)"


Signal = str  # "low" | "medium" | "high"


@dataclass(frozen=True)
class Artifact:
    """One detectable artifact a listdap operation can produce."""
    event_id: int                 # Windows event ID (0 = not an event, e.g. MDI alert)
    log: Log
    name: str
    condition: str                # audit prerequisite; "" means on by default
    default_on: bool              # visible with stock Server 2025 DC audit policy
    red_signal: Signal            # how telltale this artifact is to a SOC
    mdi: str = ""                 # related MDI alert name, if any (usually untested)
    tested: bool = True           # observed live in Phase 5
    note: str = ""


# --- Per-connection auth baseline: every authenticated listdap bind emits this.
# Visible BY DEFAULT. Repeated once per LDAP bind (see ModuleFootprint.binds).
AUTH_BASELINE: list[Artifact] = [
    Artifact(4776, Log.SEC, "NTLM credential validation",
             "", True, "medium", tested=True,
             note="listdap binds via signed NTLM by default -> this is THE default tell; "
                  "no 4768/4769 unless given a ccache (then Kerberos instead)."),
    Artifact(4624, Log.SEC, "Logon (type 3)",
             "", True, "medium", tested=True,
             note="IpAddress = attacker host; the source IP is the pivot for the SOC."),
    Artifact(4672, Log.SEC, "Special privileges assigned",
             "", True, "low", tested=True,
             note="fires even for a low-priv account on Server 2025 (env-specific)."),
    Artifact(4634, Log.SEC, "Logoff",
             "", True, "low", tested=True),
]

# --- Reusable object-level artifacts (all conditional on audit tuning) ---------
A_DS_READ = Artifact(
    4662, Log.SEC, "Operation on DS object (read)",
    "SACL auditing Read on the target object (OFF by default)",
    default_on=False, red_signal="medium", tested=True,
    note="volume grows with the number of objects/SDs/attributes read, and is "
         "markedly higher as a privileged account.")
A_SAM = Artifact(
    4661, Log.SEC, "Handle to SAM/DS object",
    "Advanced Audit: Audit SAM (OFF by default)",
    default_on=False, red_signal="high", tested=True,
    mdi="User and group membership reconnaissance (SAMR)",
    note="SAMR account-DB read path (rpc module).")
A_IPC = Artifact(
    5140, Log.SEC, "Network share accessed (IPC$)",
    "Advanced Audit: Audit File Share (OFF by default)",
    default_on=False, red_signal="medium", tested=True)
A_PIPE = Artifact(
    5145, Log.SEC, "Detailed file share (named pipe)",
    "Advanced Audit: Audit Detailed File Share (OFF by default)",
    default_on=False, red_signal="medium", tested=True,
    note="SMB named-pipe access (\\samr, \\lsarpc, certsrv/CA).")

# MDI alerts are LDAP-pattern driven, not a single event; untested (no sensor).
MDI_LDAP_RECON = Artifact(
    0, Log.MDI, "Security principal reconnaissance (LDAP)",
    "MDI sensor on the DC (licensed)", default_on=False, red_signal="high",
    mdi="Security principal reconnaissance (LDAP)", tested=False,
    note="triggered by broad directory enumeration; inferred, not validated in lab.")


@dataclass
class ModuleFootprint:
    module: str
    binds: int                     # measured LDAP binds per run (= auth-quartet repeats)
    artifacts: list[Artifact] = field(default_factory=list)
    red_signal: Signal = "low"     # overall default-case loudness
    note: str = ""


# Measured in Phase 5 (lab/results/phase5/detection_matrix.md), 2026-11-20.
REGISTRY: dict[str, ModuleFootprint] = {
    "domain":      ModuleFootprint("domain", 1, [A_DS_READ], "low"),
    "users":       ModuleFootprint("users", 2, [A_DS_READ, MDI_LDAP_RECON], "low",
                        note="broad user enumeration -> MDI LDAP-recon candidate."),
    "groups":      ModuleFootprint("groups", 2, [A_DS_READ, MDI_LDAP_RECON], "low"),
    "computers":   ModuleFootprint("computers", 2, [A_DS_READ, MDI_LDAP_RECON], "low"),
    "gpo":         ModuleFootprint("gpo", 2, [A_DS_READ], "low",
                        note="high 4662 volume when SysVol/GPO objects are SACLed."),
    "policies":    ModuleFootprint("policies", 2, [A_DS_READ], "low"),
    "trusts":      ModuleFootprint("trusts", 3, [MDI_LDAP_RECON], "medium",
                        note="no 4662 in lab: trustedDomain objects were not SACLed; "
                             "3 binds -> medium default volume."),
    "adidns":      ModuleFootprint("adidns", 2, [A_DS_READ], "low"),
    "delegations": ModuleFootprint("delegations", 6, [A_DS_READ], "medium",
                        note="6 binds -> loudest by auth volume after rpc."),
    "gmsa":        ModuleFootprint("gmsa", 2, [A_DS_READ], "low",
                        note="managed-password read on the gMSA object (if SACLed)."),
    "sidhistory":  ModuleFootprint("sidhistory", 2, [], "low",
                        note="no 4662 in lab: sIDHistory read on user objects not SACLed."),
    "fsp":         ModuleFootprint("fsp", 2, [A_DS_READ], "low"),
    "acls":        ModuleFootprint("acls", 2, [A_DS_READ], "medium",
                        note="reads many nTSecurityDescriptors + DCSync-rights -> highest "
                             "4662 density of the LDAP modules when SACLed."),
    "laps":        ModuleFootprint("laps", 2, [A_DS_READ], "low",
                        note="LAPS password attribute read on the computer object."),
    "bitlocker":   ModuleFootprint("bitlocker", 2, [A_DS_READ], "low",
                        note="recovery-info read; only surfaced as admin in lab."),
    "adcs":        ModuleFootprint("adcs", 3, [A_DS_READ, A_IPC, A_PIPE], "medium",
                        note="PKI object reads + ESC8 web-enrollment probe hits CA IPC$/certsrv."),
    "shadow":      ModuleFootprint("shadow", 2, [A_DS_READ], "low",
                        note="msDS-KeyCredentialLink read."),
    "rpc":         ModuleFootprint("rpc", 6, [A_SAM, A_DS_READ, A_IPC, A_PIPE], "high",
                        note="SAMR/LSAT over SMB: the loudest + highest-fidelity module "
                             "(SAM access + named pipes); keep opt-in."),
}

# --- Red-team stealth levers (data-driven, from the measured noise profile) ----
STEALTH_LEVERS: list[str] = [
    "Reuse one LDAP connection instead of re-binding per sub-operation: collapses "
    "the auth quartet from up to 6x (delegations, rpc) down to 1x — the single "
    "biggest default-case noise reduction.",
    "Keep the rpc module opt-in: it is the only module that touches SAMR/SMB "
    "(4661 + 5140/5145 + MDI SAMR-recon) — by far the highest-fidelity footprint.",
    "Prefer a Kerberos ccache to drop 4776 (NTLM validation), accepting 4768/4769 "
    "instead — a trade, not a clear win; choose per the DC's detection posture.",
    "Throttle/reorder broad enumeration (users/groups/computers) to avoid the "
    "burst pattern that drives MDI 'LDAP reconnaissance'.",
]


# --- Stealth (red) ------------------------------------------------------------
SIGNAL_RANK = {"low": 0, "medium": 1, "high": 2}


def stealth_order(modules: list[str]) -> list[str]:
    """Reorder module names quietest -> loudest by measured red signal, so a
    stealth run spends its early, less-suspicious budget on the quiet modules."""
    return sorted(modules, key=lambda m: (SIGNAL_RANK.get(REGISTRY[m].red_signal, 1)
                                          if m in REGISTRY else 1, m))


def loudest(modules: list[str]) -> str | None:
    known = [m for m in modules if m in REGISTRY]
    if not known:
        return None
    return max(known, key=lambda m: SIGNAL_RANK.get(REGISTRY[m].red_signal, 1))


def stealth_notice(modules: list[str], rpc_skipped: bool) -> list[str]:
    """Honest residual-signal summary for a stealth run (no false comfort)."""
    lines = [
        "Stealth reduces noise; it does NOT make listdap invisible. Residual signal:",
        "  - every bind still emits the auth quartet (4776 NTLM / 4624 logon / 4672 / "
        "4634) from YOUR source IP — the pivot a SOC correlates on.",
    ]
    hot = [m for m in modules if m in REGISTRY and REGISTRY[m].red_signal == "high"]
    if hot:
        lines.append(f"  - still-loud module(s) kept: {', '.join(hot)}.")
    lines.append("  - consider a Kerberos ccache (drops 4776, adds 4768/4769) and a "
                 "source IP that blends in.")
    return lines


# --- Views --------------------------------------------------------------------
def detectable(module: str) -> list[Artifact]:
    """All artifacts for a module: the auth baseline plus its specific ones."""
    fp = REGISTRY[module]
    return AUTH_BASELINE + fp.artifacts


def module_signal(module: str) -> Signal:
    """Overall default-case loudness, for --stealth ordering."""
    return REGISTRY[module].red_signal


def _rows():
    for name, fp in REGISTRY.items():
        for a in fp.artifacts:
            yield name, fp, a


def blue_markdown(modules: list[str] | None = None) -> str:
    """Render the detection map. `modules` limits it to those module names
    (preserving registry order); None = all. Unknown names are ignored."""
    sel = [m for m in REGISTRY if (modules is None or m in modules)]
    L = ["# listdap detection map (`--blue`)\n",
         "Per-module artifacts on a Domain Controller. Legend: **[default]** = "
         "visible with stock audit; **[needs]** = requires the stated audit "
         "prerequisite (off by default); `~` = inferred, not lab-validated.\n"]
    if modules is not None:
        L.append(f"_Scope: modules {', '.join(sel) or '(none)'}._\n")
    L.append("## Always emitted (every authenticated bind)\n")
    for a in AUTH_BASELINE:
        L.append(f"- **{a.event_id}** {a.name} — {a.log.value} · red:{a.red_signal}"
                 + (f" · _{a.note}_" if a.note else ""))
    L.append("\n## Per module\n")
    L.append("| Module | binds | red | artifacts (beyond baseline) |")
    L.append("|--------|-------|-----|------------------------------|")
    for name in sel:
        fp = REGISTRY[name]
        if not fp.artifacts:
            cells = "— (auth baseline only)"
        else:
            parts = []
            for a in fp.artifacts:
                tag = "[default]" if a.default_on else "[needs]"
                mark = "" if a.tested else "~"
                extra = f" ⟨{a.condition}⟩" if not a.default_on else ""
                idlabel = str(a.event_id) if a.event_id else "MDI"
                parts.append(f"{mark}{idlabel} {a.name} {tag}{extra}")
            cells = "<br>".join(parts)
        L.append(f"| `{name}` | {fp.binds} | {fp.red_signal} | {cells} |")
    L.append("\n## Prerequisites to actually SEE the conditional artifacts\n")
    L.append("- **4662** (object reads): a SACL auditing *Read* on each object of "
             "interest (domain head, AdminSDHolder, gMSA, LAPS computers, PKI "
             "objects…). Off by default.")
    L.append("- **4661 / 5140 / 5145** (rpc/SAMR): advanced audit *Audit SAM*, "
             "*Audit File Share*, *Audit Detailed File Share*. Off by default.")
    L.append("- **MDI alerts** (`~`): a licensed MDI sensor on the DC. Not tested in lab.")
    L.append("- **Sysmon (SwiftOnSecurity)** added nothing for listdap: inbound LDAP "
             "isn't logged and `\\samr` isn't in its pipe include-list.")
    L.append("\n## Red-team notes (`--stealth` levers)\n")
    for s in STEALTH_LEVERS:
        L.append(f"- {s}")
    return "\n".join(L)


if __name__ == "__main__":
    print(blue_markdown())
