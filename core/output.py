"""
Colored output engine for listdap.
"""

import sys
import os
import re
from dataclasses import dataclass, field
from typing import List, Optional, Callable
from enum import Enum

_ANSI_RE = re.compile(r'\033\[[0-9;]*m')

def _vlen(s: str) -> int:
    """Visible length of a string (strips ANSI escape codes)."""
    return len(_ANSI_RE.sub('', str(s)))

def _vljust(s: str, width: int) -> str:
    """ljust that pads based on visible length, not raw length."""
    pad = max(0, width - _vlen(s))
    return str(s) + ' ' * pad


# ---------------------------------------------------------------------------
# ANSI helpers
# ---------------------------------------------------------------------------

def _supports_color() -> bool:
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


class C:
    """ANSI color codes."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"

    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"
    GREY    = "\033[90m"

    @staticmethod
    def red(s: str) -> str:     return f"{C.RED}{s}{C.RESET}"
    @staticmethod
    def yellow(s: str) -> str:  return f"{C.YELLOW}{s}{C.RESET}"
    @staticmethod
    def green(s: str) -> str:   return f"{C.GREEN}{s}{C.RESET}"
    @staticmethod
    def cyan(s: str) -> str:    return f"{C.CYAN}{s}{C.RESET}"
    @staticmethod
    def blue(s: str) -> str:    return f"{C.BLUE}{s}{C.RESET}"
    @staticmethod
    def magenta(s: str) -> str: return f"{C.MAGENTA}{s}{C.RESET}"
    @staticmethod
    def bold(s: str) -> str:    return f"{C.BOLD}{s}{C.RESET}"
    @staticmethod
    def dim(s: str) -> str:     return f"{C.DIM}{s}{C.RESET}"
    @staticmethod
    def grey(s: str) -> str:    return f"{C.GREY}{s}{C.RESET}"


# ---------------------------------------------------------------------------
# Shell-command syntax highlighting (for Quick Wins + section command blocks)
# ---------------------------------------------------------------------------

#: First tokens that mark a line as a runnable command (plus the "impacket-"
#: prefix, matched separately). Anything else is treated as prose and left dim.
_CMD_STARTERS = frozenset({
    "certipy-ad", "certipy", "nxc", "netexec", "coercer", "hashcat", "bloodyAD",
    "python3", "export", "printf", "sudo", "kinit", "getTGT", "secretsdump",
    "evil-winrm", "smbclient", "ldapsearch", "crackmapexec",
})

# colors
_CMD_C = C.GREEN + C.BOLD   # command
_OPT_C = C.YELLOW           # -x / --xx options
_VAL_C = C.CYAN             # option values / arguments / quoted strings
_CMT_C = C.GREY             # comments


def _is_command_line(stripped: str) -> bool:
    if not stripped:
        return False
    tok = stripped.split(None, 1)[0]
    return tok.startswith("impacket-") or tok in _CMD_STARTERS


def _tokenize_cmd(s: str):
    """Yield (text, is_space) chunks, keeping quoted spans ('…' / "…") intact."""
    i, n = 0, len(s)
    while i < n:
        if s[i].isspace():
            j = i
            while j < n and s[j].isspace():
                j += 1
            yield s[i:j], True
            i = j
        else:
            j, quote = i, None
            while j < n:
                c = s[j]
                if quote:
                    if c == quote:
                        quote = None
                    j += 1
                elif c in "'\"":
                    quote = c
                    j += 1
                elif c.isspace():
                    break
                else:
                    j += 1
            yield s[i:j], False
            i = j


def highlight_command(line: str) -> str:
    """Syntax-highlight a single line: command / options / values / comments.

    Non-command prose is returned dimmed, so command lines visually pop out of a
    Quick Win's descriptive text. Whole-line and trailing inline comments
    (starting with '#') are greyed.
    """
    if not line.strip():
        return line
    indent = line[:len(line) - len(line.lstrip())]
    stripped = line.strip()

    if stripped.startswith("#"):
        return f"{indent}{_CMT_C}{stripped}{C.RESET}"

    if not _is_command_line(stripped):
        return C.dim(line)           # prose — unchanged dim look

    out = [indent]
    first_seen = False
    comment = False
    for text, is_space in _tokenize_cmd(line.lstrip()):
        if comment:
            out.append(text)
            continue
        if is_space:
            out.append(text)
            continue
        if text.startswith("#"):     # start of a trailing inline comment
            comment = True
            out.append(f"{_CMT_C}{text}")
            continue
        if not first_seen:
            out.append(f"{_CMD_C}{text}{C.RESET}")
            first_seen = True
        elif text.startswith("-"):
            out.append(f"{_OPT_C}{text}{C.RESET}")
        else:
            out.append(f"{_VAL_C}{text}{C.RESET}")
    if comment:
        out.append(C.RESET)
    return "".join(out)


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

class Severity(Enum):
    CRITICAL = 0
    HIGH     = 1
    MEDIUM   = 2
    INFO     = 3


SEVERITY_COLOR = {
    Severity.CRITICAL: C.RED,
    Severity.HIGH:     C.YELLOW,
    Severity.MEDIUM:   C.CYAN,
    Severity.INFO:     C.GREY,
}

SEVERITY_LABEL = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH:     "HIGH",
    Severity.MEDIUM:   "MEDIUM",
    Severity.INFO:     "INFO",
}


# ---------------------------------------------------------------------------
# Finding (for QuickWins)
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    severity: Severity
    title: str
    detail: str = ""


# ---------------------------------------------------------------------------
# QuickWinsCollector
# ---------------------------------------------------------------------------

class QuickWinsCollector:
    def __init__(self):
        self._findings: List[Finding] = []

    def add(self, severity: Severity, title: str, detail: str = "") -> None:
        self._findings.append(Finding(severity, title, detail))

    def display(self, out: "Output") -> None:
        if not self._findings:
            return
        out.section("QUICK WINS")
        sorted_findings = sorted(self._findings, key=lambda f: f.severity.value)
        for f in sorted_findings:
            color = SEVERITY_COLOR[f.severity]
            label = f"{color}{C.BOLD}[{SEVERITY_LABEL[f.severity]}]{C.RESET}"
            print(f"  {label} {C.bold(f.title)}")
            if f.detail:
                for line in f.detail.splitlines():
                    print(f"         {highlight_command(line)}")


# ---------------------------------------------------------------------------
# Output engine
# ---------------------------------------------------------------------------

class Output:
    def __init__(self, verbose: bool = False, color: bool = True):
        self.verbose = verbose
        self.color   = color and _supports_color()
        self._indent = "  "

    def _c(self, code: str, s: str) -> str:
        return f"{code}{s}{C.RESET}" if self.color else s

    # --- Section header ---

    def section(self, title: str) -> None:
        width = 60
        bar = "═" * width
        print()
        print(self._c(C.BLUE + C.BOLD, f"╔{bar}╗"))
        label = f"  {title}  "
        pad = width - len(label)
        lpad = pad // 2
        rpad = pad - lpad
        print(self._c(C.BLUE + C.BOLD, f"║{' ' * lpad}{label}{' ' * rpad}║"))
        print(self._c(C.BLUE + C.BOLD, f"╚{bar}╝"))

    def subsection(self, title: str) -> None:
        print()
        print(self._c(C.CYAN + C.BOLD, f"  ── {title} ──"))

    # --- Log levels ---

    def success(self, msg: str) -> None:
        print(f"{self._c(C.GREEN,   '[+]')} {msg}")

    def info(self, msg: str) -> None:
        print(f"{self._c(C.CYAN,    '[*]')} {msg}")

    def warning(self, msg: str) -> None:
        print(f"{self._c(C.YELLOW,  '[!]')} {msg}")

    def error(self, msg: str) -> None:
        print(f"{self._c(C.RED,     '[-]')} {msg}")

    def critical(self, msg: str) -> None:
        print(f"{self._c(C.RED + C.BOLD, '[!!]')} {msg}")

    def debug(self, msg: str) -> None:
        if self.verbose:
            print(f"{self._c(C.GREY, '[~]')} {msg}")

    def plain(self, msg: str) -> None:
        print(msg)

    # --- Counters ---

    def counter(self, label: str, total: int, subsets: Optional[dict] = None) -> None:
        """
        Prints: [*] Users: 342 total | 12 disabled | 5 AS-REP roastable
        subsets: {"disabled": 12, "AS-REP roastable": 5}
        """
        parts = [self._c(C.WHITE + C.BOLD, str(total)) + " total"]
        if subsets:
            for name, count in subsets.items():
                color = C.YELLOW if count > 0 else C.GREY
                parts.append(self._c(color, str(count)) + f" {name}")
        line = f"{self._c(C.CYAN, '[*]')} {C.BOLD}{label}{C.RESET}: " + " | ".join(parts)
        print(line)

    # --- Table ---

    def table(
        self,
        headers: List[str],
        rows: List[List[str]],
        highlight_fn: Optional[Callable[[List[str]], Optional[str]]] = None,
        indent: int = 4,
    ) -> None:
        """
        Prints a simple aligned table.
        highlight_fn(row) -> ANSI color code or None
        """
        if not rows:
            return
        all_rows = [headers] + rows
        # Use visible length for column width calculation (ignores ANSI codes)
        col_widths = [
            max(_vlen(cell) for cell in col)
            for col in zip(*all_rows)
        ]
        pad = " " * indent

        # Header
        header_line = "  ".join(
            self._c(C.BOLD, str(h).ljust(col_widths[i]))
            for i, h in enumerate(headers)
        )
        sep = self._c(C.DIM, "  ".join("─" * w for w in col_widths))
        print(f"{pad}{header_line}")
        print(f"{pad}{sep}")

        # Rows — use _vljust so ANSI codes in cells don't break alignment
        for row in rows:
            cells = "  ".join(
                _vljust(row[i], col_widths[i]) for i in range(len(headers))
            )
            if highlight_fn:
                color = highlight_fn(row)
                if color:
                    cells = f"{color}{cells}{C.RESET}"
            print(f"{pad}{cells}")

    # --- Key/value pairs ---

    def kv(self, key: str, value: str, indent: int = 4) -> None:
        pad = " " * indent
        print(f"{pad}{self._c(C.CYAN, key + ':')}  {value}")

    # --- Auth banner ---

    def auth_banner(self, auth_type: str, target: str, base_dn: str) -> None:
        print()
        print(self._c(C.GREEN + C.BOLD, "  ✔ Connected"))
        self.kv("Target",    target)
        self.kv("Auth",      self._c(C.GREEN, auth_type))
        self.kv("Base DN",   base_dn)
