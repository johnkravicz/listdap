"""
Heuristic analysis of LDAP description fields.
Detects and highlights content that is pentest-relevant.
"""

import re
from typing import Optional
from core.output import C

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# Keywords that strongly suggest a credential value follows
_CRED_KW = (
    r"password|passwd|pass|pwd|mot\s+de\s+passe|mdp|passphrase"
    r"|credentials?|creds?|secret|token|api[-_]?key|clé|cle"
    r"|initial|temporar(?:y|ily)|default|changeme|reset"
)

# Pattern: <keyword><separator><value>
# e.g. "password: Foo123!", "pass=abc", "pwd set to XYZ"
_CRED_VALUE_RE = re.compile(
    r"(?:" + _CRED_KW + r")"
    r"(?:\s+(?:is|are|set\s+to|was|:))?"   # optional verb
    r"[\s:=\-_>]+(\S+)",
    re.IGNORECASE,
)

# Standalone password-like token: 8+ chars with complexity
# (upper + lower + digit, or letters + special chars)
_PWD_STANDALONE_RE = re.compile(
    r"\b(?=[A-Za-z\d!@#$%^&*()\-_+=.]{8,})"
    r"(?=(?:[^A-Z]*[A-Z]){1})"   # at least 1 upper
    r"(?=(?:[^a-z]*[a-z]){1})"   # at least 1 lower
    r"(?=(?:\D*\d){1})"          # at least 1 digit
    r"[A-Za-z\d!@#$%^&*()\-_+=.]{8,}\b"
)

# Hash-like strings: 32 hex (NTLM/MD5) or 40 hex (SHA1) or 64 hex (SHA256)
_HASH_RE = re.compile(r"\b[0-9a-fA-F]{32}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{64}\b")

# IPv4 addresses
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# URLs
_URL_RE = re.compile(r"https?://\S+", re.IGNORECASE)

# UNC paths  \\server\share
_UNC_RE = re.compile(r"\\\\[\w\-\.]+\\[\w\-\.]+")

# Sensitive keywords without an obvious value (lower signal)
_SENSITIVE_KW_RE = re.compile(
    r"\b(?:" + _CRED_KW + r"|admin|root|sa\b|sysadmin|superuser|service.?account)\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Severity levels for findings
# ---------------------------------------------------------------------------

HIGH   = "HIGH"
MEDIUM = "MEDIUM"
LOW    = "LOW"


# ---------------------------------------------------------------------------
# Core analyser
# ---------------------------------------------------------------------------

def analyze_description(desc: str) -> tuple[str, Optional[str]]:
    """
    Analyse a description string for pentest-relevant content.

    Returns:
        (highlighted_desc, severity)
        severity is None if nothing interesting is found,
        or HIGH / MEDIUM / LOW otherwise.
        highlighted_desc has ANSI color codes injected around sensitive tokens.
    """
    if not desc:
        return desc, None

    findings = []   # list of (start, end, severity, label)

    # --- HIGH: credential keyword + explicit value ---
    for m in _CRED_VALUE_RE.finditer(desc):
        # Group 1 is the value after the keyword
        val = m.group(1)
        start = m.start(1)
        end   = m.end(1)
        findings.append((start, end, HIGH, "credential"))

    # --- HIGH: hash-like strings ---
    for m in _HASH_RE.finditer(desc):
        findings.append((m.start(), m.end(), HIGH, "hash"))

    # --- MEDIUM: standalone password-like tokens (not already covered) ---
    covered = {(s, e) for s, e, _, _ in findings}
    for m in _PWD_STANDALONE_RE.finditer(desc):
        if (m.start(), m.end()) not in covered:
            findings.append((m.start(), m.end(), MEDIUM, "password-like"))

    # --- MEDIUM: IP addresses ---
    for m in _IP_RE.finditer(desc):
        findings.append((m.start(), m.end(), MEDIUM, "ip"))

    # --- MEDIUM: URLs ---
    for m in _URL_RE.finditer(desc):
        findings.append((m.start(), m.end(), MEDIUM, "url"))

    # --- MEDIUM: UNC paths ---
    for m in _UNC_RE.finditer(desc):
        findings.append((m.start(), m.end(), MEDIUM, "path"))

    # --- LOW: sensitive keywords with no associated value ---
    if not findings and _SENSITIVE_KW_RE.search(desc):
        # Just flag the whole description, no specific highlight
        return C.yellow(desc), LOW

    if not findings:
        return desc, None

    # --- Determine overall severity ---
    if any(sev == HIGH for _, _, sev, _ in findings):
        overall = HIGH
    elif any(sev == MEDIUM for _, _, sev, _ in findings):
        overall = MEDIUM
    else:
        overall = LOW

    # --- Build highlighted string ---
    # Sort findings by start position; remove overlaps (keep first occurrence)
    findings.sort(key=lambda x: x[0])
    merged = []
    for f in findings:
        if merged and f[0] < merged[-1][1]:
            # Overlap: extend end if needed
            prev = merged[-1]
            end  = max(prev[1], f[1])
            sev  = HIGH if HIGH in (prev[2], f[2]) else MEDIUM
            merged[-1] = (prev[0], end, sev, prev[3])
        else:
            merged.append(f)

    result = []
    pos = 0
    for start, end, sev, label in merged:
        result.append(desc[pos:start])
        token = desc[start:end]
        if sev == HIGH:
            result.append(f"{C.RED}{C.BOLD}{token}{C.RESET}")
        else:
            result.append(f"{C.YELLOW}{token}{C.RESET}")
        pos = end
    result.append(desc[pos:])

    return "".join(result), overall


def extract_credentials(desc: str) -> list[str]:
    """
    Extract raw credential values from a description string.
    Returns a list of candidate password/hash strings (no ANSI codes).
    Only returns HIGH-confidence findings (keyword+value or hash).
    """
    if not desc:
        return []

    found = []
    seen  = set()

    # Credential keyword + value
    for m in _CRED_VALUE_RE.finditer(desc):
        val = m.group(1).strip(".,;:\"'")
        if val and val not in seen:
            found.append(val)
            seen.add(val)

    # Hash-like strings
    for m in _HASH_RE.finditer(desc):
        val = m.group(0)
        if val not in seen:
            found.append(val)
            seen.add(val)

    # Standalone password-like tokens (only if no keyword match above)
    if not found:
        for m in _PWD_STANDALONE_RE.finditer(desc):
            val = m.group(0)
            if val not in seen:
                found.append(val)
                seen.add(val)

    return found


def severity_color(sev: Optional[str]) -> Optional[str]:
    """Return ANSI row-level color for a given severity (for table highlight_fn)."""
    if sev == HIGH:
        return C.RED
    if sev == MEDIUM:
        return C.YELLOW
    return None
