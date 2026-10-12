# listdap

LDAP enumeration tool for offensive security assessments, targeting Active
Directory environments. Pure Python 3, authenticated or anonymous.

> For authorized security testing, CTFs, and lab/educational use only.

## Features

- **Authentication**: Kerberos (GSSAPI) via ccache / `$KRB5CCNAME` / auto-acquired
  TGT, with NTLM, SIMPLE and anonymous fallbacks. Automatic domain discovery.
- **Enumeration modules**: domain info & FSMO, users, groups, computers, GPOs,
  password policies (incl. FGPP), trusts, delegations.
- **ACL analysis** (pure-Python security-descriptor parser): DCSync rights and
  dangerous DACLs on sensitive objects, with privileged-principal filtering to
  avoid noise.
- **ADCS / ESC detection**: ESC1, ESC2, ESC3, ESC4, ESC6, ESC7, ESC8, ESC9.
  - Exploitability is assessed **relative to the authenticated identity**
    (its SID + token groups), like `certipy find -vulnerable` — a template is
    only flagged actionable if the current user can actually enroll.
  - ESC7 reads the authoritative CA registry security descriptor over MS-RRP
    (falls back to the CA LDAP object DACL when RRP is unavailable).
  - ESC8 actively probes `/certsrv/` over HTTP/HTTPS for NTLM-relay surface.
  - Findings include **ready-to-run exploitation commands** filled from the
    enumerated data (CA name, template CN, DC, domain, current credentials).
- **LAPS** (legacy + Windows) and **Shadow Credentials** detection.
- **Quick Wins** summary sorted by severity, plus optional user-list dumps.

## Install

```bash
# System prerequisites for the Kerberos GSSAPI bind (Debian/Kali/Ubuntu):
sudo apt install -y libkrb5-dev krb5-user gcc python3-dev

python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
# Anonymous
python3 listdap.py -dc <DC_IP>

# With credentials (auto-discovers domain, Kerberos first, NTLM fallback)
python3 listdap.py -dc <DC_IP> -u <user> -p '<password>'

# Explicit domain, LDAPS
python3 listdap.py -d <domain> -dc <DC_IP> -u <user> -p '<password>' --ldaps

# Kerberos via existing ccache
python3 listdap.py -dc <DC_IP> -u <user> --ccache /tmp/user.ccache

# Specific modules only
python3 listdap.py -dc <DC_IP> -u <user> -p '<password>' --modules users,acls,adcs

# Dump user lists
python3 listdap.py -dc <DC_IP> -u <user> -p '<password>' --dump /tmp/corp

# Verbose
python3 listdap.py -dc <DC_IP> -u <user> -p '<password>' -v
```

## Project structure

```
listdap.py        Entry point, CLI, orchestration
core/             Auth strategies, LDAP connection + rootDSE, output engine
modules/          Per-topic enumeration (domain, users, …, acls, adcs, laps, shadow)
utils/            LDAP helpers, SID resolution, timestamps, UAC, description heuristics
```

## Dependencies

`ldap3`, `impacket`, `gssapi` — see `requirements.txt`.

## Notes / limitations

- LDAP paging is disabled by design; very large containers (>1000 objects) may
  be truncated.
- The security-descriptor parser covers the common ACE types, not every
  inherited/complex structure.
- `lastLogonTimestamp` is replicated and can lag up to ~14 days.
- ADCS ESC5 and ESC10–ESC16 are not currently covered.
