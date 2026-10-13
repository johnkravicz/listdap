# Changelog

All notable changes to listdap are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The running version is defined by `__version__` in `listdap.py` and shown in the
banner and via `listdap.py --version`.

## [Unreleased]

### Added
- `-U` / `--user-file FILE`: write all enumerated domain users (one login per
  line) to an exact path, ready to feed to netexec (`nxc ... -u FILE`). Can be
  combined with `--dump`; both reuse the same enumerated user set.

## [2.1.0] - 2026-10-12

### Added
- Quick Wins now carry **copy-pasteable exploitation commands** filled from the
  session (domain, user, password/ccache, DC IP + FQDN), with a **Kerberos
  variant** (getTGT + `-k -no-pass`) for signing-enforcing DCs where applicable:
  Kerberoasting (GetUserSPNs), AS-REP roasting (GetNPUsers), DCSync
  (secretsdump), RBCD via MachineAccountQuota (addcomputer/rbcd/getST),
  password spraying (nxc), PASSWD_NOTREQD empty-password tests, unconstrained /
  constrained / RBCD delegation abuse (getST/S4U, coercion), and Shadow
  Credentials (certipy shadow auto). New helper module `utils/exploit_cmds.py`.

## [2.0.0] - 2026-10-12

Full impacket LDAP backend. listdap now authenticates to DCs that enforce LDAP
signing / channel binding (e.g. Windows Server 2025 defaults), where the ldap3
backend could not.

### Changed
- **LDAP backend rewritten on impacket** (replacing ldap3). NTLM binds use
  GSS-SPNEGO and are **signed/sealed**, and Kerberos is done in pure Python
  (derives AES), so binds succeed against signing-enforcing DCs. Search results
  are native impacket records; the `get_*` helpers and all modules were adapted.
- Authentication order: explicit ccache/Kerberos → NTLM (signed) →
  Kerberos from password → SIMPLE → anonymous.

### Added
- Native paging on subtree searches (the ldap3 backend disabled paging, which
  could truncate large containers).
- `get_raw` / `get_raw_all` helpers for binary attributes.

### Fixed
- SID → name resolution now reads the `<SID=...>` DN (base scope) instead of a
  binary `(objectSid=\xx..)` filter: impacket's filter compiler UTF-8 re-encodes
  high bytes, so binary-value filters never matched.
- Kerberos binds target the DC **FQDN** (SPN `ldap/<fqdn>`) while the socket
  still connects to the IP, fixing `KDC_ERR_S_PRINCIPAL_UNKNOWN` on ccache /
  password Kerberos.
- `policies` module crashed with a `SCOPE_BASE` NameError (missing import).

### Removed
- `ldap3` and `gssapi` dependencies.
- Temporary `krb5.conf` generation, GSSAPI SPN handling, and the
  `dns_canonicalize_hostname` workaround — impacket needs none of them.

## [1.0.0] - 2026-10-12

First versioned release. ldap3-based enumeration engine.

### Added
- Authentication: Kerberos (GSSAPI) via ccache / `$KRB5CCNAME` / auto-acquired
  TGT, with NTLM, SIMPLE and anonymous fallbacks; automatic domain discovery.
- Enumeration modules: domain & FSMO, users, groups, computers, GPOs, password
  policies (default + FGPP), trusts, delegations, LAPS, shadow credentials.
- ACL analysis via a pure-Python security-descriptor parser: DCSync rights and
  dangerous DACLs on sensitive objects.
- ADCS detection: ESC1, ESC2, ESC3, ESC4, ESC6, ESC7, ESC8, ESC9.
  - Exploitability assessed relative to the authenticated identity (its SID +
    token groups), like `certipy find -vulnerable`.
  - ESC7 reads the CA registry security descriptor over MS-RRP (falls back to
    the CA LDAP object DACL when RRP is unavailable).
  - ESC8 actively probes `/certsrv/` over HTTP/HTTPS for NTLM-relay surface.
  - Findings include ready-to-run exploitation commands filled from the
    enumerated data, with both direct (RPC) and Kerberos variants.
- Shared privileged / low-privilege SID filters to suppress false positives
  across ADCS (ESC4/ESC7) and ACL (DCSync, sensitive objects) checks.
- SID → sAMAccountName resolution over LDAP, with caching.
- `--version` / `-V` flag and version shown in the banner.
- `requirements.txt`, MIT `LICENSE`, authorised-use disclaimer, and a colored
  example-output capture in `docs/`.

### Fixed
- Read `nTSecurityDescriptor` as a non-admin by attaching the `SD_FLAGS` control
  (OWNER+GROUP+DACL), so ACL-based checks work without domain privileges.
- `ScanContext.domain_sid` resolved lazily, so SID resolution and RID-based
  filters work even when modules run in isolation (e.g. `--modules adcs`).
- Kerberos SPN canonicalisation (`dns_canonicalize_hostname = false`) to avoid
  `Server not found in Kerberos database` when `/etc/hosts` lists a non-FQDN
  canonical name for the DC.
- Clearer authentication diagnostics: when an authenticated bind fails and the
  tool falls back to anonymous, the real per-attempt errors are surfaced along
  with guidance (notably for DCs that enforce LDAP signing, which ldap3 cannot
  satisfy).
