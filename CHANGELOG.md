# Changelog

All notable changes to listdap are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The running version is defined by `__version__` in `listdap.py` and shown in the
banner and via `listdap.py --version`.

## [Unreleased]

## [2.6.0] - 2026-11-15

### Added
- **gMSA / dMSA module** (`gmsa`) — new identity-relative module for Group and
  Delegated Managed Service Accounts, with two LDAP-native wins:
  - **Managed-password read → pass-the-hash.** A DC returns the constructed
    `msDS-ManagedPassword` blob only to principals in the account's
    `msDS-GroupMSAMembership` security descriptor. When the current identity is
    authorised, the module parses the MSDS-MANAGEDPASSWORD_BLOB (`utils/gmsa.py`)
    and derives the **NT hash** (MD4 over the raw UTF-16LE current-password
    buffer) → CRITICAL Quick Win with ready PtH commands (`nxc -H`,
    `secretsdump -hashes`, `listdap -H`). The membership SD is parsed (reusing
    the ACLs DACL parser) to report *who* may read the password even when the
    blob is not returned on this bind — flagging when the **current identity is
    authorised** (retrieve via `nxc --gmsa` / `gMSADumper`) and when a **broad
    low-priv principal** (Domain Users / Authenticated Users) can read it.
  - **dMSA / BadSuccessor (Server 2025).** Inventories delegated MSAs, decodes
    `msDS-DelegatedMSAState`, and follows `msDS-ManagedAccountPrecededByLink` to
    the superseded account — **CRITICAL** when it supersedes a privileged account
    (authenticating as the dMSA inherits its migrated KERB key list / privileges).
  - A managed account that is itself in a privileged group raises recovered-
    password findings to domain-impact. gMSA/dMSA accounts feed
    `ctx.ldap_identity_count` but are kept out of human-login dumps (they are `$`
    machine-class accounts).

### Notes
- ⚠️ **Not yet validated live** — the module and the MSDS-MANAGEDPASSWORD_BLOB
  parser are unit-tested against mocked records and a synthetic blob (NT-hash
  derivation verified against a direct MD4), but never run against a real
  gMSA/dMSA-bearing DC.

## [2.5.0] - 2026-11-15

### Added
- **ADCS ESC5 detection** (LDAP-only) — takeover rights (GenericAll / WriteDACL /
  WriteOwner / GenericWrite) held by a **non-privileged** principal over a PKI
  infrastructure object. Reads the `nTSecurityDescriptor` (base scope, SD_FLAGS
  auto-attached) of `CN=NTAuthCertificates`, the `CN=Certificate Templates`,
  `CN=Enrollment Services` and `CN=OID` containers, the `CN=Public Key Services`
  parent, and each CA's **host computer object** (resolved from `dNSHostName`),
  reusing the existing DACL parser. Control of NTAuthCertificates or the CA host
  is **CRITICAL** (rogue-CA / box takeover → forge any auth); the containers are
  HIGH. Quick Win points at `certipy-ad find` to map the PKI.
- **ADCS ESC14 detection** (LDAP-only surface) — accounts carrying a **weak
  explicit certificate mapping** in `altSecurityIdentities` (subject-only,
  issuer+subject, or RFC822-email — as opposed to the strong SKI / SHA1-PUKEY /
  issuer+serial forms). Privileged victims (`is_privileged_sid` /
  `is_high_value_sid` / `adminCount=1`) raise the finding to **CRITICAL**, others
  MEDIUM. The Quick Win carries the **confirmation command**: an `impacket-reg`
  read of the DC's `StrongCertificateBindingEnforcement` (0/1 = weak mappings
  honored → exploitable; 2 = full enforcement) and the Schannel
  `CertificateMappingMethods`, plus a low-priv functional confirmation via
  `certipy-ad auth`.
- Coverage is now ESC1-ESC9, ESC13, ESC14, ESC15 (still not covered: ESC10-ESC12,
  ESC16).

### Notes
- ⚠️ **ESC5 and ESC14 are not yet validated live** — implemented and unit-tested
  against mocked SDs / records (crafted security descriptor, mapping classifier),
  but never run against a real DC carrying a genuine ESC5/ESC14 misconfiguration.
- ESC14 exploitability depends on a DC **registry** value LDAP cannot read; the
  emitted `impacket-reg` confirmation generally needs remote-registry/admin
  rights, so as a low-priv attacker the functional `certipy-ad auth` test is the
  reliable confirmation. A listdap-native check (RRP value read, mirroring
  `utils/ca_rrp.py`) is feasible but deferred for the same admin-rights reason.

## [2.4.0] - 2026-11-15

### Added
- **ADCS ESC13 detection** — a certificate template whose issuance policy
  (`msPKI-Certificate-Policy`) references an OID object linked to an AD group via
  `msDS-OIDToGroupLink`. When the template also allows client authentication,
  enrolling puts the linked group's SID into the PKINIT PAC, granting that group's
  membership without ever joining it. The module reads the OID container
  (`CN=OID,CN=Public Key Services,CN=Services,…`) once, builds the OID→group map,
  resolves each linked group's SID/name, and raises the finding to **CRITICAL**
  when the linked group is privileged/high-value (otherwise HIGH). Identity-
  relative like ESC1/ESC9: reported actionable only when the current identity can
  enrol. Quick Win emits `certipy-ad req … && certipy-ad auth …` (no SAN needed).
- **ADCS ESC15 detection** — EKUwu (CVE-2024-49019): a schema **V1** template
  (`msPKI-Template-Schema-Version` ≤ 1) where the enrollee supplies the subject
  (`ENROLLEE_SUPPLIES_SUBJECT`), published and enrollable by a low-priv principal.
  V1 templates copy an attacker-supplied Application Policies extension from the
  CSR, so a Client-Authentication (or Certificate-Request-Agent) policy can be
  injected into a cert whose nominal EKU forbids it. Severity **CRITICAL**. Quick
  Win emits both the direct `-application-policies 'Client Authentication'`
  impersonation and the Certificate-Request-Agent / on-behalf-of variant.
- Coverage is now ESC1-ESC4, ESC6-ESC9, ESC13, ESC15 (still not covered: ESC5,
  ESC10-ESC12, ESC14, ESC16).

### Notes
- ⚠️ **ESC13 and ESC15 are not yet validated live** — implemented and unit-tested
  against mocked template records, but never run against a real DC carrying a
  genuine ESC13/ESC15 misconfiguration. Confirm the ESC13 OID-container read and
  the ESC15 schema-version gate against certipy on a live target before relying
  on a (non-)finding.

### Added (prior, unreleased)
- **Self-bootstrapping launcher** (`./listdap`) — runs listdap directly when
  the system Python already has impacket (e.g. Kali's `python3-impacket`), and
  otherwise creates a local `.venv/` from `requirements.txt` and reuses it on
  later runs (refreshed only when `requirements.txt` changes). Falls back to a
  per-repo venv under `~/.cache/listdap/` when the checkout lives on a
  filesystem that rejects symlinks (e.g. a VirtualBox shared folder). Knobs:
  `--reinstall`, `LISTDAP_FORCE_VENV=1`, `LISTDAP_PYTHON=<interpreter>`.

## [2.3.0] - 2026-10-14

### Added
- **RPC enumeration module** (`rpc`) — the opportunistic complement to the
  LDAP modules, for the common case where the LDAP bind reads the rootDSE but
  not the directory objects (anonymous / RestrictAnonymous) while RPC over SMB
  still leaks the account database. `utils/rpc.py` provides a DCE/RPC transport
  (mirroring `utils/ca_rrp.py`) that reuses the LDAP-side credentials
  (password / pass-the-hash / Kerberos ccache). Pipes covered:
  - **SAMR** (`\samr`) — users (with account-control flags, pwd-last-set and
    descriptions), groups, local aliases, and the domain password policy.
  - **LSAT** (`\lsarpc`) — LSA policy, account-domain SID, trusted domains, and
    **RID cycling** as a fallback when SAMR is blocked but name lookups are not.
  - **SRVSVC** (`\srvsvc`) — shares and sessions.
  - **WKSSVC** (`\wkssvc`) — logged-on users.
  - **EPM** (endpoint mapper, tcp/135) — a summarised dump of the registered
    RPC attack surface (distinct services, with notable ones surfaced).
- Trigger model: RPC runs **automatically** when the LDAP bind is anonymous or
  returns no identity objects; `--rpc` forces it even when LDAP succeeded, and
  `--no-rpc` disables it. SAMR descriptions are run through the credential
  highlight heuristic, and SAMR-discovered users feed `--dump` / `--user-file`.
- Quick Wins from RPC: "LDAP unreadable but SAMR enumerates N users" (headline),
  cleartext-credential-in-description, AS-REP-roastable (credential-free
  `GetNPUsers -no-pass`), PASSWD_NOTREQD empty-password, and password-spray when
  the SAMR-read lockout threshold is 0.

### Notes
- Each RPC pipe degrades gracefully and independently: on a hardened DC it is
  normal for SAMR null to succeed while LSAT/SRVSVC/WKSSVC return
  STATUS_ACCESS_DENIED — these are reported as notes, never fatal.
- A null SAMR/LSAT session requires a **non-empty domain** in the SMB
  credentials (an empty domain is rejected with STATUS_INVALID_PARAMETER); the
  discovered domain is threaded through automatically.

## [2.2.0] - 2026-10-13

### Added
- `-H` / `--hashes [LM:]NT`: **pass-the-hash** authentication. Binds via signed
  NTLM (GSS-SPNEGO) with the NT hash, with a Kerberos-from-hash (RC4) fallback.
  Accepts `LMHASH:NTHASH`, `:NTHASH` or a bare `NTHASH`. Generated Quick Win
  commands switch to `-hashes` / `-H` automatically when no password is in use.
- `-U` / `--user-file FILE`: write all enumerated domain users (one login per
  line) to an exact path, ready to feed to netexec (`nxc ... -u FILE`). Can be
  combined with `--dump`; both reuse the same enumerated user set.
- acls: **outbound control check** — flags objects (users/groups/computers/gMSA)
  over which the *authenticated account* itself holds a dangerous right
  (GenericAll, WriteDACL, WriteOwner, GenericWrite, Write-KeyCredentialLink,
  Write-member/Self-Membership, Write-SPN, Write-AllowedToActOnBehalfOf,
  ForceChangePassword, AllExtendedRights). Each finding carries a ready-to-run
  takeover command (`utils/exploit_cmds.acl_abuse`). Already-privileged and
  contextual SIDs are filtered out to avoid noise.

### Fixed
- acls: the new outbound-control check recognises the **expanded full-control
  mask** (`0x000F01FF`), not just the GENERIC_ALL bit — a real "Full Control"
  ACE is usually stored expanded and the generic-bit-only test missed it.

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
