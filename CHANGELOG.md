# Changelog

All notable changes to listdap are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The running version is defined by `__version__` in `listdap.py` and shown in the
banner and via `listdap.py --version`.

## [Unreleased]

## [2.25.0] - 2026-11-20

### Fixed

- **INHERIT_ONLY ACEs no longer counted as access on the object (acls module)**
  — fixes a **false positive**. The DACL parser ignored the ACE header flags, so
  an `INHERIT_ONLY` ACE (which is a template for child objects and grants no
  access on the object itself) was reported as a dangerous right. `_parse_dacl`
  now skips `INHERIT_ONLY_ACE` (0x08); inherited ACEs without that flag (0x10)
  still correctly apply. Benefits every DACL consumer (acls, gpo, adidns, adcs,
  gmsa).
- **Conditional (callback) ACEs are now parsed (acls module)** — fixes a
  **false negative**. `ACCESS_ALLOWED/DENIED_CALLBACK[_OBJECT]` (0x09/0x0A/0x0B/
  0x0C) were dropped entirely, so a real conditional grant was invisible. They
  share the base-type binary layout, so they are normalised to the base type and
  tagged `conditional`. Detection-safe handling: a conditional ALLOW surfaces as
  a potential grant, while a conditional DENY does **not** suppress a finding
  (its expression is not evaluated, so assuming it denies could hide a real path).
  The trailing conditional expression itself is not evaluated (documented limit).
- **FSMO roles are now identified distinctly (domain module)** — fixes a
  **mislabel + a missing role**. `_guess_role` tested `"ridmanager" in dn`, which
  never matched the real `CN=RID Manager$` object (note the space), so the RID
  Master was silently dropped and the domain head was labelled "PDC Emulator /
  RID Master". Matching is now exact/base-relative: domain head → **PDC
  Emulator**, `CN=RID Manager$,CN=System` → **RID Master**, `CN=Infrastructure`
  → **Infrastructure Master** (the exact match also avoids the DNS application
  partitions' own Infrastructure objects being reported as extra rows).

### Changed

- **Inactive-accounts finding now carries a caveat** (users module):
  `lastLogonTimestamp` replicates lazily (lags up to ~14 days), so a
  recently-active account can appear in the inactive list — the output now says
  so, to avoid acting on a false positive for an individual account.

## [2.24.0] - 2026-11-20

### Fixed

- **`--blue` now reflects the auth method actually used (NTLM vs Kerberos)**
  (detection registry + CLI). The detection map's per-bind baseline was
  hard-coded to the NTLM quartet (**4776** credential validation + 4624/4672/
  4634), so on a Kerberos run the map was factually wrong — it claimed 4776 that
  never fired and hid the **4768 (AS-REQ) / 4769 (TGS-REQ)** that did.
  - New `AUTH_BASELINE_KERBEROS` and `auth_baseline(auth, from_ccache)` in
    `utils/detection.py`: Kerberos swaps 4776 → 4768+4769, and a **pre-existing
    ccache drops 4768** (the TGT was obtained elsewhere; only 4769 at bind time).
    The Kerberos-specific events are marked `~` (inferred — Phase 5 measured the
    NTLM path); 4624/4672/4634 are method-agnostic and stay lab-validated.
  - `blue_markdown`, `render_blue` and `stealth_notice` take an `auth` argument
    and render the correct baseline, header and residual-signal tell.
  - `listdap.py` selects it from the realized `AuthResult` for `--blue`/
    `--stealth` (`_auth_kind`, incl. `ccache_path` → `from_ccache`) and infers it
    for the offline `--blue-only` from the args that would be used
    (`_planned_auth`: explicit `--ccache`/`$KRB5CCNAME` → Kerberos, else NTLM).
  - Validated live against the lab DC: NTLM run shows 4776; Kerberos run (via a
    real TGT/ccache) shows 4769 only, no 4776/4768.

## [2.23.0] - 2026-11-20

### Fixed

- **DENY ACEs are now honoured in DACL analysis (acls module)** — fixes a
  **false-positive** class. The DACL parser previously parsed only
  `ACCESS_ALLOWED`/`ACCESS_ALLOWED_OBJECT` ACEs and ignored
  `ACCESS_DENIED`/`ACCESS_DENIED_OBJECT`, so a dangerous right (GenericAll,
  WriteDACL, DCSync, Write-KeyCredentialLink, …) was reported even when an
  explicit DENY on the same trustee revoked it.
  - `_parse_dacl` now also returns DENY ACEs (incl. the object form `0x06`).
  - New **effective-access engine** (`_effective_access`): per object it
    collapses ALLOW and DENY ACEs for a trustee set into the rights actually
    held (DENY wins). All three checks now decide on effective access rather
    than a lone ALLOW: DCSync rights, dangerous permissions on sensitive
    objects, and outbound control held by the current account.
  - Scope/limits (documented): DENY is matched on the resolved trustee SIDs,
    not on implicit broad groups a principal only transitively belongs to
    (Everyone / Authenticated Users), and not on non-canonical ALLOW-before-DENY
    ordering (AD rewrites DACLs to canonical order on write).
  - Validated with crafted binary security descriptors (ALLOW+DENY of the same
    right → no finding; ALLOW-only → finding kept) and live against the lab DC
    (no regression on genuine findings).

## [2.22.0] - 2026-11-20

### Changed

- **ADIDNS reframed around the attack surface, not the record dump** (adidns
  module). The full record listing is recon-only, so it is now **demoted behind
  `-v`** (default shows a count + the name→IP Quick Win). The new headline is a
  **"Plantable missing names"** view: for every zone where the current identity
  holds Create-Child, it lists the high-value names that are **absent and
  therefore plantable** — `*` (CRITICAL, domain-wide catch-all), `wpad` (HIGH,
  WPAD coercion), `isatap` (MEDIUM) — each with a ready `dnstool.py` / Powermad
  command. A present `*` in a zone marks it neutralised (overwrite instead).
  **Client-facing only**: reverse (`.arpa`) and locator/service zones (`_msdcs`,
  `_sites`, `_tcp`…) are skipped for wpad/catch-all, since clients never resolve
  wpad there. `_check_zone_create` now reports just the Create-Child permission
  surface; the "what to plant" detail moved to `_check_missing_names`.
  Validated live (corp.lab wildcard neutralised; a clean client zone → `*`/`wpad`/
  `isatap` plantable; `_msdcs` skipped).

### Fixed

- **`--blue` / `--blue-only` rendered as raw Markdown** in the terminal. They now
  render through the Output engine (`detection.render_blue`): boxed section,
  coloured module headers by red signal, `[needs: …]`/`[default]` tags — no more
  `#`/`|`/`<br>`. `blue_markdown()` is kept for file/Markdown use.

## [2.21.0] - 2026-11-20

### Added

- **`--stealth` (red) + `--throttle`** (`listdap.py`, backed by the Phase 5
  detection registry). `--stealth` reduces the detection footprint, driven by the
  measured per-module red signal:
  - **skips the `rpc`/SAMR module** (its 4661 + 5140/5145 + SAMR-recon are the
    highest-fidelity footprint) unless `--rpc` forces it;
  - **reorders modules quiet→loud** (`detection.stealth_order`) so the budget is
    spent on low-signal modules first;
  - **throttles between modules** (base delay + random jitter) to break the burst
    pattern that drives MDI "LDAP reconnaissance"; `--stealth` defaults the delay
    to 3.0s, and `--throttle SEC` tunes it (usable on its own too);
  - **prints the residual signal honestly** — stealth does NOT make listdap
    invisible: every bind still logs the NTLM auth quartet from the source IP,
    and any kept high-signal module is named. No false comfort.

  The LDAP connection was already reused across searches, so the quiet-by-default
  posture is preserved; `--stealth` addresses the remaining measured noise.

## [2.20.0] - 2026-11-20

### Added

- **Detection registry + `--blue` (purple-team)** (`utils/detection.py`). A single
  source of truth maps each module to the artifacts it generates on a DC
  (Windows event ID, log, and — crucially — the **audit prerequisite** for each,
  since almost every object-level artifact needs a SACL or advanced-audit
  subcategory that is OFF by default). Two new flags render it:
  - `--blue` — after the scan, print the detection footprint of the modules that
    actually ran (auto-scoped).
  - `--blue-only` — print the map for the selected modules and **exit without
    connecting** (deconfliction sheet: no authentication, no directory traffic;
    honours `--modules` / `--no-rpc`).

  Grounded in a live lab measurement (Server 2025 DC, default-audit vs
  instrumented): listdap's default footprint is the **NTLM auth quartet**
  (4776/4624/4672/4634) per bind — it uses NTLM, never Kerberos, without a
  ccache — and is otherwise invisible at the object level unless the DC has
  SACLs / advanced audit. `4662` lights up for SACLed object reads; the `rpc`
  module additionally yields `4661` + `5140`/`5145` (SAMR/IPC$/named-pipe).
  Artifacts carry a `tested` flag (`~` = inferred, e.g. MDI alerts, not
  lab-validated). Sysmon (SwiftOnSecurity) added nothing for signed-LDAP/RPC.

## [2.19.4] - 2026-11-16

### Fixed (live validation)

- **BitLocker Recovery GUID display** (bitlocker module). `msFVE-RecoveryGuid` is a
  binary GUID; it was read with `get_attr` and rendered as garbled bytes. It is now
  read raw and formatted as a GUID string (e.g. `75b0fb3d-44fb-4919-941e-94a5dd4dc7fd`).

## [2.19.3] - 2026-11-16

### Fixed (live validation)

- **ESC8 web-enrollment probe — hostname fallback** (adcs module). The probe
  targeted only the CA's `dNSHostName`, which an attacker box that doesn't use the
  domain's DNS cannot resolve, so a reachable `/certsrv/` was missed. It now
  probes the CA FQDN first (correct Host header) and **falls back to the `-dc` IP**
  (the enrollment host for a DC-hosted CA). Validated: `/certsrv/` on the DC IP is
  now reported as ESC8.

## [2.19.2] - 2026-11-16

### Fixed (live validation)

- **acls — sensitive-object check missed expanded masks** (`_is_dangerous_ace`).
  It only matched the generic bits (GENERIC_ALL 0x10000000 / GENERIC_WRITE
  0x40000000 / WriteDacl / WriteOwner), so a real **GenericAll stored as the
  expanded specific-rights mask** (0x000F01FF) on a sensitive object (e.g. Domain
  Admins) was **not flagged**. It now also matches the expanded FULL_CONTROL mask
  (→ GenericAll), write-ALL-properties (no specific GUID → WriteAllProperties) and
  `Write member` (→ CRITICAL), while still ignoring benign specific-property ACEs
  (e.g. the default Terminal Server License Servers ACE) to avoid noise — mirroring
  `_classify_control`. Validated: a GenericAll (0x000F01FF) ACE on Domain Admins is
  now reported CRITICAL; default WriteProperty ACEs are not.

## [2.19.1] - 2026-11-16

### Fixed (locale independence — found & validated on a French Windows Server 2025 DC)

Privileged-group / sensitive-object identification must not depend on English
display names (localized on non-English Windows, e.g. "Domain Admins" →
"Admins du domaine"):

- **acls module** — the "dangerous permissions on sensitive objects" check
  hardcoded `CN=Domain Admins,CN=Users,…`, which does not exist on a localized DC,
  so the Domain Admins ACL check was silently skipped. The privileged groups
  (Domain Admins / Enterprise Admins / Administrators) are now resolved from their
  **SID/RID via the `<SID=…>` DN**. Validated: a WriteDACL granted to a low-priv
  user on `CN=Admins du domaine` is now reported.
- **groups module** — **Protected Users** (RID 525) and **Remote Management Users**
  (`S-1-5-32-580`) were matched by English name; they are now in the SID/RID
  catalog, so they are detected regardless of locale.

## [2.19.0] - 2026-11-16

### Fixed / Changed (live validation against a Windows Server 2025 lab DC)

Found while validating listdap end-to-end against a real `corp.lab` (Server 2025,
DFL/FFL 2025) domain controller:

- **Functional level 10 → "Windows Server 2025"** (core/connection.py). It was
  shown as `Unknown (10)`; the FUNCTIONAL_LEVELS map now recognises level 10.
- **ADIDNS writable-records noise** (adidns module). The "writable existing
  records" and "zone create-child" checks treated **DNS-administrative groups**
  (DnsAdmins / DnsUpdateProxy, resolved by name→SID) and **high-value groups**
  (Key/Enterprise Key Admins etc., via `is_high_value_sid`) as non-privileged,
  flooding the output with ~50 records those principals may write *by design* —
  and falsely escalating a writable wildcard to CRITICAL through their default
  ACE. They are now excluded, so only genuinely non-privileged write (e.g. a
  low-priv user on a record) is reported.
- **Duplicate cleartext-credential finding** (utils/highlight.py). A value and its
  trailing-punctuation-stripped prefix were both emitted (`Winter2026Backup` +
  `Winter2026Backup!`); `extract_credentials` now drops the shorter when the only
  difference is trailing punctuation (keeps the fuller secret).

## [2.18.0] - 2026-11-16

### Added
- **Shadow Credentials parsing & risk scoring** (shadow module + `utils/keycred.py`).
  Instead of only flagging that `msDS-KeyCredentialLink` is set, the module now:
  - **parses the KEYCREDENTIALLINK_BLOB** (MS-ADTS 2.2.20, DN-Binary) → key id,
    **creation time**, device GUID, usage (NGC/FIDO), source (AD/AzureAD). The
    creation time is the tell that separates a planted backdoor from a Windows
    Hello for Business key;
  - **risk-scores each object** by target sensitivity: a key on krbtgt / a DC
    (UAC SERVER_TRUST) / an adminCount=1 or privileged-group account → **CRITICAL**
    persistence IOC; on a computer account → **HIGH** (Shadow-Credentials / RBCD
    artifact); on a plain user → **MEDIUM** (likely WHfB — verify the device/time);
  - emits one Quick Win per risk tier with the parsed per-key creation times, and
    a detail table (Object / Kind / Key created / Usage / Device / Risk).

### Changed
- The users module no longer raises its own (flat HIGH) Shadow-Credentials Quick
  Win — it keeps the inline flag and points to the SHADOW CREDENTIALS section,
  which now owns the parsed, risk-scored findings (no more duplicate finding).

## [2.17.0] - 2026-11-16

### Added
- **Foreign Security Principals module** (`fsp`) — cross-domain / forest members
  of local groups, pure LDAP:
  - enumerates `CN=ForeignSecurityPrincipals,<domain>` and keeps only real
    external domain SIDs (`S-1-5-21-<other>-<rid>`), skipping the benign
    well-known SIDs AD auto-seeds there and principals of this domain;
  - for each foreign SID, resolves **transitive** group membership
    (`LDAP_MATCHING_RULE_IN_CHAIN`) and classifies privilege via the groups
    catalog → a foreign principal in a privileged group (directly or nested) is a
    **CRITICAL/HIGH** cross-trust escalation / persistence path (compromise it in
    its home domain → inherit the privilege here);
  - resolves the **source trust** by matching the SID's domain against
    `trustedDomain` `securityIdentifier`, labels the trust kind/direction, and
    notes when SID filtering is OFF (additional SID-injection surface);
  - lists **orphan / stale FSPs** (no current group membership) as INFO — residue
    of a removed cross-domain grant / historical-access indicator.
  - Registered after `sidhistory`. Reuses the groups privilege catalog and the
    trusts SID-filtering helper.
  - ⚠️ **NOT VALIDATED LIVE**: unit-tested against mocked records only.

## [2.16.0] - 2026-11-16

### Added
- **Reversible password encryption detection** (users + policies modules).
  `ENCRYPTED_TEXT_PWD_ALLOWED` means the password is stored reversibly (RC4 under
  the SYSKEY), so a DCSync / secretsdump recovers the **cleartext**, not just the
  NT hash.
  - users: a new "Reversible Password Encryption" subsection + **HIGH** Quick Win
    for every account with UAC flag `0x80` (previously decoded but never surfaced);
    the flag is also added to the UAC summary (`REVERSIBLE_PWD`).
  - policies: the domain-wide `pwdProperties` bit `DOMAIN_PASSWORD_STORE_CLEARTEXT`
    (0x10) → **HIGH** Quick Win (every account affected).
- **AdminSDHolder orphan detection** (users module). The adminCount=1 list now
  cross-checks **current** protected-group membership and flags orphans — accounts
  that carry adminCount=1 but are no longer a (transitive) member of any protected
  group:
  - the protected-member set is resolved with the transitive membership matching
    rule (`LDAP_MATCHING_RULE_IN_CHAIN`, 1.2.840.113556.1.4.1941) over the
    AdminSDHolder-protected groups (by SID/RID), plus `primaryGroupID`;
  - a non-protected adminCount=1 account → **MEDIUM** Quick Win (residual privilege
    / stale locked ACL / adminCount persistence marker to review);
  - detection is best-effort: if the transitive query is unavailable it is skipped
    (no over-reporting) and the table marks membership `unknown`; `krbtgt` is
    excluded.

### Changed
- The AdminSDHolder (adminCount=1) subsection gains a "Still protected" column
  (yes / ORPHAN / unknown).

## [2.15.0] - 2026-11-16

### Added
- **Shadow-admin escalation analysis** (groups module). The module moves from
  listing high-value groups to explaining — and weaponising — what membership
  grants, for the privileges most audits overlook:
  - **SID/RID-driven catalog.** Privileged groups are matched by **objectSid /
    RID** (robust to renaming and locale) with a sAMAccountName fallback for the
    RID-less ones (DnsAdmins, Exchange, DHCP…). A non-empty group yields a Quick
    Win at its severity with the concrete escalation path and an abuse command:
    DnsAdmins → DLL into the DNS service → SYSTEM on a DC; Backup Operators →
    SeBackupPrivilege → SAM/NTDS read (DCSync-equiv); Server Operators → service
    → SYSTEM; Print Operators → SeLoadDriverPrivilege; Account Operators → reset
    passwords / add to unprotected privileged groups; Schema Admins → schema SD
    persistence; Exchange Windows Permissions → domain WriteDACL → DCSync;
    Key/Enterprise Key Admins → Shadow Credentials.
  - **Core vs shadow tier.** Expected-populated groups (Domain Admins / Enterprise
    Admins / Administrators) are reported as an INFO roster, not an alarm; the
    overlooked groups drive the severity-ranked Quick Wins.
  - **Member resolution.** Nested groups and **foreign (cross-domain) members**
    (ForeignSecurityPrincipals) are flagged; a foreign member notes the escalation
    is reachable across a trust.
  - **`member;range=` retrieval.** Groups with more than ~1500 members (where AD
    truncates `member` to a ranged attribute) are now fully paged, instead of
    silently losing members past the first chunk.

### Changed
- The groups module no longer matches privileged groups by name alone (fragile to
  renamed / localized groups) — the escalation catalog is SID/RID-first.

## [2.14.0] - 2026-11-16

### Added
- **ADIDNS wildcard (`*`) detection** (adidns module). A `*` record answers every
  otherwise-unresolved name in a zone, which changes how every other ADIDNS
  finding should be read:
  - **Wildcard inventory.** New "Wildcard records (*)" subsection lists any `*`
    node and its value, with a MEDIUM Quick Win: a present wildcard already
    catches missing-name / wpad queries (classic injection largely neutralised),
    but whoever can overwrite it controls resolution of *all* unresolved names
    (domain-wide MITM) — and its current target should be confirmed as expected.
  - **Create-child messaging is now wildcard-aware.** When a zone has no `*`, the
    spoofing Quick Win surfaces *planting a `*` catch-all* as the strongest option
    (domain-wide, beyond wpad) with the ready `dnstool.py --record '*'` command;
    when a `*` already exists, it says so and redirects to overwriting it instead
    of planting a redundant missing-name record.
  - **A writable wildcard is CRITICAL.** In the "writable records" check, an
    overwritable `*` is escalated from HIGH to **CRITICAL** and annotated, since
    it hijacks every unresolved name in the zone at once.

## [2.13.0] - 2026-11-15

### Added
- **GPO edit-rights / linked-scope abuse analysis** (gpo module). The module
  moves beyond inventory to the actual attack surface — a GPO is a code-execution
  primitive over everything it is linked to:
  - **Edit rights.** Reads each `groupPolicyContainer` `nTSecurityDescriptor` and
    flags non-privileged principals holding a write right (GenericWrite /
    GenericAll / WriteDACL / WriteOwner / WriteProperty) → they can push a
    scheduled task / startup script / immediate task (SharpGPOAbuse, pyGPOAbuse).
    Already-privileged trustees and the default full-control principals
    (SYSTEM / Creator Owner / BUILTIN\Administrators / Enterprise DCs) are
    filtered out; a right held by the current identity is marked `(you)`.
  - **Linked-scope severity.** Parses `gPLink` on OU / domain / site objects
    (across the domain NC and the configuration NC) to find where each GPO
    applies, and sets severity by blast radius: **domain root** or the **Domain
    Controllers OU** → CRITICAL; any other OU or a site → HIGH; editable but
    linked nowhere → MEDIUM (latent). Disabled links are shown as such.
  - Quick Wins carry ready-to-run **pyGPOAbuse** (Linux) and **SharpGPOAbuse**
    (Windows) commands filled with the GPO id / name and the session creds.
  - Reuses `modules.acls._parse_dacl` and `utils.sids` privilege filtering.
  - ⚠️ **NOT VALIDATED LIVE**: the edit-rights / linked-scope analysis is
    unit-tested against synthetic descriptors only (plain inventory was validated
    earlier).

## [2.12.0] - 2026-11-15

### Added
- **ADIDNS module** (`adidns`) — AD-integrated DNS enumeration and spoofing
  surface, pure LDAP against the DNS application partitions
  (`DC=DomainDnsZones,…`, `DC=ForestDnsZones,…`, legacy `CN=MicrosoftDNS,CN=System,…`):
  - **Recon.** Parses the binary `dnsRecord` attribute of every `dnsNode`
    (`utils/dnsrecord.py`: A / AAAA / CNAME / NS / PTR / MX / SRV / TXT / SOA /
    DNAME) → full internal name→IP map, services, and hosts absent from the
    computers module — no DNS query, no zone transfer. INFO Quick Win with the
    host list.
  - **Zone Create-Child (spoofing).** Reads each zone's DACL and flags
    Create-Child / GenericWrite / GenericAll granted to a non-privileged
    trustee → the identity can add arbitrary records (NTLM coercion / relay).
    **HIGH** when the trustee is broad (Everyone / Authenticated Users / Domain
    Users / Domain Computers — the common default), MEDIUM for a group-scoped
    trustee. Notes a missing `wpad` record as a direct spoofing target. Quick
    Win emits ready-to-run `dnstool.py` (dirkjanm) and `Powermad` commands.
  - **Writable existing records (hijack).** Reads each `dnsNode` DACL and flags
    records writable (GenericAll / WriteDACL / WriteOwner / GenericWrite /
    WriteProperty) by a non-privileged principal → an existing name can be
    overwritten (redirect a server's A record). **HIGH**, with a `dnstool.py
    --action modify` Quick Win.
  - Reuses `modules.acls._parse_dacl` for DACL parsing and the shared
    `utils.sids` privilege filtering; registered after `trusts`.
  - ⚠️ **NOT VALIDATED LIVE**: implemented and unit-tested against mocked
    records / synthetic descriptors, never run against a real DC.

## [2.11.0] - 2026-11-15

### Added
- **Richer trustAttributes analysis** (trusts module):
  - new flag **`TRUST_ATTRIBUTE_CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION`
    (0x800)** decoded, and **TGT-delegation analysis**: explicit-enable → HIGH
    (cross-forest unconstrained-delegation path), a forest trust with neither
    enable nor the `NO_TGT_DELEGATION` guard → MEDIUM (confirm the DC is patched);
  - **`USES_RC4_ENCRYPTION` (0x80)** → MEDIUM: the inter-realm trust key is
    RC4/NT-hash-derived, easing inter-realm TGT forgery once the trust key is
    dumped;
  - unknown high bits are now appended to the decoded string as a hex remainder.

### Changed
- **More accurate SID-filtering detection.** The previous heuristic flagged any
  outbound/bidirectional non-within-forest trust, over-reporting forest trusts
  (which enforce SID filtering by default). It now applies only to **external**
  trusts (quarantine bit absent → filtering off → SID-history injection), with
  forest trusts handled by the TGT-delegation / forest-pivot findings instead.
  Dangerous trusts (TGT delegation enabled) are highlighted red in the table.

## [2.10.0] - 2026-11-15

### Added
- **Kerberos encryption-type decoding** (`utils/enctypes.py`) — the users module
  now decodes `msDS-SupportedEncryptionTypes` (previously fetched but unused):
  - the Kerberoastable and AS-REP tables gain an **Enc** column, coloured red for
    DES and yellow when RC4 is reachable;
  - a new **"Weak Kerberos Encryption"** subsection lists **DES-enabled** accounts
    (→ HIGH Quick Win: Kerberos material trivially crackable) and **RC4-reachable
    roastable** accounts (→ MEDIUM Quick Win: request an etype-23 ticket for a
    fast `-m 13100`/`-m 18200` crack, a downgrade even when AES is also allowed);
  - classification (`weakness()`): DES / RC4-only / RC4+AES / RC4-default (attribute
    unset → RC4 fallback) / strong (AES-only); disabled accounts are excluded.

## [2.9.0] - 2026-11-15

### Added
- **BitLocker module** (`bitlocker`) — searches for `msFVE-RecoveryInformation`
  objects (the recovery info a machine escrows to AD under its computer object)
  and reports the 48-digit `msFVE-RecoveryPassword` wherever the DC returns it
  (i.e. wherever the current identity may read it — over-permissioned OUs /
  delegations routinely expose it to low-priv users). A readable key is
  **CRITICAL** → offline access to the volume; the Quick Win carries the
  `manage-bde -unlock` and `dislocker` commands. The computer name is derived
  from the recovery object's parent DN. When objects exist but the password is
  withheld, the module still inventories which machines escrow BitLocker and
  notes that reading needs Domain Admins / a delegated read.

### Notes
- ⚠️ **Not yet validated live** — unit-tested against mocked records (readable,
  withheld and empty), but never run against a real DC holding
  msFVE-RecoveryInformation.

## [2.8.0] - 2026-11-15

### Added
- **Credential scanning beyond `description`.** The users module now runs the
  credential heuristic over more attributes:
  - free-text: **`info`** (the ADUC "Notes" field — a frequent offender),
    **`comment`**, and **`extensionAttribute1-15`** (Exchange custom attributes);
  - password-bearing: **`userPassword`** and **`unixUserPassword`**, whose entire
    value is treated as the secret (cleartext → CRITICAL with a ready re-run
    command; `{SCHEME}`-prefixed hash → HIGH with a crack-offline note).
  A new **"Secrets in attributes"** subsection lists every hit (user / attribute /
  highlighted value), the summary counter gains a `secrets in attrs` count, and
  each finding yields a Quick Win mirroring the existing description flow.

### Changed
- **More reliable credential extraction** (`utils/highlight.py`,
  `extract_credentials`): standalone password-shaped tokens (8+ chars,
  upper+lower+digit) are now always collected and merged with keyword+value
  matches, and captured values that are themselves a credential keyword or a
  common filler word are dropped. So `"Default password: Sup3rP@ss123"` yields
  `Sup3rP@ss123` (not `password`) and `"Password for backup: X"` yields `X` (not
  `for`).

### Fixed
- **Standalone-password regex over-matching** (`_PWD_STANDALONE_RE`): the
  complexity lookaheads (`\D*\d`, `[^A-Z]*[A-Z]`, …) were unbounded and crossed
  whitespace, so a plain word like `Password` matched whenever a digit appeared
  anywhere later in the string. The lookaheads are now bounded to the token
  (whitespace-excluding), fixing false positives in both highlighting and
  extraction.

## [2.7.0] - 2026-11-15

### Added
- **sIDHistory module** (`sidhistory`) — enumerates objects whose `sIDHistory`
  attribute is populated (one `(sIDHistory=*)` LDAP search, multi-valued binary
  SIDs). Each SID is resolved and classified:
  - **Privileged SID** (Domain Admins, Administrators, Enterprise Admins, RID
    500/512/519, high-value builtins) → **CRITICAL**: the SID is injected into the
    token at logon like a group membership, so the account is effectively
    privileged while appearing unprivileged (mimikatz/DCShadow sid-history
    persistence IOC). Quick Win notes the DCSync path for a controlled account.
  - **Foreign-domain SID** (`S-1-5-21-…` not from the current domain) → **HIGH**:
    cross-domain migration artifact or SID-history injection across a trust
    (impactful where SID filtering / quarantine is not enforced).
  - Same-domain non-privileged SIDs are shown as benign migration artifacts.
  - Reuses `is_privileged_sid` / `is_high_value_sid` / `resolve_sid`; covers
    users, computers, groups and trust accounts.

### Notes
- ⚠️ **Not yet validated live** — unit-tested against mocked records (privileged,
  foreign and benign sIDHistory values), but never run against a real DC with
  populated sIDHistory.

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
