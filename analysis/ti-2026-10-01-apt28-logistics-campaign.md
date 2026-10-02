---
title: "Russian GRU Targeting Western Logistics Entities and Technology Companies"
source_url: https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-141a
pdf_url: https://media.defense.gov/2025/May/21/2003719846/-1/-1/0/CSA_Russian_GRU_Target_Logistics_v1-1.PDF
advisory_id: AA25-141A
publication_date: 2025-05-21
last_revised: 2026-04 (correction to two domains)
extraction_date: 2026-10-01
threat_actor: GRU 85th GTsSS, military unit 26165 (APT28 / Fancy Bear / Forest Blizzard / BlueDelta, ATT&CK G0007)
attack_version_in_source: v17
stix:
  - https://www.cisa.gov/sites/default/files/AA25-141A_Russian_GRU_Targeting_Western_Logistics_Entities_and_Technology_Companies.stix.json
  - https://www.cisa.gov/sites/default/files/AA25-141A_Russian_GRU_Targeting_Western_Logistics_Entities_and_Technology_Companies.stix.xml
---

# APT28 (GRU Unit 26165): Campaign Against Western Logistics and Tech Companies

## Threat Overview

| Field | Detail |
|---|---|
| **Actor** | Russian GRU 85th GTsSS, military unit 26165, known as [APT28 (G0007)](https://attack.mitre.org/groups/G0007/), Fancy Bear, Forest Blizzard, and BlueDelta |
| **Motivation** | Espionage. The goal is to track the delivery of foreign aid to Ukraine: senders, recipients, train/plane/ship numbers, routes, container numbers, and cargo. |
| **Target sectors** | Defense industry, transportation and hubs (ports, airports), maritime, air traffic management, and IT services. The actor also did reconnaissance on a maker of railway ICS components, but no compromise was confirmed. |
| **Target countries** | Bulgaria, Czech Republic, France, Germany, Greece, Italy, Moldova, Netherlands, Poland, Romania, Slovakia, Ukraine, and the United States |
| **IP camera sub-campaign** | Began in March 2022. More than 10,000 RTSP cameras were targeted, with 81% in Ukraine, 9.9% in Romania, 4% in Poland, 2.8% in Hungary, and 1.7% in Slovakia. Targets were near border crossings, military sites, and rail stations. |
| **Time period** | Ran from February 2022 to at least May 2025. The WinRAR exploitation started in fall 2023. The listed brute-force IPs date from June to August 2024. |
| **Malware** | HEADLACE and MASEPIE were observed. OCEANMAP and STEELHOOK may also be used but were not seen against logistics victims. |
| **Authoring agencies** | 21 agencies, including NSA, FBI, CISA, NCSC-UK, BSI, ANSSI, and ASD's ACSC |

### Source mapping caveats
- The advisory uses ATT&CK v17. In v19, **T1070.001 (Clear Windows Event Logs) moved to [T1685.005](https://attack.mitre.org/techniques/T1685/005/)**. This report uses the v19 ID when choosing atomic tests.
- **T1627 / T1627.001** in the advisory are **Mobile** ATT&CK IDs. The Enterprise equivalent for the redirector geofencing is [T1480 / T1480.001](https://attack.mitre.org/techniques/T1480/001/), and that is the mapping used here.
- **T1659 (Content Injection)** does not fit WinRAR CVE-2023-38831 well. [T1203 Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203/) is listed below as the better mapping.
- The advisory's T1187 hyperlink points to a D3FEND page by mistake. The technique ID itself is correct.

---

## TTPs (MITRE ATT&CK)

Confidence ratings:
- **High:** the advisory gives a specific tool, command, or procedure.
- **Medium:** the behavior is stated without detail.
- **Low:** the behavior is only mentioned in passing, or the mapping was inferred.

### Reconnaissance & Resource Development
| ID | Technique | Use in campaign | Confidence |
|---|---|---|---|
| [T1589.002](https://attack.mitre.org/techniques/T1589/002/) | Gather Victim Identity Info: Email Addresses | After compromise, gathered contact information to find more targets in key roles. | Medium |
| [T1591](https://attack.mitre.org/techniques/T1591/) / [.002](https://attack.mitre.org/techniques/T1591/002/) / [.004](https://attack.mitre.org/techniques/T1591/004/) | Gather Victim Org Info | Researched the victim's security department, transport coordinators, and partner companies. | Medium |
| [T1592](https://attack.mitre.org/techniques/T1592/) | Gather Victim Host Info | Enumerated RTSP servers that host IP cameras. | High |
| [T1586.002](https://attack.mitre.org/techniques/T1586/002/) / [.003](https://attack.mitre.org/techniques/T1586/003/) | Compromise Accounts: Email / Cloud | Sent phishing from compromised accounts and free webmail. | High |
| [T1665](https://attack.mitre.org/techniques/T1665/) | Hide Infrastructure | Proxied activity through compromised SOHO devices located near the target. | Medium |

### Initial Access
| ID | Technique | Use in campaign | Confidence |
|---|---|---|---|
| [T1110.001](https://attack.mitre.org/techniques/T1110/001/) / [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Password Guessing / Spraying | Guessed and sprayed credentials through Tor and commercial VPNs, with frequent IP rotation and TLS on every connection. | High |
| [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | Spearphishing Link | Sent one target at a time, in the target's own language, a link to a fake government or cloud-mail login page hosted on free services or compromised SOHO devices. | High |
| [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Spearphishing Attachment | Attached WinRAR CVE-2023-38831 archives and HEADLACE/MASEPIE payloads. | High |
| [T1566.004](https://attack.mitre.org/techniques/T1566/004/) | Spearphishing Voice | Made at least one vishing attempt, posing as IT staff to get privileged access. | Medium |
| [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | Exploited Roundcube CVE-2020-12641, CVE-2020-35730, and CVE-2021-44026, plus SQL injection. | High |
| [T1133](https://attack.mitre.org/techniques/T1133/) | External Remote Services | Exploited corporate VPNs. | Medium |
| [T1199](https://attack.mitre.org/techniques/T1199/) | Trusted Relationship | Used business ties to pivot to partner transport companies. | Medium |
| [T1203](https://attack.mitre.org/techniques/T1203/) (source: T1659) | Exploitation for Client Execution | WinRAR CVE-2023-38831, which runs code embedded in an archive. | High |

### Execution
| ID | Technique | Use in campaign | Confidence |
|---|---|---|---|
| [T1204.001](https://attack.mitre.org/techniques/T1204/001/) / [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | User Execution: Link / File | Got users to open hosted shortcuts and malware executables. | High |
| [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | Windows Command Shell | Ran HEADLACE BAT scripts, including headless Edge, `chcp 65001`, and `taskkill`. | High |
| [T1059.005](https://attack.mitre.org/techniques/T1059/005/) | Visual Basic | Delivered VBScript in spearphishing. | Medium |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell | Staged data for exfiltration, ran an NTLM listener, and used a `Get-Credential` lure loop. | High |
| [T1059.006](https://attack.mitre.org/techniques/T1059/006/) | Python | Installed Python to run Certipy, Get-GPPPassword.py, and ldap-dump.py. | High |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled Task | Created tasks with `schtasks /create /xml`. | High |

### Persistence
| ID | Technique | Use in campaign | Confidence |
|---|---|---|---|
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled Task | Same activity as listed under Execution. | High |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Registry Run Keys | Used Run keys for persistence. | Medium |
| [T1547.009](https://attack.mitre.org/techniques/T1547/009/) | Shortcut Modification | Placed malicious LNK files in the Startup folder. | Medium |
| [T1098.002](https://attack.mitre.org/techniques/T1098/002/) | Additional Email Delegate Permissions | Changed mailbox and folder permissions to keep collecting email. | High |
| [T1556.006](https://attack.mitre.org/techniques/T1556/006/) | Modify Auth Process: MFA | Enrolled compromised accounts in MFA to make them look more trusted. | High |

### Privilege Escalation
| ID | Technique | Use in campaign | Confidence |
|---|---|---|---|
| [T1574.001](https://attack.mitre.org/techniques/T1574/001/) | DLL Search Order Hijacking | Used DLL search-order hijacking to run malware. | Medium |
| [T1552.006](https://attack.mitre.org/techniques/T1552/006/) | GPP Passwords | Ran Get-GPPPassword.py to recover plaintext credentials. | High |

### Defense Evasion
| ID | Technique | Use in campaign | Confidence |
|---|---|---|---|
| [T1685.005](https://attack.mitre.org/techniques/T1685/005/) (source: T1070.001) | Clear Windows Event Logs | Deleted event logs with `wevtutil`. | High |
| [T1574.001](https://attack.mitre.org/techniques/T1574/001/) | DLL Search Order Hijacking | Same activity as listed under Privilege Escalation. | Medium |
| [T1480.001](https://attack.mitre.org/techniques/T1480/001/) (source: T1627.001) | Execution Guardrails: Geofencing | Redirectors checked IP geolocation and browser fingerprint, and sent visitors that failed the check to msn.com. | High |
| [T1222.001](https://attack.mitre.org/techniques/T1222/001/) *(inferred)* | Windows File Permissions Modification | The advisory lists `cacls`/`icacls` as used utilities. | Low |

### Credential Access
| ID | Technique | Use in campaign | Confidence |
|---|---|---|---|
| [T1187](https://attack.mitre.org/techniques/T1187/) | Forced Authentication | Sent crafted calendar invites that exploit Outlook CVE-2023-23397 to leak NTLM hashes. | High |
| [T1003.003](https://attack.mitre.org/techniques/T1003/003/) | NTDS | Ran `ntdsutil "activate instance ntds" ifm "create full C:\temp\xxx"` over RDP. May also have used vssadmin. | High |
| [T1552.006](https://attack.mitre.org/techniques/T1552/006/) | GPP Passwords | Ran Get-GPPPassword.py. | High |
| [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Password Spraying | Sprayed passwords internally over LDAP with a modified ldap-dump.py. | High |
| [T1111](https://attack.mitre.org/techniques/T1111/) | MFA Interception | Phishing redirectors relayed MFA codes. | Medium |
| [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture | Relayed CAPTCHAs, and HEADLACE showed a fake `Get-Credential` prompt. | Medium |
| [T1649](https://attack.mitre.org/techniques/T1649/) *(inferred)* | Steal or Forge Auth Certificates | Used Certipy against AD CS. The advisory only says it was used for AD data exfiltration. | Low |

### Discovery
| ID | Technique | Use in campaign | Confidence |
|---|---|---|---|
| [T1087.002](https://attack.mitre.org/techniques/T1087/002/) | Domain Account Discovery | Ran ldap-dump.py and ADExplorer, and enumerated Office 365 user lists. | High |
| [T1033](https://attack.mitre.org/techniques/T1033/), [T1057](https://attack.mitre.org/techniques/T1057/), [T1082](https://attack.mitre.org/techniques/T1082/), [T1016](https://attack.mitre.org/techniques/T1016/) *(inferred)* | Owner/User, Process, System Info, Network Config Discovery | The advisory lists `whoami`, `tasklist`, `hostname`, `systeminfo`, `arp`, `net`, and `wmic` as used utilities. | Medium |

### Lateral Movement
| ID | Technique | Use in campaign | Confidence |
|---|---|---|---|
| [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | RDP | Used RDP to reach more hosts and domain controllers. | High |
| [T1021.002](https://attack.mitre.org/techniques/T1021/002/) / [T1569.002](https://attack.mitre.org/techniques/T1569/002/) *(inferred)* | SMB Admin Shares / Service Execution | Used Impacket (both .py and .exe builds) and PsExec. The advisory maps this only to TA0008. | Medium |

### Collection
| ID | Technique | Use in campaign | Confidence |
|---|---|---|---|
| [T1114.002](https://attack.mitre.org/techniques/T1114/002/) | Remote Email Collection | Pulled mail over EWS and IMAP, and through the Roundcube exploits. | High |
| [T1119](https://attack.mitre.org/techniques/T1119/) | Automated Collection | Ran periodic EWS queries for mail since the last pull. | High |
| [T1560.001](https://attack.mitre.org/techniques/T1560/001/) | Archive via Utility | Zipped files with PowerShell before exfiltration. | High |
| [T1125](https://attack.mitre.org/techniques/T1125/) | Video Capture | Accessed RTSP camera feeds and snapshots. | High |

### Command and Control
| ID | Technique | Use in campaign | Confidence |
|---|---|---|---|
| [T1090.003](https://attack.mitre.org/techniques/T1090/003/) | Multi-hop Proxy | Routed traffic through Tor and commercial VPNs. | High |
| [T1090.002](https://attack.mitre.org/techniques/T1090/002/) | External Proxy | Sent RTSP DESCRIBE requests through compromised routers. | High |
| [T1573](https://attack.mitre.org/techniques/T1573/) | Encrypted Channel | Used TLS for all brute-force connections. | Medium |
| [T1104](https://attack.mitre.org/techniques/T1104/) | Multi-Stage Channels | Chained redirectors such as webhook.site, Mocky, and Pipedream. | Medium |

### Exfiltration
| ID | Technique | Use in campaign | Confidence |
|---|---|---|---|
| [T1048](https://attack.mitre.org/techniques/T1048/) | Exfil Over Alternative Protocol | Attempted exfiltration through a dropped OpenSSH binary (`ssh -Nf`). | High |
| [T1029](https://attack.mitre.org/techniques/T1029/) | Scheduled Transfer | Exfiltrated in periodic batches with long gaps, using infrastructure geographically near the victim. | High |

### Impact
None observed. The campaign was espionage only, with no destructive or encryption activity reported.

---

## Indicators of Compromise

> **Caveat:** The advisory says these IOCs may no longer be under actor control. Some may be compromised third-party infrastructure or shared Tor/VPN exits. Vet them before blocking. All values below are defanged.

### IP addresses: Outlook CVE-2023-23397 exploitation
- 213.32.252[.]221
- 124.168.91[.]178
- 194.126.178[.]8
- 159.196.128[.]120

### IP addresses: brute forcing (June–August 2024)
| Month | IPs |
|---|---|
| June 2024 | 192.162.174[.]94, 103.97.203[.]29, 209.14.71[.]127, 109.95.151[.]207 |
| July 2024 | 207.244.71[.]84, 162.210.194[.]2 |
| August 2024 | 31.135.199[.]145, 31.42.4[.]138, 46.112.70[.]252, 46.248.185[.]236, 64.176.67[.]117, 64.176.69[.]196, 64.176.70[.]18, 64.176.70[.]238, 64.176.71[.]201, 70.34.242[.]220, 70.34.243[.]226, 70.34.244[.]100, 70.34.245[.]215, 70.34.252[.]168, 70.34.252[.]186, 70.34.252[.]222, 70.34.253[.]13, 70.34.253[.]247, 70.34.254[.]245, 79.184.25[.]198, 79.185.5[.]142, 83.10.46[.]174, 83.168.66[.]145, 83.168.78[.]27, 83.168.78[.]31, 83.168.78[.]55, 83.23.130[.]49, 83.29.138[.]115, 89.64.70[.]69, 90.156.4[.]204, 91.149.202[.]215, 91.149.203[.]73, 91.149.219[.]158, 91.149.219[.]23, 91.149.223[.]130, 91.149.253[.]118, 91.149.253[.]198, 91.149.253[.]20, 91.149.253[.]204, 91.149.254[.]75, 91.149.255[.]122, 91.149.255[.]19, 91.149.255[.]195, 91.221.88[.]76, 93.105.185[.]139, 95.215.76[.]209, 138.199.59[.]43, 147.135.209[.]245, 178.235.191[.]182, 178.37.97[.]243, 185.234.235[.]69, 192.162.174[.]67, 194.187.180[.]20, 212.127.78[.]170, 213.134.184[.]167 |

### Domains: hosting, redirector, and API-mocking services to alert on or block
The advisory recommends alerting on these, with an allowlist for legitimate use. They are shared services, not actor-owned domains.

`*.000[.]pe`, `*.1cooldns[.]com`, `*.42web[.]io`, `*.4cloud[.]click`, `*.accesscam[.]org`, `*.bumbleshrimp[.]com`, `*.camdvr[.]org`, `*.casacam[.]net`, `*.ddnsfree[.]com`, `*.ddnsgeek[.]com`, `*.ddnsguru[.]com`, `*.dynuddns[.]com`, `*.dynuddns[.]net`, `*.free[.]nf`, `*.freeddns[.]org`, `*.frge[.]io`, `*giize[.]com`, `*.great-site[.]net`, `*.infinityfreeapp[.]com`, `*.kesug[.]com`, `*.loseyourip[.]com`, `*.lovestoblog[.]com`, `*.mockbin[.]io`, `*.mockbin[.]org`, `*.mocky[.]io`, `*.mybiolink[.]io`, `*.mysynology[.]net`, `*.mywire[.]org`, `*.ngrok[.]io`, `*.ooguy[.]com`, `*.pipedream[.]net`, `*.rf[.]gd`, `*.urlbae[.]com`, `*.webhook[.]site`, `*.webhookapp[.]com`, `*.webredirect[.]org`, `*.wuaze[.]com`

**Redirector services named in the advisory:** Webhook[.]site, FrgeIO, InfinityFree, Dynu, Mocky, Pipedream, and Mockbin[.]org.

**Webmail providers used for phishing:** portugalmail[.]pt, mail-online[.]dk, email[.]cz, and seznam[.]cz.

### Email addresses: Outlook CVE-2023-23397 senders (probably compromised accounts)
- md-shoeb@alfathdoor[.]com[.]sa
- jayam@wizzsolutions[.]com
- accounts@regencyservice[.]in
- m.salim@tsc-me[.]com
- vikram.anand@4ginfosource[.]com
- mdelafuente@ukwwfze[.]com
- sarah@cosmicgold469[.]co[.]za
- franch1.lanka@bplanka[.]com
- commerical@vanadrink[.]com
- maint@goldenloaduae[.]com
- karina@bhpcapital[.]com
- tv@coastalareabank[.]com
- ashoke.kumar@hbclife[.]in

### File hashes
None in the advisory text. Check the STIX bundles linked in the frontmatter.

### File names (CVE-2023-38831 archives)
`calc.war.zip`, `news_week_6.zip`, `Roadmap.zip`, `SEDE-PV-2023-10-09-1_EN.zip`, `war.zip`, `Zeyilname.zip`

### File paths and command-line patterns (hunting)
| Pattern | Context |
|---|---|
| `ntdsutil.exe "activate instance ntds" ifm "create full C:\temp\[a-z]{3}" quit quit` | NTDS dump to a three-letter folder under `C:\temp` |
| `edge.exe --headless=new --disable-gpu` / `msedge --headless=new` | HEADLACE launcher |
| `whoami>"%programdata%...`, `del /q /f "%programdata%...`, `del /q /f "%userprofile%\Downloads\...` | HEADLACE batch script artifacts |
| `ssh -Nf` | OpenSSH tunnel used for exfiltration |
| `schtasks /create /xml` | Scheduled task persistence |
| `wevtutil cl ...` | Event log clearing |
| `[InternetShortcut]` + `file://` + `msedge.exe` + `IconFile` | HEADLACE `.url` shortcut dropper |
| PowerShell `HttpListener` on `http://localhost:8080/` that handles NTLM `Authorization` headers | Custom NTLM listener |

### Registry keys
The advisory doesn't name specific keys. It says Run keys were used (T1547.001), so hunt `HKCU\` and `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` for unknown entries.

### Other strings
- Hikvision backdoor string: `YWRtaW46MTEK`, which is Base64 for `admin:11`
- RTSP `DESCRIBE` requests with `User-Agent: WebClient` and Basic or Digest auth for the user `admin`

### Tools
| Category | Tools |
|---|---|
| Malicious scripts or tools | Certipy, Get-GPPPassword.py, ldap-dump.py (modified), Impacket (.py and .exe builds), PsExec, ADExplorer |
| Malware | HEADLACE and MASEPIE observed; OCEANMAP and STEELHOOK possible |
| Living-off-the-land binaries | ntdsutil, wevtutil, vssadmin, OpenSSH/ssh, schtasks, whoami, tasklist, hostname, arp, systeminfo, net, wmic, cacls, icacls, reg |

### Vulnerabilities
| CVE | Product |
|---|---|
| [CVE-2023-23397](https://nvd.nist.gov/vuln/detail/CVE-2023-23397) | Outlook NTLM leak |
| [CVE-2023-38831](https://nvd.nist.gov/vuln/detail/CVE-2023-38831) | WinRAR |
| [CVE-2020-12641](https://nvd.nist.gov/vuln/detail/CVE-2020-12641), [CVE-2020-35730](https://nvd.nist.gov/vuln/detail/CVE-2020-35730), [CVE-2021-44026](https://nvd.nist.gov/vuln/detail/CVE-2021-44026) | Roundcube |

### Detection content in the advisory
The advisory includes YARA rules for:
- `APT28_NTLM_LISTENER`
- `APT28_HEADLACE_SHORTCUT`
- `APT28_HEADLACE_CREDENTIALDIALOG`
- `APT28_HEADLACE_CORE`
- `APT28_MASEPIE`
- `APT28_STEELHOOK`
- `GENERIC_PSEXEC`

These are reproduced in the source. Microsoft also publishes a CVE-2023-23397 audit script (https://aka.ms/CVE-2023-23397ScriptDoc).

---

## Simulation Plan (Atomic Red Team)

Test numbers come from the Atomic Red Team master `Indexes-CSV/index.csv`, pulled 2026-10-01. Before running a test, check its GUID with `Invoke-AtomicTest <ID> -ShowDetailsBrief`. Run tests only in a lab or an authorized test environment.

Priority rules:
- **P1:** high confidence, and an atomic closely matches the advisory's procedure.
- **P2:** an atomic exists but only approximates the behavior.
- **P3:** low confidence, or a supporting technique.

### P1: High confidence with a close match
| Technique | Atomic test(s) | Fit |
|---|---|---|
| T1003.003 | **#3 Dump Active Directory Database with NTDSUtil**; #1 Create Volume Shadow Copy with vssadmin | Uses the advisory's exact `ntdsutil ifm` procedure. vssadmin is also listed. |
| T1552.006 | **#2 GPP Passwords (Get-GPPPassword)**; #1 GPP Passwords (findstr) | Same tool the actor used. |
| T1110.003 | **#3 Password spray all AD domain users via LDAP**; #7 MSOLSpray (Azure/O365) | Matches the internal LDAP spray and the external cloud spray. |
| T1110.001 | #2 Brute force single AD user via LDAP; #3 Brute force single Azure AD user | Initial-access credential guessing. |
| T1685.005 | **#1 Clear Logs** (wevtutil) | Same utility as the advisory. |
| T1053.005 | **#8 Import XML Schedule Task with Hidden Attribute**; #2 Scheduled task Local | #8 matches `schtasks /create /xml`. |
| T1547.009 | #2 Create shortcut to cmd in startup folders | Startup-folder LNK. |
| T1547.001 | #1 Reg Key Run | Run key persistence. |
| T1098.002 | **#1 EXO – Full access mailbox permission granted to a user** | Matches the mailbox permission abuse. |
| T1114.002 | **#1 Office365 – Remote Mail Collected** | EWS-style remote collection. |
| T1087.002 | #24 Account Enumeration with LDAPDomainDump; #7 Adfind – Enumerate AD User Objects | Closest to the ldap-dump.py / ADExplorer enumeration. |
| T1021.001 | #1 RDP to Remote Host | |
| T1569.002 | **#3 psexec.py (Impacket)**; #2 Use PsExec to execute a command on a remote host | Both tools are named in the advisory. |
| T1560.001 | #4 Compress with 7zip (or use T1560 #1 *Compress Data for Exfiltration With PowerShell*) | The advisory says PowerShell zip, so **T1560 #1** is the closest match. |
| T1048 | #1 / #2 Exfiltration Over Alternative Protocol – SSH | Matches the OpenSSH exfiltration. These tests are `sh`, so run them from a Linux host or adapt them for Windows OpenSSH. |
| T1090.003 | **#2 Tor Proxy Usage – Windows** | Tor anonymization. |
| T1059.006 | #3 Execute Python via Python executables | The actor installed Python to run its tools. |

### P2: Atomic approximates the behavior
| Technique | Atomic test(s) | Gap |
|---|---|---|
| T1187 | #3 Trigger an authenticated RPC call with no Sign flag; #1 PetitPotam | No Outlook-reminder test for CVE-2023-23397. Use Microsoft's audit script and alert on outbound SMB/NTLM to the internet. |
| T1566.001 | #1 Download Macro-Enabled Phishing Attachment | No WinRAR CVE-2023-38831 test. A benign archive delivery is a reasonable stand-in for email-gateway testing. |
| T1566.002 | #1 Paste and run technique | Doesn't match credential harvesting. Run a phishing simulation platform instead. |
| T1204.002 | Any of the 13 tests | Generic user-execution coverage. |
| T1059.003 | #1 Create and Execute Batch Script | Approximates HEADLACE BAT. Add headless-Edge launch detection. |
| T1059.005 | #1 VBS execution to gather local computer info | |
| T1059.001 | Various | Approximates the NTLM-listener and credential-prompt scripts. Validate with the advisory's YARA rules. |
| T1574.001 | #1 DLL Search Order Hijacking – amsi.dll; #7 ntprint | The advisory doesn't name the hijacked DLL. |
| T1119 | #2 Automated Collection PowerShell | The real activity was periodic EWS polling. |
| T1573 | #1 OpenSSL C2 | |
| T1033 / T1057 / T1082 / T1016 | whoami, tasklist, systeminfo, and arp tests (multiple per technique) | Covers the LOTL discovery set. |
| T1222.001 | cacls/icacls tests | |
| T1125 | #1 Registry artefact when application uses webcam | Doesn't fit RTSP camera access. Test perimeter RTSP (554/tcp) exposure instead. |

### P3: Low confidence or inferred
| Technique | Atomic test(s) |
|---|---|
| T1649 (Certipy / AD CS) | #1 Staging Local Certificates via Export-Certificate. This is weak. Consider a manual Certipy `find` in the lab. |

### Techniques with no atomic tests
| Technique | Alternative validation |
|---|---|
| T1190: Roundcube CVEs / SQL injection | Run vulnerability scans and confirm patch levels. Review webmail logs. |
| T1133: VPN exploitation | Audit VPN logs for logins from Tor or commercial VPN exits (the existing T1133 atomic, a Chrome VPN extension, doesn't fit). |
| T1199: Trusted Relationship | Review third-party and partner access. Run a tabletop exercise. |
| T1566.004: Vishing | Run a social-engineering exercise against the help desk. |
| T1556.006: MFA enrollment | Manually enroll a new MFA device on a test account and confirm the Azure AD audit log alert fires. |
| T1111 / T1056: MFA and CAPTCHA relay | Use an adversary-in-the-middle phishing simulation, but only with an authorized vendor. |
| T1480.001: Geofenced redirectors | Not applicable to endpoint testing. Hunt DNS and proxy logs for the listed services. |
| T1104, T1090.002, T1665, T1029 | Network and infrastructure behaviors. Validate them through proxy and NetFlow analytics. |
| Recon (T1589, T1591, T1592), Resource Development (T1586) | Pre-compromise. Not simulatable on endpoints. |

### Suggested execution order
1. **Initial access (cloud identity):** T1110.003 #7 and T1110.001 #3 from a Tor exit (T1090.003 #2).
2. **Persistence in the cloud:** T1098.002 #1, then the manual MFA enrollment (T1556.006).
3. **Collection from the cloud:** T1114.002 #1.
4. **Endpoint foothold:** T1566.001 #1, T1059.003 #1, T1053.005 #8, T1547.001 #1, and T1547.009 #2.
5. **Discovery and credentials:** T1033, T1082, and T1016, then T1087.002 #24, T1552.006 #2, and T1110.003 #3.
6. **Lateral movement and credential dumping:** T1569.002 #3, then T1021.001 #1 to a lab DC, then T1003.003 #3.
7. **Staging and exfiltration:** T1560 #1, then T1048 #1.
8. **Cleanup:** T1685.005 #1.

### Expected telemetry by project log source
| Log source | What should fire |
|---|---|
| **Azure AD sign-in logs** | Spray and guessing patterns: many users with one password, failure code 50126, sign-ins from Tor or VPN exits with rotating IPs, legacy or IMAP authentication, and new sign-ins from unfamiliar ASNs. |
| **Azure AD audit logs** | New MFA method registered (`User registered security info`), mailbox or folder permission changes (`Add-MailboxPermission` / `Add-MailboxFolderPermission` in the unified audit log), and app consent. |
| **Windows Security** | 4625 bursts (spray), 4624 Type 10 (RDP), 1102 (log cleared), 4698 (scheduled task created), 4662 / 4688 for ntdsutil, and 5145 on SYSVOL `Groups.xml` (GPP read). |
| **Sysmon** | EID 1 for `ntdsutil … ifm`, `wevtutil cl`, `schtasks /create /xml`, `msedge --headless=new`, `ssh -Nf`, and python.exe from non-standard paths. EID 3 for outbound 445/SMB to the internet (CVE-2023-23397) and SSH egress. EID 11 for `.lnk` in Startup and new `.zip` files in staging. EID 13 for Run key writes. EID 7 for DLL loads from user-writable paths. EID 22 for DNS queries to webhook.site, mocky.io, pipedream.net, and the other listed services. |
