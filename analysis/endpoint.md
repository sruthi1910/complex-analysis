# Endpoint Analysis: logs/windows/

- **Source:** Windows Security, Sysmon, AD FS and WID SQL audit events
- **Analyst:** endpoint-analyst agent
- **Scope:** `logs/windows/WindowsEvents.json`

## Summary

On 2021-08-02 between 13:05:32 and 13:13:11 UTC, `SIMULANDLABS\wardog` (SID ending `-500`, the built-in Administrator) stole AD FS keys, which sets up a Golden SAML attack. wardog:

- read the encrypted AD FS configuration, which holds the token-signing certificate, from the local AD FS database (WID) on ADFS01;
- read the AD FS DKM master key from Active Directory on DC01 three times.

There is no Sysmon Event ID 1 (process creation) telemetry, so the exact tool and command line are unknown. The hard evidence is:

- two WID SQL / Sysmon events on ADFS01;
- five DC01 4662 events tied to wardog's logon IDs.

## 1. Files examined

| File | Format | Records | Time range (UTC) |
|---|---|---|---|
| `logs/windows/WindowsEvents.json` | JSON Lines (one object per line, despite the `.json` extension), exported from Azure Log Analytics / Sentinel. Contains `SecurityEvent` and `Event` tables plus one record with a minimal schema. | 38 (lines 1–38) | 2021-08-02T13:05:32.77Z to 13:32:54.28Z (about 27 min) |

### Event counts

**DC01.simulandlabs.com**

- 4624 ×24
- 4662 ×5

**ADFS01.simulandlabs.com**

- 4624 ×4
- AD FS Auditing 412 ×1 and 501 ×1
- MSSQL$MICROSOFT##WID audit 33205 ×1 (Application log)
- Sysmon 18 (Pipe Connected) ×1
- WFP 5156 ×1

The records are not in time order in the file. They were sorted by time for this analysis.

**Not present:** Sysmon 1/3/11/13, 4688, 4672, 4625, 4648, 4768/4769, 7045/4697, 4698, AD FS 1200/1202.

## 2. Timeline (UTC, 2021-08-02)

**Hosts and IPs**

- ADFS01 is 192.168.2.5. This comes from `WorkstationName=ADFS01` with `IpAddress=192.168.2.5` on lines 7 and 31.
- DC01 is probably 192.168.2.4 and fe80::1d35:28c0:59d6:6862. This is inferred.

| Time | Host | EID | Evidence (line) | Assessment |
|---|---|---|---|---|
| 13:05:32.765Z | ADFS01 | Sysmon 18 | `powershell.exe` (PID 5692, ProcessGuid `{9acedb82-ccd4-6107-22de-030000000600}`) connects to pipe `\MICROSOFT##WID\tsql\query`. Sysmon user is NT AUTHORITY\SYSTEM. (line 16) | **Suspicious, high.** PowerShell connects straight to the AD FS database pipe. |
| 13:05:32.797Z (logged 13:05:33.483Z) | ADFS01 | 33205 (SQL audit, SELECT) | `session_server_principal_name: SIMULANDLABS\wardog`. The SID decodes to S-1-5-21-2490359158-13971675-3780420524-500. Database `AdfsConfigurationV4`. Statement: `SELECT ServiceSettingsData from IdentityServerPolicy.ServiceSettings` (line 13) | **Malicious, high.** Dump of the AD FS configuration, including the encrypted token-signing and token-decryption certificates. Matches the AADInternals `Export-AADIntADFSCertificates` / ADFSDump pattern. |
| 13:06:38.33Z / .337Z | DC01 | 4624 type 3, Kerberos | wardog from 192.168.2.5:53085/53091. LogonIds 0x8f0cd568, 0x8f0cd582 (lines 3–4) | Admin network logons from ADFS01. |
| 13:06:39.587Z / 13:06:40.033Z | DC01 | 4624 type 3, Kerberos | adfsadmin (S-1-5-21-...-1103) from 192.168.2.5. LogonIds 0x8f0ce93e, 0x8f0ce99e (lines 5–6) | Context. |
| 13:08:45.653Z | DC01 | 4624 type 3, **NTLM V1** | pgustavo (S-1-5-21-...-1105). Workstation ADFS01, 192.168.2.5:53115. LogonId 0x8f0de3f2 (line 7) | **Anomalous, medium.** NTLMv1 logon from the AD FS server. |
| 13:09:19.323Z | ADFS01 | 5156 | System (PID 4). fe80::a405:857d:204:efa5:53121 to the same address on TCP/80, inbound (line 17) | Probably benign: local HTTP.sys loopback. |
| 13:09:20.04Z | ADFS01 | AD FS 412 / 501 | Token validated (SecureConversation). Claims: name `SIMULANDLABS\adfsadmin`, primarysid -1103 (lines 1–2) | **Medium.** adfsadmin authenticated to the AD FS service inside the attack window. |
| **13:11:39.767Z** | DC01 | 4624 type 3, Kerberos | wardog from 192.168.2.5:53140, **LogonId 0x8f0f2cd7** (line 9) | Attacker session. |
| **13:11:39.77Z** | DC01 | **4662** ×2 | SubjectLogonId 0x8f0f2cd7. ObjectType `{5cb41ed0-0e4c-11d0-a286-00aa003049e2}` is the contact class. Object `{9736f74f-fd37-4b02-80e8-8120a72ad6c2}`. AccessMask 0x10 (Read Property). Properties include `{8d3bca50-1d7e-11d0-a081-00aa006c33ed}`, which is **thumbnailPhoto**. (lines 14–15) | **Malicious, high.** DKM master key read. The key is stored in the thumbnailPhoto attribute of a contact object under CN=ADFS,CN=Microsoft,CN=Program Data. |
| 13:11:53.573Z / .627Z | DC01 | 4624 | wardog from 192.168.2.5. LogonIds 0x8f0f438e, **0x8f0f43a6** (lines 23–24) | |
| **13:11:53.63Z** | DC01 | **4662** | SubjectLogonId 0x8f0f43a6. Same object, thumbnailPhoto read (line 20) | **High.** Second DKM read. |
| 13:12:55.12Z | DC01 | 4624 | adfsadmin from 192.168.2.5, LogonId 0x8f102237 (line 26) | Context. |
| 13:13:10.997Z | DC01 | 4624 | wardog from 192.168.2.5, **LogonId 0x8f105095** (line 27) | |
| **13:13:11Z / 13:13:11.003Z** | DC01 | **4662** ×2 | SubjectLogonId 0x8f105095. Same object. Line 22 reads every attribute of the object, including thumbnailPhoto (lines 21–22) | **High.** Third DKM read; the full object was dumped. |
| 13:13:29.373Z | DC01 | 4624 NTLM V1 | pgustavo from ADFS01, 192.168.2.5:53163, LogonId 0x8f107008 (line 31) | **Medium.** Same NTLMv1 anomaly as 13:08:45. |
| 13:15:30.443Z | DC01 | 4624 | wardog from 192.168.2.5, LogonId 0x8f1148dd (line 33) | Last wardog activity in the data. |
| 13:23:47.457Z / 13:24:11.643Z | DC01 | 4624 | `MSOL_2826475d0356` (S-1-5-21-...-1118) from fe80::1d35:28c0:59d6:6862. LogonIds 0x8f15ea51, 0x8f17c70d (lines 18–19) | Probably benign: Azure AD Connect sync account. **Confirms hybrid identity.** |
| 13:32:54.223Z | DC01 | 4624 type 3, Advapi/Negotiate | cjones logged on by `C:\Program Files\Azure Advanced Threat Protection Sensor\2.156.14310.28897\Microsoft.Tri.Sensor.exe` (PID 0xaa4) (line 34) | Benign: Defender for Identity (MDI) sensor service account. |
| 13:32:54.267–.28Z | ADFS01 | 4624 ×4 | cjones from 192.168.2.4. LogonIds 0x51296bb8, 0x51296c0c, 0x51296c2d, 0x51296c3f (lines 35–38) | Benign: MDI sensor querying ADFS01 from DC01. |

## 3. MITRE ATT&CK mapping

| Technique | Evidence | Confidence |
|---|---|---|
| T1552.004 Unsecured Credentials: Private Keys; T1555 Credentials from Password Stores | WID dump of ServiceSettingsData (line 13); Sysmon 18 (line 16); DKM thumbnailPhoto reads (lines 14, 15, 20, 21, 22) | High |
| T1606.002 Forge Web Credentials: SAML Tokens (Golden SAML) | Likely objective: stolen certificate plus DKM key allows token forgery. Forging happens off-host, so it must be confirmed in the cloud logs. | Medium (inferred) |
| T1059.001 PowerShell | powershell.exe is the WID client (line 16) | High |
| T1087.002 / T1018 / T1069 Domain discovery via LDAP | Full-attribute 4662 read (line 22) | Medium |
| T1078.002 Valid Accounts: Domain Accounts | wardog (RID 500) used from the AD FS server. The logs cannot show whether the account was compromised or this is red-team activity. | High that the account was used |
| T1550.002 / T1021 (possible) | pgustavo NTLMv1 network logons from ADFS01 | Low–Medium |

## 4. Entities for cross-source correlation

### Users

- Domain: NetBIOS `SIMULANDLABS`, DNS `SIMULANDLABS.COM` / simulandlabs.com.
- Domain SID: `S-1-5-21-2490359158-13971675-3780420524`. Use it to match `onPremisesSecurityIdentifier` in Azure AD.
- No UPNs or email addresses appear in these logs. Any `user@simulandlabs.com` form is inferred.

| User | SID | Forms seen | Notes |
|---|---|---|---|
| wardog | S-1-5-21-2490359158-13971675-3780420524-500 | `SIMULANDLABS\wardog`, `SIMULANDLABS.COM\wardog`, SQL hex SID `01050000000000051500000076dd6f94db30d500aca354e1f4010000` | Probable UPN `wardog@simulandlabs.com` (unverified). RID 500 accounts are normally excluded from AAD Connect sync. |
| adfsadmin | ...-1103 | `SIMULANDLABS\adfsadmin`, `SIMULANDLABS.COM\adfsadmin` | |
| pgustavo | ...-1105 | `SIMULANDLABS\pgustavo` | NTLMv1 logons from ADFS01 |
| cjones | ...-1106 | `SIMULANDLABS\cjones`, `SIMULANDLABS.COM\cjones` | MDI service account |
| MSOL_2826475d0356 | ...-1118 | `SIMULANDLABS.COM\MSOL_2826475d0356` | AAD Connect connector account. Pairs with the `Sync_<host>_...` account in the AAD audit logs. |

### Hosts and IPs

All IPs in these logs are internal; there are no external IPs.

- **ADFS01.simulandlabs.com:**
  - 192.168.2.5 and fe80::a405:857d:204:efa5
  - Azure VM `/subscriptions/0000.../resourcegroups/azhybrid/providers/microsoft.compute/virtualmachines/adfs01`
- **DC01.simulandlabs.com:** 192.168.2.4 and fe80::1d35:28c0:59d6:6862 (inferred)

### DC01 logon IDs tied to the DKM reads

| LogonId | Lines |
|---|---|
| 0x8f0f2cd7 | 9, 14, 15 |
| 0x8f0f43a6 | 24, 20 |
| 0x8f105095 | 27, 21, 22 |

**Other wardog logon IDs:** 0x8f0cd568, 0x8f0cd582, 0x8f0f438e, 0x8f1148dd.
**wardog LogonGuid:** `bd2dda1b-862a-504f-2260-d9d2ed316e26`.

### Other artifacts

- DKM contact object GUID: `9736f74f-fd37-4b02-80e8-8120a72ad6c2`
- WID SQL `sequence_group_id`: `8CD5F561-0EC9-437F-9E50-D83756A1C214`
- Sysmon ProcessGuid `{9acedb82-ccd4-6107-22de-030000000600}`, PID 5692

### Time windows

- **Key theft:** 13:05:30–13:13:30Z
- **Cloud follow-up:** 13:05Z onward. Any federated Azure AD sign-in after this point could use a forged token.

## 5. Severity, confidence, and what was ruled out

- **Critical, high confidence:** wardog stole the AD FS token-signing certificate and DKM key. This compromises federated identity completely: any federated user can be impersonated in the cloud, and the forged token can claim MFA was done.
- **Medium, medium confidence:** adfsadmin authenticated to AD FS (412/501) and made Kerberos logons from ADFS01 inside the attack window. This could be admin tooling used during the theft.
- **Medium, low–medium confidence:** pgustavo made NTLMv1 logons from ADFS01 at 13:08:45 and 13:13:29. NTLMv1 is weak and deprecated, and the timing lines up with the attack phases.

**Benign or ruled out**

- **cjones logons** (lines 8, 10–12, 25, 28–30, 32, 34–38): the MDI sensor account resolving entities. Line 34 shows Microsoft.Tri.Sensor.exe.
- **MSOL_ logons:** routine AAD Connect sync.
- **5156 (line 17):** local System loopback to port 80.
- **Event 501 Activity text** "Desktop Window Manager is experiencing heavy resource contention": the export mislabeled it. The event is actually AD FS Auditing (claims).

**Not observed, because the event types are missing:** persistence (registry, scheduled tasks, services), lateral movement through PsExec, WMI or services, brute force (no 4625), privilege escalation (no 4672), encoded PowerShell. These were not checked and found clean; the data needed to check them is absent.

## 6. Gaps and questions for the cloud logs

### Missing telemetry

- No Sysmon 1 or 4688, so the PowerShell command line, parent process, hashes and tool name are unknown.
- No Sysmon 3, so there is no network context for the LDAP reads.
- No 4672.
- No ADFS01 security-log entry for wardog's logon, so how wardog got onto ADFS01 is unknown (no type 10 or 2 logon).
- No AD FS 1200/1202 token-issuance events.
- The dataset covers only about 27 minutes.

### Parsing notes

- The file is NDJSON with mixed schemas; line 17 has no Type or Tenant fields.
- Records are out of time order.
- The Activity text on event 501 is mislabeled.
- The 4662 Properties field is a raw GUID list. The GUIDs were resolved by hand: contact class `5cb41ed0...`, thumbnailPhoto `8d3bca50...`.

### Questions for the Azure AD logs

1. Are there federated (SAML/WS-Fed) sign-ins after 13:05Z with no matching AD FS 1200/1202 issuance? That is the Golden SAML signature. Look for MFA "satisfied by claim in the token", unusual IPs, and admin targets.
2. Which UPNs are federated? Are wardog, adfsadmin, pgustavo or cjones synced? Match `onPremisesSecurityIdentifier` against the SIDs above.
3. Are there post-theft audit events such as:
   - federation settings changes;
   - new service principal credentials;
   - app consent;
   - role assignments;
   - mailbox or Graph access?
4. Does any cloud sign-in come from ADFS01's public IP (unknown here) or from an external attacker IP?
5. Does pgustavo's NTLMv1 activity have a cloud counterpart?

### On-prem next steps

- ADFS01 Sysmon 1 / 4688 and PowerShell 4104 for 13:00–13:20Z.
- ADFS01 4624 / 4672 events for wardog.
- DC01 4769 events for wardog and adfsadmin.
- MDI alerts raised around 13:11–13:33Z.
