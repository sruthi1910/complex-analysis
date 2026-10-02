# Correlation: Endpoint + Cloud

**Inputs:** `analysis/endpoint.md` (Windows Security, Sysmon, AD FS and WID logs) and `analysis/cloud.md` (Azure AD audit and Office activity logs).
**Date of activity:** 2021-08-02. All times are UTC.

## Summary

The two datasets fit one hybrid identity attack in two phases:

1. **On-prem (13:05–13:15):** `SIMULANDLABS\wardog`, the built-in Administrator (RID 500), steals what is needed to forge AD FS tokens. That is the encrypted token-signing configuration from the AD FS database on ADFS01, and the DKM decryption key from Active Directory on DC01.
2. **Cloud (13:25–13:32):** the identity `pgustavo@simulandlabs.com`, using scripted PowerShell, does four things:
   - grants a tenant app Mail.ReadWrite;
   - gives it admin consent for all users;
   - adds a backdoor client secret;
   - reads pgustavo's mailbox through Microsoft Graph.

The step that links the phases is a forged SAML sign-in as pgustavo (Golden SAML). That step is **inferred, not observed**: no Azure AD sign-in logs or AD FS token-issuance logs were provided. The time order, the matching tenant, the hybrid setup confirmed by Azure AD Connect sync, and the exact fit with the Golden SAML scenario in Microsoft's SimuLand attack-simulation lab (which this tenant, `simulandlabs.com`, comes from) make it likely that the two phases are one campaign (medium confidence). That Golden SAML was the *mechanism* is less certain (low confidence): the attacker may instead have used pgustavo's real credentials (see section 2). No single data point proves either.

## 1. Timeline

| Time (UTC) | Source | Host / scope | Event | Phase |
|---|---|---|---|---|
| 13:05:32.765 | Endpoint (Sysmon 18) | ADFS01 | `powershell.exe` (PID 5692) connects to the AD FS database pipe `\MICROSOFT##WID\tsql\query` | Credential access |
| 13:05:32.797 | Endpoint (WID audit 33205) | ADFS01 | `SIMULANDLABS\wardog` runs `SELECT ServiceSettingsData FROM IdentityServerPolicy.ServiceSettings`, which dumps the encrypted token-signing certificate | Credential access |
| 13:06:38–13:06:40 | Endpoint (4624) | DC01 | wardog and adfsadmin make Kerberos network logons from ADFS01 (192.168.2.5) | Discovery / staging |
| 13:08:45.653 | Endpoint (4624, NTLM V1) | DC01 | **pgustavo** network logon from ADFS01 | ⚠ Unexplained |
| 13:09:20.04 | Endpoint (AD FS 412/501) | ADFS01 | adfsadmin token validated by the AD FS service | Possible admin tooling |
| 13:11:39.77 | Endpoint (4662 ×2) | DC01 | wardog (LogonId 0x8f0f2cd7) reads `thumbnailPhoto` on the DKM contact object, which is where the DKM master key is stored | Credential access |
| 13:11:53.63 | Endpoint (4662) | DC01 | wardog (0x8f0f43a6), second DKM key read | Credential access |
| 13:13:11.00 | Endpoint (4662 ×2) | DC01 | wardog (0x8f105095), third DKM read, this time every attribute of the object | Credential access |
| 13:13:29.373 | Endpoint (4624, NTLM V1) | DC01 | **pgustavo** network logon from ADFS01 | ⚠ Unexplained |
| 13:15:30.443 | Endpoint (4624) | DC01 | Last wardog logon in the data | |
| *13:15 – 13:25* | *No log in either source* | *Off-host / Azure AD* | *Expected step: SAML token forged for pgustavo and used to sign in to Azure AD. Neither dataset records it.* | *Pivot (inferred)* |
| 13:23:47 / 13:24:11 | Endpoint (4624) | DC01 | `MSOL_2826475d0356` logons. This is Azure AD Connect sync: routine, but it confirms the hybrid identity setup | Benign |
| **13:25:12.246** | Cloud (AuditLogs) | Azure AD | pgustavo: *Update application*. SimuLandApp now requests Graph **Mail.ReadWrite** | Persistence / privilege |
| **13:27:20.017** | Cloud (AuditLogs) | Azure AD | pgustavo: *Add delegated permission grant*, `User.Read Mail.ReadWrite`, ConsentType **AllPrincipals** | Persistence / privilege |
| **13:29:25.983** | Cloud (AuditLogs) | Azure AD | pgustavo: new client secret **SimuLandCreds** (KeyId `59eaeebc-…`) on an app that had no credentials | Persistence |
| **13:32:07** | Cloud (OfficeActivity) | Exchange Online | **MailItemsAccessed**: pgustavo's Inbox, 7 messages, through Graph REST, ClientAppId `5a95e683-…` | Collection |
| 13:32:54 | Endpoint (4624) | DC01 → ADFS01 | cjones logons by the Defender for Identity (MDI) sensor | Benign |
| 13:41:16 | Cloud (OfficeActivity) | Exchange Online | Start_Time / ElevationTime on the same mail-access record. It conflicts with TimeGenerated, so treat 13:32–13:41 as the access window. | Collection |

**Timing**

- The key theft ends at 13:13:11.
- The first cloud change comes **about 12 minutes later**, at 13:25:12.
- The whole cloud phase takes **7 minutes**, from 13:25 to 13:32.
- The 10-minute window from 13:15 to 13:25 is where the forged sign-in would happen. It is a blind spot in both datasets.

## 2. User correlation

| User | Endpoint activity | Cloud activity | In both? |
|---|---|---|---|
| **pgustavo** | 2 NTLMv1 network logons to DC01 from ADFS01 (13:08:45, 13:13:29). SID `S-1-5-21-2490359158-13971675-3780420524-1105` | Initiator of all 3 audit events. Mailbox owner and accessor in MailItemsAccessed. Object ID `aead923d-…`. Mailbox SID `S-1-5-21-1825954961-…-26087451` | **Yes** |
| wardog (RID 500) | Did the WID dump and all 5 DKM reads. Many Kerberos logons from ADFS01 | None | No, endpoint only |
| adfsadmin | Kerberos logons from ADFS01; AD FS 412/501 token validation inside the attack window | None | No, endpoint only |
| cjones | MDI sensor service account (benign) | None | No |
| MSOL_2826475d0356 | Azure AD Connect sync (benign) | No matching `Sync_*` account appears in the cloud audit data | No |

**pgustavo is the only user in both sources.** Some notes on that match:

- **It is a name match only.** The on-prem SID and the Exchange Online mailbox SID come from different domain identifiers (`2490359158…` vs `1825954961…`), so the records cannot be joined on SID. The cloud SID is most likely an Exchange Online-specific SID. To confirm the identities are the same, compare Azure AD `onPremisesSecurityIdentifier` for object `aead923d-…` with `…-1105`.
- **Endpoint:** pgustavo is a *target or bystander*. The account only shows network logons to the DC from the AD FS server. It does nothing malicious on-prem.
- **Cloud:** pgustavo is the *acting identity* for every malicious change.
- **This is the Golden SAML signature.** The account that steals the keys (wardog) never appears in the cloud. A different, federated account (pgustavo) is impersonated there.

**The pgustavo NTLMv1 logons from ADFS01 have two possible readings:**

- **(a) Benign:** AD FS checking pgustavo's credentials for a real sign-in. A sign-in through forms or WIA on ADFS01 makes the AD FS server authenticate the user against the DC. This reading would weaken the forgery theory. pgustavo may have had a real federated session, or the attacker may have had pgustavo's password.
- **(b) Malicious:** the attacker on ADFS01 testing or using pgustavo's credentials directly.

The data available cannot tell these apart. AD FS 1200/1202 events and Azure AD sign-in logs would.

## 3. IP correlation

**No IP appears in both sources.**

| Source | IPs present |
|---|---|
| Endpoint | Internal only: 192.168.2.5 / fe80::a405:857d:204:efa5 (ADFS01) and 192.168.2.4 / fe80::1d35:28c0:59d6:6862 (DC01, inferred) |
| Cloud | Audit events have `ipAddress=null`. MailItemsAccessed has `1.2.3.4`, which is a placeholder or sanitised value. |

IP cannot link the two phases. The best link besides identity is the **host fingerprint**. The cloud user agent is `WindowsPowerShell/5.1.17763.1971`, i.e. Windows build 17763 (Server 2019 / Win10 1809). ADFS01 is the obvious candidate, because PowerShell is already shown running there in the attack. Nothing in the endpoint data records ADFS01's OS build or any traffic from it to Microsoft cloud endpoints, so this is **unconfirmed**.

## 4. Likely attack chain

### Initial access: unknown

- Neither dataset shows how the attacker got in. The endpoint data begins at 13:05:32 with the attack already in progress as wardog.
- There is no ADFS01 logon event (type 2/10/3) for wardog, so how wardog reached ADFS01 is not visible.
- There are no failed logons (4625), phishing artifacts or exploitation evidence. Those event types are absent from the data, so this does not show there was no such activity.
- **Working assumption:** a domain admin account (wardog, RID 500) was already compromised before 13:05, and the attacker had an interactive or remote session on ADFS01. The SimuLand scenario models this as an "assume breach" starting point.

### Actions on endpoint: credential access on the AD FS farm

1. **13:05:** PowerShell on ADFS01 connects to the AD FS database (Windows Internal Database) and runs a SELECT as wardog. This extracts `ServiceSettingsData`, which contains the encrypted token-signing and token-decryption certificates. This is the AADInternals `Export-AADIntADFSCertificates` / ADFSDump technique. **T1552.004**
2. **13:06–13:15:** repeated Kerberos network logons as wardog from ADFS01 to DC01, i.e. LDAP queries.
3. **13:11–13:13:** three reads of the AD FS DKM contact object's `thumbnailPhoto` attribute on DC01. That attribute holds the master key that decrypts the certificate blob from step 1. The last read pulls every attribute of the object. **T1552.004 / T1555**

**Result:** the attacker holds the decrypted AD FS token-signing private key and can mint SAML tokens for any federated user, including claims that MFA was done.

### Pivot to cloud: forged SAML token (inferred)

4. **About 13:15–13:25:** the attacker forges a SAML token for `pgustavo@simulandlabs.com` off-host and presents it to Azure AD, which trusts the federated domain. Azure AD issues access tokens for Azure AD / Microsoft Graph. **T1606.002 Golden SAML**
   - This is supported by: the key theft just before; the cloud activity just after; the stealing account (wardog) never appearing in the cloud; and hybrid federation confirmed by AAD Connect.
   - It is **not directly observed**. The evidence that would show it (a sign-in log for pgustavo with no matching AD FS 1200 issuance event) is missing.

### Actions in the cloud: app backdoor

5. **13:25:** SimuLandApp is changed to request delegated Graph `Mail.ReadWrite`. **T1098.003**
6. **13:27:** tenant-wide admin consent (AllPrincipals) for `Mail.ReadWrite`, so the app can act on *any* user's mail when that user's token is used. **T1098.003**
7. **13:29:** a new client secret, `SimuLandCreds`, is added. The attacker can now authenticate as the app on their own, which survives a reset of pgustavo's password and rotation of the AD FS certificate. **T1098.001**

### Ultimate objective: email collection

8. **13:32 (to about 13:41):** pgustavo's Inbox (7 messages) is read through Microsoft Graph REST by client app `5a95e683-…`, very likely SimuLandApp, using the newly consented `Mail.ReadWrite`. **T1114.002 Remote Email Collection, T1550.001**

**Overall objective:** long-term access to mail in the tenant. Golden SAML gives the first cloud foothold. The consented app plus its secret is a durable backdoor that does not depend on the AD FS keys. The 7-message Inbox read looks like a test that the access works, not the end goal.

## 5. Confidence assessment

### High confidence

- wardog extracted AD FS token-signing material on ADFS01. The WID SELECT on `ServiceSettingsData` is direct evidence, backed by Sysmon 18.
- wardog read the DKM master key from AD on DC01 three times (4662 on `thumbnailPhoto`, with logon IDs tied to wardog logons from ADFS01).
- Together these give the attacker everything needed to forge SAML tokens for the tenant.
  - The *extraction* is high confidence; that it was *malicious* rests on context. A legitimate AD FS backup (e.g. the AD FS Rapid Restore tool) also exports this configuration and the DKM key. An admin running that tool from PowerShell would look much the same in these logs. The reading is unlikely here because the extraction is followed within minutes by the cloud backdoor, but the endpoint data alone cannot rule it out. Process telemetry (gap 3) would settle it.
- The identity `pgustavo@simulandlabs.com` escalated SimuLandApp's permissions, granted tenant-wide consent, added a client secret, and then read mail through Graph.
- The cloud activity is malicious and scripted, not ordinary app maintenance: AllPrincipals consent, a brand-new secret, immediate mailbox access, and a PowerShell user agent.

### Medium confidence

- **The two phases are one campaign.** Supported by: strict time order (13:13 → 13:25); the same organisation and tenant (`simulandlabs.com`); confirmed hybrid identity; and the textbook SimuLand Golden SAML sequence. The only direct link between the phases is the name "pgustavo".
- **ClientAppId `5a95e683-…` is SimuLandApp.** It fits the timing and the scope, but the audit records carry no appId.
- **adfsadmin's AD FS and Kerberos activity during the window is part of the attacker's tooling.** It could also be normal admin or service behaviour.

### Low confidence / uncertain

- **That Golden SAML was actually used to sign in as pgustavo.** There are no sign-in logs and no AD FS 1200/1202 logs. pgustavo's NTLMv1 logons from ADFS01 leave open the alternatives that the attacker used pgustavo's real credentials, or that pgustavo had a real federated session.
- **That the cloud PowerShell ran on ADFS01.** This rests only on the build 17763 user agent. The OS build is not confirmed, and there are no network or DNS logs from ADFS01.
- **Initial access, and how wardog was compromised:** not observable.
- **Whether pgustavo holds a directory role** that allows tenant-wide consent. Audit `roles=[]` is inconclusive. If pgustavo is *not* an admin, then either the consent was granted some other way or the attacker had a privileged token, and the story needs revising.
- **Use of the `SimuLandCreds` secret after creation:** unknown, because there are no service principal sign-in logs.

## 6. Gaps: logs that would help

Ordered by how much each would resolve.

| # | Missing data | Question it would answer |
|---|---|---|
| 1 | **Azure AD SigninLogs** (interactive and non-interactive) for pgustavo, 13:00–13:45 | How pgustavo authenticated (federated vs password), source IP, user agent, device, MFA detail ("MFA requirement satisfied by claim in the token" is a Golden SAML tell), conditional access result. **This confirms or refutes the pivot.** |
| 2 | **AD FS Admin/Auditing logs, events 1200/1202** (and 1203/1210) on ADFS01 | Whether AD FS actually issued a token for pgustavo. An Azure AD federated sign-in with *no* matching 1200 shows a forged token. It would also explain the pgustavo NTLMv1 logons. |
| 3 | **ADFS01 process telemetry**: Sysmon 1, Security 4688, PowerShell 4103/4104 (13:00–13:45) | The tool and commands used for the WID/DKM extraction (e.g. AADInternals), whether the cloud PowerShell (AzureAD module, Graph calls, `SimuLandCreds`) ran on ADFS01, and the parent process chain back to initial access. |
| 4 | **ADFS01 network telemetry**: Sysmon 3/22, firewall or proxy logs | Connections or DNS lookups to `login.microsoftonline.com` / `graph.microsoft.com` from ADFS01, and its public egress IP to compare with cloud IPs. |
| 5 | **AADServicePrincipalSignInLogs** for SimuLandApp | Whether the `SimuLandCreds` secret was used (client-credentials sign-ins), from where, and when. This is the scope of the persistence. |
| 6 | **Unsanitised IPs and tenant IDs** in the cloud exports | `1.2.3.4` and the zeroed tenant ID prevent IP correlation. |
| 7 | **Azure AD directory data**: pgustavo's role assignments, `onPremisesSecurityIdentifier`, and SimuLandApp's appId | Confirms pgustavo could grant tenant consent, confirms the cloud and on-prem pgustavo are the same identity, and ties ClientAppId `5a95e683-…` to SimuLandApp. |
| 8 | **ADFS01 Security log**: 4624/4672/4648 for wardog; DC01 4768/4769 | How and when wardog got onto ADFS01 (logon type, source host), i.e. the initial access and lateral movement path. |
| 9 | **Wider time window**: hours or days before 13:05 | Initial compromise of wardog, earlier reconnaissance, any earlier key theft. |
| 10 | **Defender for Identity (MDI) alerts** for 13:05–13:35 | MDI detects AD FS DKM key reads and suspicious LDAP. Its alerts may add context or confirm detection coverage. |
| 11 | **Unified Audit Log beyond MailItemsAccessed** | Other mailboxes accessed through SimuLandApp after tenant-wide consent; any mail sent, forwarding rules, or exfiltration. |
