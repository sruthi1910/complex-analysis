# Investigation Summary: simulandlabs.com hybrid identity compromise (AD FS key theft and SimuLandApp mail backdoor)

**Data:** OTRF/SimuLand lab dataset (Microsoft SimuLand Golden SAML scenario), activity on 2021-08-02, all times UTC. **Sources:** `correlation.md`, `checkpoint-phase1.md`.

## Executive Summary

The endpoint and cloud logs fit a two-phase hybrid identity attack:

- **On-prem (13:05–13:13):** `SIMULANDLABS\wardog` (built-in Administrator, RID 500), working from ADFS01, extracted the AD FS token-signing configuration and the DKM master key needed to decrypt it.
- **Cloud (13:25–13:32):** acting as `pgustavo@simulandlabs.com` through scripted PowerShell, the attacker gave SimuLandApp tenant-wide Graph `Mail.ReadWrite`, added a backdoor client secret, and read pgustavo's Inbox.

The step linking the phases (13:15–13:25) is **not observed** in either dataset. The phases being one campaign is **medium** confidence. That Golden SAML (a forged token) was the mechanism is **low** confidence: the attacker may instead have used pgustavo's real credentials. **Key open question: forged token or real credentials?** Initial access is unknown.

## Timeline

| Time (UTC) | Event |
|---|---|
| 13:05:32 | PowerShell on ADFS01 connects to the WID database; wardog dumps `ServiceSettingsData` (Sysmon 18, WID audit 33205) |
| 13:08:45, 13:13:29 | pgustavo NTLMv1 network logons to DC01 from ADFS01 (unexplained) |
| 13:11:39–13:13:11 | wardog reads the DKM key (`thumbnailPhoto`) on DC01 three times (4662) |
| 13:15–13:25 | Blind spot: inferred sign-in to Azure AD as pgustavo |
| 13:25:12 | SimuLandApp updated to request Graph `Mail.ReadWrite` |
| 13:27:20 | Delegated grant `User.Read Mail.ReadWrite`, ConsentType AllPrincipals |
| 13:29:25 | Client secret `SimuLandCreds` added (KeyId `59eaeebc-…`) |
| 13:32:07 (to ~13:41) | MailItemsAccessed: pgustavo's Inbox, 7 messages, Graph REST, ClientAppId `5a95e683-…` |

## ATT&CK Techniques (with confidence levels)

| Technique | Evidence | Confidence |
|---|---|---|
| T1552.004 Private Keys (and T1555) | WID dump and DKM reads | **High** that it was extracted; malicious rather than an AD FS backup (e.g. Rapid Restore) is **High** but rests on context |
| T1606.002 Golden SAML | Inferred from key theft followed by cloud activity | **Low** (undecided against real credentials) |
| T1098.003 Additional Cloud Roles | Mail.ReadWrite added; AllPrincipals consent | **High** |
| T1098.001 Additional Cloud Credentials | `SimuLandCreds` secret | **High** |
| T1114.002 Remote Email Collection | MailItemsAccessed, 7 messages | **High** |
| T1550.001 Application Access Token | Graph read by ClientAppId `5a95e683-…` | Mail read **High**; that the app is SimuLandApp **Medium** |

## Indicators of Compromise

- **Accounts:** `SIMULANDLABS\wardog` (RID 500); `pgustavo@simulandlabs.com` (on-prem SID `…-1105`, cloud object `aead923d-…`; matched on name only).
- **Hosts:** ADFS01 (192.168.2.5); DC01 (192.168.2.4, inferred).
- **Cloud:** SimuLandApp; secret `SimuLandCreds` (KeyId `59eaeebc-…`); ClientAppId `5a95e683-…`; user agent `WindowsPowerShell/5.1.17763.1971`.
- **Not usable:** IP `1.2.3.4` is a placeholder. No IP appears in both sources.

## Impact

- The extracted material is everything needed to forge SAML tokens for any federated user in the tenant.
- SimuLandApp holds tenant-wide `Mail.ReadWrite` consent and its own secret, a backdoor that survives a pgustavo password reset and AD FS certificate rotation.
- Confirmed data access: 7 messages in pgustavo's Inbox. Access to other mailboxes and any use of `SimuLandCreds` are **unknown**.

## Recommendations

**Contain now:**

- Remove `SimuLandCreds` and revoke the AllPrincipals grant on SimuLandApp.
- Revoke pgustavo's sessions and reset the credentials.
- Rotate the AD FS token-signing and token-decryption certificates twice.
- Reset the wardog / built-in Administrator account.

**Investigate next (in order):**

1. Azure AD SigninLogs for pgustavo, 13:00–13:45, and AD FS 1200/1202 on ADFS01, to answer forged token vs real credentials.
2. ADFS01 process and network telemetry (Sysmon 1/3/22, 4688, PowerShell 4103/4104).
3. Service principal sign-ins for SimuLandApp, and the Unified Audit Log for other mailboxes.
4. Directory data: pgustavo's roles, `onPremisesSecurityIdentifier`, SimuLandApp's appId.
5. Initial access: wardog logons on ADFS01 and a wider time window before 13:05.
