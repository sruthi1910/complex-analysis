# Checkpoint: Phase 1 (Endpoint + Cloud Correlation)

**Checkpoint date:** 2026-10-02
**Activity date:** 2021-08-02. All times are UTC.
**Sources so far:** `endpoint.md` (Windows Security, Sysmon, AD FS, WID audit), `cloud.md` (Azure AD audit, OfficeActivity), `correlation.md`, `verify-local.md` (an external review whose valid points are now folded into `correlation.md`).
**Environment:** hybrid identity tenant `simulandlabs.com` (Microsoft SimuLand lab). Hosts: ADFS01 (192.168.2.5) and DC01 (192.168.2.4, inferred).

## 1. Current understanding of the attack

This looks like a two-phase hybrid identity attack that fits the SimuLand Golden SAML scenario:

1. **On-prem credential theft (13:05–13:13).** `SIMULANDLABS\wardog` (built-in Administrator, RID 500), working from ADFS01, takes:
   - the encrypted AD FS token-signing configuration from the WID database;
   - the DKM master key from Active Directory on DC01.

   Together these let someone forge SAML tokens for any federated user.
2. **Pivot (13:15–13:25, not observed).** Our working theory is that a SAML token was forged for `pgustavo@simulandlabs.com` and used to sign in to Azure AD. Neither dataset covers this window.
3. **Cloud backdoor and collection (13:25–13:32).** Acting as pgustavo, through scripted PowerShell, the attacker:
   - gives SimuLandApp Graph `Mail.ReadWrite` with tenant-wide (AllPrincipals) consent;
   - adds a new client secret, `SimuLandCreds`;
   - reads pgustavo's Inbox through Graph.

**Apparent objective:** lasting access to mail across the tenant. The app and its secret do not depend on the AD FS keys or on pgustavo's password. The 7-message read looks like a check that the access works.

**Initial access:** unknown. The data starts at 13:05 with wardog already active on ADFS01. We are assuming a breach happened before that point.

## 2. Confirmed findings with evidence

| # | Finding | Evidence | ATT&CK |
|---|---|---|---|
| F1 | wardog dumped the AD FS token-signing configuration on ADFS01 | Sysmon 18 at 13:05:32.765: `powershell.exe` (PID 5692) connects to `\MICROSOFT##WID\tsql\query`. WID audit 33205 at 13:05:32.797: wardog runs `SELECT ServiceSettingsData FROM IdentityServerPolicy.ServiceSettings` | T1552.004 |
| F2 | wardog read the DKM master key from AD three times | 4662 on DC01 for the DKM contact object's `thumbnailPhoto`: at 13:11:39 (×2, LogonId 0x8f0f2cd7), at 13:11:53 (0x8f0f43a6), and at 13:13:11 (×2, 0x8f105095, all attributes). The logon IDs match wardog logons from ADFS01 | T1552.004 |
| F3 | SimuLandApp was changed to request Graph Mail.ReadWrite | AuditLogs 13:25:12.246, *Update application*, initiated by pgustavo | T1098.003 |
| F4 | Tenant-wide delegated consent was granted | AuditLogs 13:27:20.017, *Add delegated permission grant*, `User.Read Mail.ReadWrite`, ConsentType AllPrincipals | T1098.003 |
| F5 | A backdoor client secret was added | AuditLogs 13:29:25.983, new credential `SimuLandCreds` (KeyId `59eaeebc-…`) on an app that had no credentials before | T1098.001 |
| F6 | pgustavo's mailbox was read through Graph | OfficeActivity MailItemsAccessed at 13:32:07: Inbox, 7 messages, Graph REST, ClientAppId `5a95e683-…`, client IP `1.2.3.4` (a placeholder). The access window runs to about 13:41 | T1114.002, T1550.001 |
| F7 | The cloud activity was scripted | User agent `WindowsPowerShell/5.1.17763.1971` on the cloud events | — |
| F8 | The environment uses hybrid identity | `MSOL_2826475d0356` (Azure AD Connect sync) logons on DC01 at 13:23:47 and 13:24:11 | — |
| F9 | pgustavo is the only identity in both sources, and no IP appears in both | Endpoint: two NTLMv1 logons to DC01 from ADFS01 (13:08:45, 13:13:29), SID `…-1105`. Cloud: pgustavo started every malicious change (object `aead923d-…`). The match is on **name only**, because the SIDs come from different domain identifiers. Endpoint IPs are internal; cloud IPs are null or a placeholder | — |

**Caveat on F1/F2:** that the material was *extracted* is certain. That the extraction was *malicious* rests on context. A legitimate AD FS backup, such as the Rapid Restore tool run from PowerShell, would look much the same in these logs.

## 3. Hypotheses and confidence levels

| # | Hypothesis | Confidence | For | Against / open |
|---|---|---|---|---|
| H1 | wardog's extraction was malicious, not a legitimate AD FS backup | **High** | Followed within minutes by the cloud backdoor; repeated DKM reads | No process telemetry to identify the tool |
| H2 | The cloud activity is malicious, not routine app maintenance | **High** | AllPrincipals consent, a brand-new secret, an immediate mailbox read, a PowerShell user agent | — |
| H3 | The on-prem and cloud phases are one campaign | **Medium** | Strict time order (13:13 → 13:25); same tenant; hybrid setup confirmed; a textbook SimuLand sequence | The only direct link is the name "pgustavo" |
| H4 | ClientAppId `5a95e683-…` is SimuLandApp | **Medium** | Timing and scope fit | The audit records carry no appId |
| H5 | adfsadmin's AD FS 412/501 and Kerberos activity during the window is part of the attacker's tooling | **Medium** | Falls inside the attack window | Could be normal admin or service activity |
| H6 | **Golden SAML (a forged token) was how the attacker signed in as pgustavo** | **Low** | Key theft just before; wardog never appears in the cloud; federation is in place | No sign-in logs and no AD FS 1200/1202 events. pgustavo's NTLMv1 logons from ADFS01 leave room for real credentials or a genuine session |
| H6-alt | The attacker used pgustavo's real credentials (or pgustavo had a real federated session) | **Low** (undecided against H6) | The pgustavo NTLMv1 logons from ADFS01 at 13:08 and 13:13 | Does not explain why the AD FS keys were stolen |
| H7 | The cloud PowerShell ran on ADFS01 | **Low** | User agent build 17763 (Server 2019); PowerShell is already in use on ADFS01 | ADFS01's OS build is not confirmed; no network or DNS logs |
| H8 | pgustavo holds a directory role that allows tenant-wide consent | **Unknown** | Consent succeeded | Audit `roles=[]` is inconclusive. If pgustavo is not an admin, the story needs revising |

**Key open question:** did pgustavo reach the cloud with a **forged token** (H6) or with **real credentials** (H6-alt)?

## 4. What we need to investigate next

Ordered by how much each item would resolve.

1. **Azure AD SigninLogs for pgustavo, 13:00–13:45** (interactive and non-interactive). This decides H6 against H6-alt. Check:
   - the authentication method (federated or password);
   - the source IP and user agent;
   - the MFA detail. "MFA requirement satisfied by claim in the token" points to Golden SAML.
2. **AD FS 1200/1202 (and 1203/1210) on ADFS01.** An Azure AD federated sign-in with *no* matching 1200 event shows the token was forged. These events would also explain the pgustavo NTLMv1 logons.
3. **ADFS01 process telemetry: Sysmon 1, Security 4688, PowerShell 4103/4104.** This would:
   - identify the extraction tool (AADInternals / ADFSDump or Rapid Restore), which settles the H1 caveat;
   - show whether the cloud PowerShell ran there (H7);
   - give the process chain back to initial access.
4. **ADFS01 network and DNS logs: Sysmon 3/22, proxy or firewall.** Look for traffic to `login.microsoftonline.com` and `graph.microsoft.com`, and find ADFS01's public egress IP.
5. **AADServicePrincipalSignInLogs for SimuLandApp.** These show whether `SimuLandCreds` has been used, which tells us how far the persistence goes.
6. **Azure AD directory data:**
   - pgustavo's roles (H8);
   - `onPremisesSecurityIdentifier` for `aead923d-…` against `…-1105` (to confirm the identities are the same);
   - SimuLandApp's appId compared with `5a95e683-…` (H4).
7. **Unified Audit Log beyond MailItemsAccessed.** Look for other mailboxes reached through SimuLandApp, mail sent, forwarding rules, and any exfiltration.
8. **Initial access:**
   - ADFS01 4624/4672/4648 for wardog;
   - DC01 4768/4769;
   - a wider time window before 13:05.
9. **Unsanitised cloud exports.** Real IPs instead of `1.2.3.4`, and the real tenant ID.
10. **Defender for Identity alerts, 13:05–13:35.** Check whether the DKM reads were detected.

### Containment to consider now (whichever way the open questions fall)

- Remove the `SimuLandCreds` secret and revoke the AllPrincipals grant on SimuLandApp.
- Revoke pgustavo's sessions and reset the credentials.
- Rotate the AD FS token-signing and token-decryption certificates twice, so the old ones are no longer trusted.
- Reset the wardog / built-in Administrator account.
