# Cloud Analysis: logs/cloud/

- **Source:** Azure AD audit logs and Office 365 activity
- **Analyst:** cloud-analyst agent
- **Scope:** `logs/cloud/AADAuditEvents.json`, `logs/cloud/OfficeActivityEvents.json`

## Summary

On 2021-08-02, `pgustavo@simulandlabs.com` ran one connected attack chain from Windows PowerShell 5.1 over about 7 minutes:

1. Added Mail.ReadWrite to the app "SimuLandApp".
2. Granted admin consent for the whole tenant.
3. Added a new client secret to the app.
4. Read the user's mailbox through Microsoft Graph.

This matches the SimuLand pattern of Golden SAML, then app credential abuse, then mail collection.

**No Azure AD sign-in logs were provided.** Location, device, MFA, conditional access, impossible travel and failed-then-successful sign-ins therefore cannot be assessed. All anomaly evidence comes from the audit and Office logs.

## 1. Files examined

| File | Format | Records | Time range (UTC) |
|---|---|---|---|
| `logs/cloud/AADAuditEvents.json` | NDJSON, Sentinel `AuditLogs` export with KQL-projected columns | 4 lines, which is **3 unique events**. Lines 1 and 2 share the `Id` `Directory_10065ffb-..._AUMVX_13992832`: one event split by modified property. | 2021-08-02T13:25:12.246Z to 13:29:25.983Z |
| `logs/cloud/OfficeActivityEvents.json` | NDJSON, Sentinel `OfficeActivity` | 1 | TimeGenerated 2021-08-02T13:32:07Z. Start_Time and ElevationTime are 13:41:16Z, which is inconsistent; see Gaps. |

There is no SigninLogs, AADServicePrincipalSignInLogs or AADNonInteractiveUserSignInLogs file.

## 2. Timeline (UTC, 2021-08-02)

All audit events share these values:

| Field | Value |
|---|---|
| Tenant | `00000000-0000-0000-0000-000000000000` (sanitised) |
| Initiator | `pgustavo@simulandlabs.com`, user object ID `aead923d-498b-4f64-a66c-2af91447a8b6` |
| InitiatedBy | `ipAddress=null`, `roles=[]` |
| UserAgent | `Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.17763.1971` |
| LoggedByService | Core Directory |
| Result | success |

The user agent points to Windows PowerShell 5.1 on build 17763, which is Windows Server 2019 or Windows 10 1809. The calls were most likely made with the AzureAD, MSOnline or Graph PowerShell module, or with Invoke-RestMethod.

### T1: 13:25:12.246Z, Update application

- **Record:** AADAuditEvents.json line 3, CorrelationId `ae69aa7a-e9b7-4066-84f2-58582994d8cb`.
- **Target:** application "SimuLandApp", object ID `11b49e19-2326-4be6-93cb-7f37439bbd81`.
- **Change:** RequiredResourceAccess for Microsoft Graph (`00000003-0000-0000-c000-000000000000`).
  - **Before:** `e1fe6dd8-ba31-4d61-89e7-88639da4683d` (User.Read, delegated).
  - **After:** adds `024d486e-b451-40bb-833d-3e66d98c5c73` (**Mail.ReadWrite, delegated**).

### T2: 13:27:20.017Z, Add delegated permission grant

- **Record:** line 4, CorrelationId `630d7f0c-acc4-4596-85ab-7e5d839b4291`.
- **Targets:**
  - Microsoft Graph service principal `401dd906-ea4f-4d41-b762-7e936d222368`
  - client service principal (SimuLandApp's SP) `0d2f5969-011b-460d-ac74-3291d227d49f`
- **Change:**
  - Scope went from "User.Read" to "**User.Read Mail.ReadWrite**".
  - ConsentType = **AllPrincipals**, which is admin consent for every user in the tenant.

### T3: 13:29:25.983Z, Update application (Certificates and secrets management)

- **Record:** lines 1–2, CorrelationId `10065ffb-8199-48bc-8ff5-912cb5b8295a`.
- **Target:** SimuLandApp `11b49e19-...`.
- **Change:** KeyDescription went from `[]` to:
  - KeyIdentifier = `59eaeebc-8a6b-44a6-9f24-7d55e64420c9`
  - KeyType = Password, KeyUsage = Verify
  - DisplayName = `SimuLandCreds`

  This is a **new client secret on an app that had no credentials before**.

### T4: 13:32:07Z, MailItemsAccessed

Record: OfficeActivityEvents.json line 1, OfficeId `699e0b10-1c53-403e-976f-ce0847a92b44`.

| Field | Value |
|---|---|
| Workload | Exchange |
| UserId / MailboxOwnerUPN | `pgustavo@simulandlabs.com` |
| Logon_Type | Owner |
| MailboxOwnerSid = LogonUserSid | `S-1-5-21-1825954961-3338807533-2873504967-26087451` |
| UserKey | `100320015858B802` |
| MailboxGuid | `d0c5f8ae-9ed7-4e46-bfdf-ea1460f5a31b` |
| ClientInfoString | Client=REST |
| AppId | `00000003-0000-0000-c000-000000000000` (Microsoft Graph) |
| **ClientAppId** | **`5a95e683-08ad-424e-a441-1d1aec52c02c`** |
| Client_IPAddress | 1.2.3.4 (placeholder or sanitised) |
| MailAccessType | Bind |
| IsThrottled | False |
| Folder | `\Inbox`, 7 InternetMessageIds |
| ExternalAccess | False |

The mailbox was accessed about 2.7 minutes after the secret was added. Access went through Graph REST using a client application, which fits use of the newly consented Mail.ReadWrite scope.

Sign-in, location, device, MFA and conditional access data are all **unavailable**. That covers device ID, device name, OS, compliance/join state and failure reasons.

## 3. MITRE ATT&CK mapping

| Finding | Technique | Confidence |
|---|---|---|
| T1: app modified to request Mail.ReadWrite | T1098 Account Manipulation; T1098.003 Additional Cloud Roles (app permission escalation) | High |
| T2: tenant-wide admin consent for Mail.ReadWrite | T1098.003; enables T1550.001 Application Access Token | High |
| T3: new client secret "SimuLandCreds" | **T1098.001 Additional Cloud Credentials** | High |
| T4: Graph mailbox read | **T1114.002 Remote Email Collection**; T1550.001 Use of Application Access Token | Medium–High |
| How pgustavo's session was obtained (inferred; not in these logs) | T1606.002 Forge Web Credentials: SAML Tokens (Golden SAML); T1552.004 Private Keys (theft of the AD FS token-signing certificate) | Low–Medium. Inferred from the scenario pattern and the absence of interactive sign-ins. |
| PowerShell tooling | T1059.001 PowerShell, on whichever endpoint made the calls | Medium |

## 4. Entities for cross-source correlation

### Users

- **UPN:** `pgustavo@simulandlabs.com`.
  - The on-prem SAM name is probably `pgustavo`. This is inferred from the UPN and not confirmed.
  - DisplayName is null in the logs.
- **AAD object ID:** `aead923d-498b-4f64-a66c-2af91447a8b6`.
- **SID:** `S-1-5-21-1825954961-3338807533-2873504967-26087451`. The very large RID suggests an Exchange Online / cloud SID rather than the on-prem AD SID. Check it against endpoint 4624/4672 events anyway.

### Apps and service principals

| Entity | ID |
|---|---|
| SimuLandApp object ID | `11b49e19-2326-4be6-93cb-7f37439bbd81` |
| SimuLandApp service principal | `0d2f5969-011b-460d-ac74-3291d227d49f` |
| ClientAppId seen in mail access | `5a95e683-08ad-424e-a441-1d1aec52c02c`. Presumed to be SimuLandApp's appId; this can't be confirmed because the audit logs carry no appId. |
| Secret | KeyId `59eaeebc-8a6b-44a6-9f24-7d55e64420c9`, DisplayName "SimuLandCreds" |
| Microsoft Graph service principal | `401dd906-ea4f-4d41-b762-7e936d222368` |

### Tenant

- `simulandlabs.onmicrosoft.com` / `simulandlabs.com`.
- The tenant ID is zeroed out.
- OfficeTenantId is the literal string `$RestApiTenantId$`.

### IPs

- Only `1.2.3.4` appears, and it looks like a placeholder, so it isn't a reliable join key.
- The audit events have no IP.

### Host fingerprint

PowerShell 5.1.17763.1971. Look for a Windows Server 2019 / build 17763 host in the endpoint data.

### Time windows

- **Core:** 2021-08-02 13:25–13:42 UTC.
- **Precursor (credential or token theft):** about 12:00–13:25 UTC.

## 5. Severity, confidence, and benign explanations

**Overall: high severity, high confidence.** Within 7 minutes, all from scripted PowerShell:

- the app's permissions were escalated;
- admin consent was granted;
- a backdoor secret was added;
- mail was collected.

That is a classic OAuth app persistence and collection pattern.

**Benign explanations considered**

- **A developer configuring their own app.** Plausible for any single event. Three things make it unlikely:
  - the consent covers all users (AllPrincipals) for Mail.ReadWrite;
  - the secret was added to an app that had no prior credentials;
  - the mailbox was read immediately afterwards through Graph.
- **`roles=[]` on the initiator.** This is odd for granting tenant-wide consent. It may just be how the field is populated. Check whether pgustavo actually holds Global Admin, Application Admin or Cloud Application Admin.
- **Logon_Type "Owner".** This does not mean the user read their own mail interactively. It reflects delegated Graph access as that user.

## 6. Gaps and questions for the endpoint logs

### Missing data

- **No sign-in logs at all.** It is impossible to tell how pgustavo authenticated (federated/SAML or password), or to see source IP, MFA, conditional access or device. If AD FS is in use, an AAD sign-in with no matching AD FS 1200/1202 event would indicate a forged SAML token.
- **No AADServicePrincipalSignInLogs.** There is no way to see whether the SimuLandApp secret was used for client-credentials sign-ins.
- **No appId in the audit logs.** ClientAppId `5a95e683-...` cannot be definitively tied to SimuLandApp.

### Data quality

- Audit rows are duplicated (lines 1 and 2).
- The IP, tenant ID and message IDs are sanitised.
- In the Office record, Start_Time and ElevationTime (13:41:16Z) are later than TimeGenerated (13:32:07Z). Treat 13:32–13:41 as the access window.
- OperationName "...secrets management " has a trailing space. Exact-match queries must allow for it.

### What to look for in the endpoint logs

1. **On the AD FS server before 13:25, evidence of token-signing certificate theft:**
   - Sysmon 17/18 named-pipe access to `\\.\pipe\microsoft##wid\tsql\query` by a process other than AD FS;
   - AD FS DKM key reads from AD (Security 4662 on the ADFS container object, thumbnailPhoto attribute) by an unexpected account;
   - logons by the AD FS service account.
2. **Any host where pgustavo or another admin ran PowerShell 13:20–13:45 UTC**, especially Windows Server 2019 hosts (because of the build 17763 user agent):
   - Sysmon 1 powershell.exe;
   - 4104 ScriptBlock logs containing `New-AzureADApplicationPasswordCredential`, `oauth2PermissionGrant`, `Mail.ReadWrite`, `SimuLandApp`, `SimuLandCreds`, or Graph / login.microsoftonline.com URLs;
   - Sysmon 3/22 network and DNS events to `graph.microsoft.com`, `login.microsoftonline.com` and `graph.windows.net`.
3. **Logons for `pgustavo` / `SIMULAND\pgustavo`** (4624/4648/4672). Was pgustavo active on-prem at the time? Cloud actions with no matching on-prem session would support token forgery.
4. **Any endpoint egress IP** that could stand in for the 1.2.3.4 placeholder.
