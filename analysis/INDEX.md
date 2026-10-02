# Index

There are seven files in this folder. Six belong to one investigation: the simulandlabs.com hybrid identity compromise (OTRF/SimuLand Golden SAML lab dataset, activity on 2021-08-02 UTC). The seventh is a separate threat-intel report that nothing else in the folder uses.

## Files

| File | Role | What it contains |
|---|---|---|
| `endpoint.md` | Primary analysis (on-prem) | The endpoint-analyst agent's review of `logs/windows/WindowsEvents.json` (38 Security, Sysmon, AD FS and WID audit events). wardog (RID 500) dumps the AD FS token-signing config from WID on ADFS01 and reads the DKM key from DC01 three times. Also covers the pgustavo NTLMv1 logons, the benign MDI and AAD Connect activity, and questions for the cloud logs. |
| `cloud.md` | Primary analysis (cloud) | The cloud-analyst agent's review of `logs/cloud/AADAuditEvents.json` and `OfficeActivityEvents.json`. Acting as pgustavo through PowerShell, the attacker adds Mail.ReadWrite to SimuLandApp, grants AllPrincipals consent, adds the `SimuLandCreds` secret, and reads 7 Inbox messages through Graph. Also covers entities to correlate and questions for the endpoint logs. |
| `correlation.md` | Synthesis | Joins the endpoint and cloud findings into one timeline. Covers user correlation (pgustavo is the only user in both, matched on name only) and IP correlation (none). Also gives the inferred attack chain, a confidence assessment (Golden SAML is low confidence), and 11 ranked log gaps. |
| `verify-local.md` | Review / QA | An external critique of a draft of `correlation.md`. It raises questions about unsupported conclusions, alternative explanations and logical gaps. It has no header, date or author, and its questions are generic. Some of them misread the draft, for example the question about the 13:13:11 end of the key theft. |
| `checkpoint-phase1.md` | Working state | Phase 1 checkpoint dated 2026-10-02. Holds the current understanding of the attack, confirmed findings F1–F9 with evidence and ATT&CK mappings, hypotheses H1–H8 with confidence levels, 10 ranked next steps, and containment actions. |
| `investigation-summary.md` | Final deliverable | Executive-level summary covering the timeline, ATT&CK techniques with confidence levels, IOCs, impact, containment, and the investigation steps to take next. |
| `ti-2026-10-01-apt28-logistics-campaign.md` | Unrelated threat intel | Extraction (2026-10-01) of CISA advisory AA25-141A on APT28 / GRU Unit 26165 targeting Western logistics and tech companies. Covers TTPs mapped to ATT&CK v19, IOCs, and an Atomic Red Team simulation plan with the telemetry each test should produce. |

## How the files relate

```
logs/windows/WindowsEvents.json ──► endpoint.md ──┐
                                                  ├──► correlation.md ◄─── verify-local.md
logs/cloud/*.json ───────────────► cloud.md ──────┘    (draft reviewed;     (review feedback)
                                                        feedback folded in)
                                                              │
   endpoint.md, cloud.md, correlation.md, verify-local.md ──► checkpoint-phase1.md
                                                              │
                         correlation.md, checkpoint-phase1.md ──► investigation-summary.md

CISA AA25-141A ──► ti-2026-10-01-apt28-logistics-campaign.md   (standalone; no links)
```

| File | Inputs (as stated in the file) | Used as input by |
|---|---|---|
| `endpoint.md` | `logs/windows/WindowsEvents.json` (not in this folder) | `correlation.md`, `checkpoint-phase1.md` |
| `cloud.md` | `logs/cloud/AADAuditEvents.json`, `logs/cloud/OfficeActivityEvents.json` (not in this folder) | `correlation.md`, `checkpoint-phase1.md` |
| `correlation.md` | `endpoint.md`, `cloud.md` (cited as `analysis/…`), plus valid points from `verify-local.md` | `checkpoint-phase1.md`, `investigation-summary.md` |
| `verify-local.md` | A draft of `correlation.md` | `correlation.md` (revisions), `checkpoint-phase1.md` |
| `checkpoint-phase1.md` | `endpoint.md`, `cloud.md`, `correlation.md`, `verify-local.md` | `investigation-summary.md` |
| `investigation-summary.md` | `correlation.md`, `checkpoint-phase1.md` | — |
| `ti-2026-10-01-apt28-logistics-campaign.md` | CISA AA25-141A advisory, its PDF and STIX, and the Atomic Red Team index | — |

## Notes

- **Confidence in Golden SAML drops as the work moves downstream.** `endpoint.md` rates T1606.002 as *Medium (inferred)* and `cloud.md` as *Low–Medium*. `correlation.md`, `checkpoint-phase1.md` and `investigation-summary.md` all settle on *Low*, because the alternative that the attacker used pgustavo's real credentials can't be ruled out. The later files are the current view.
- **The APT28 report is not linked to the SimuLand case.** No investigation file cites it, and the SimuLand files contain no APT28 attribution or IOC overlap. Its overlap with the case is generic technique IDs only (T1114.002, T1059.001, T1087.002).
- **The raw logs are not in this folder.** They are referenced under `logs/windows/` and `logs/cloud/`.
