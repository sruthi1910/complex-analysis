# complex-analysis

Modules 8-9: a multi-source investigation (endpoint + cloud) with subagents, plan mode, local-model verification and context management, then reports and artifacts generated from the findings.

## Notes for course readers

**The investigation uses Microsoft's SimuLand dataset (Golden SAML), not the course's cookie-theft telemetry.**
The course's lab telemetry wasn't available, and having the model generate an attack dataset was blocked by its safety safeguards. SimuLand is a published, recorded dataset with both Windows and cloud logs, so the multi-source correlation still works on real telemetry. *If you're following the course:* use its cookie-theft logs. The prompts and workflow are the same; only the findings differ.

**Every document in `reports/` describes the Golden SAML findings.**
The report, briefing deck, dashboard and timeline were generated from `analysis/investigation-summary.md`, with an instruction to use only facts from that summary. Each one had a human review pass, and one wording fix each was applied.

**`analysis/verify-local.md` is a second-model review, not a source of truth.**
It came from a local model (Ollama). Its valid points were folded into `correlation.md`, and its generic or incorrect points were set aside. Treat any second model as a reviewer.

**Claude Desktop looks different from the course screenshots.**
Newer versions have a Chat/Cowork toggle inside the message box instead of separate tabs; Claude Code is the `</>` icon. Document generation needs Settings → Capabilities → code execution and file creation turned on.

**Connectors were used read-only.**
Nothing was posted to external services. Distribution should come after human review of the documents.
