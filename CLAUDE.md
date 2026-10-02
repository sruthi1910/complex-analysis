# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Purpose

This project builds repeatable workflows for complex security analysis tasks.

## Workflows

### 1. Threat intel processing
Ingest threat intelligence reports → extract TTPs → create simulation plans.

### 2. Multi-source investigation
Correlate endpoint and cloud logs to investigate activity across sources.

## Log Sources

| Source | Domain |
|---|---|
| Windows Security events | Endpoint |
| Sysmon events | Endpoint |
| Azure AD sign-in logs | Cloud identity |
| Azure AD audit logs | Cloud identity |
