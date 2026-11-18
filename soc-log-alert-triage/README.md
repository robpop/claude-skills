# soc-log-alert-triage

A Claude skill that triages security logs and alerts like a **SOC Tier 2 analyst** and produces a structured incident report that is safe to paste into a ticket, chat or email.

## What it does

- Extracts and deduplicates IOCs and **defangs** every external indicator (`hxxps://`, `evil[.]com`, `198.51.100[.]4`)
- Keeps internal (RFC1918) addresses out of the IOC table and lists them under Affected Assets instead
- Builds a UTC timeline and assigns one severity, from Informational to Critical, with a justification
- Recommends action items only where the evidence supports them
- Treats log content as evidence, never instructions, and flags prompt-injection text found in logs
- Forms its own verdict before reconciling with any prior analyst notes

## When it triggers

Pasted or uploaded security data such as firewall, proxy, DNS, EDR/AV, IDS/IPS, SIEM alerts, auth/VPN logs, Windows event logs, email headers or sandbox output. It also triggers on requests to triage, investigate or pull IOCs. Ordinary application debugging logs are out of scope.

## Report sections

Executive Summary · Timeline (UTC) · Extracted IOCs · Affected Assets · Immediate Action Items · Notes

## Install

- **Claude.ai:** zip this folder, then upload it under Skills in Settings. Code execution must be enabled.
- **Claude Code:** copy this folder to `~/.claude/skills/` (all projects) or `.claude/skills/` (one project).

## Notes

Sanitize logs before sharing them with any AI tool, according to your organization's data-handling policy.
