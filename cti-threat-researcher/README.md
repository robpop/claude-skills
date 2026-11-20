# cti-threat-researcher

A Claude skill that acts as a **senior cyber threat intelligence researcher** (CrowdStrike / Mandiant / Unit 42 depth) and produces detection-ready intel for detection engineers. Every report answers one question: what do I need to know to detect, hunt and respond to this threat in my environment?

## What it does

- Builds an alias crosswalk across vendor naming schemes (e.g. Scattered Spider = Octo Tempest = UNC3944) and researches every alias, so no reporting is missed
- Researches live sources instead of relying on memory, prioritizing government advisories, vendor research blogs and The DFIR Report over news coverage
- Never fabricates IOCs: every indicator is cited, dated and **defanged**, and atomic IOCs older than about six months are flagged as likely stale
- Orders observed activity into a kill-chain behavior chain and maps it to **MITRE ATT&CK** (or **ATLAS** for AI/ML threats) with actor-specific procedures
- Ranks detection opportunities by durability using the Pyramid of Pain, with concrete telemetry (Defender XDR tables, Windows/Sysmon event IDs, cloud logs)
- Separates fact from assessment with estimative language and calls out conflicting vendor claims and intelligence gaps
- Stays defensive: describes attacker behavior at detection depth without writing exploit code, malware or operator playbooks

## When it triggers

Questions about a threat actor or APT, a ransomware, malware, loader, infostealer, RAT or botnet family, an offensive or dual-use tool (Cobalt Strike, Sliver, Mimikatz, RMM abuse), a campaign, a CVE exploited in the wild, or an AI/ML attack. Phrases like "what do we know about X", "research X", "IOCs for X", "TTPs for X" or "how do I detect X" are enough. Writing the final Defender KQL rule is out of scope; use `defender-detection-engineer` for that. Triaging pasted logs is also out of scope; use `soc-log-alert-triage`.

## Report sections

BLUF · Identity and Attribution · Targeting and Victimology · Recent Activity Timeline · Behavior Chain · ATT&CK / ATLAS Mapping · Tooling and Malware · IOCs · Infrastructure Patterns · Detection Opportunities · Hunting Hypotheses · Mitigations · Intelligence Gaps · Detection Engineering Handoff · Sources

Full profiles use every section. Focused questions get the relevant sections in depth, and quick checks get a few dated, sourced sentences. Optional exports include an IOC table as CSV and an ATT&CK Navigator layer JSON.

## Install

- **Claude.ai:** zip this folder, then upload it under Skills in Settings. Code execution and web search must be enabled.
- **Claude Code:** copy this folder to `~/.claude/skills/` (all projects) or `.claude/skills/` (one project).

## Works well with

- [`defender-detection-engineer`](../defender-detection-engineer): turns the handoff section's top detections into Defender XDR custom detection rules
- [`soc-log-alert-triage`](../soc-log-alert-triage): triages logs and alerts that match the threats you've researched

## Notes

Telemetry guidance defaults to Microsoft Defender XDR / Sentinel and Sigma, but the intel itself is vendor-neutral. Never include internal hostnames, usernames, IPs or other organizational data in research prompts. Validate IOCs and detection logic against current sources and your own environment before alerting or blocking on them.
