# Threat Intelligence Report Template

Use for full profiles. For narrower questions, use only the relevant sections. Omit a section rather than padding it; if something is unknown, say so in Intelligence Gaps.

---

# [Subject name] — Threat Profile
*Research date: [today]. Coverage: reporting from [earliest] to [latest]. Confidence: [overall].*

## 1. BLUF (bottom line up front)
3–5 sentences: what it is, who it targets, whether it's active now, why the reader should care (relevance to their sector / environment if applicable), and the single most important detection takeaway.

## 2. Identity and attribution
- **Aliases** — table: Vendor | Name | Notes on overlap
- **Type / motivation** — nation-state espionage, eCrime, ransomware affiliate/RaaS, hacktivist, etc.
- **Suspected origin / sponsor** — with confidence and who assesses it
- **Active since / last reported activity** — with dates
- **Relationships** — affiliates, RaaS programs used, shared tooling, access brokers

## 3. Targeting and victimology
Sectors, regions, organization sizes, and notable victims (public only). Note whether the reader's sector has been targeted, if known.

## 4. Recent activity timeline
Table: Date | Event | Source. Most recent first, last 12–18 months emphasized.

## 5. Behavior chain (kill chain)
Narrative walk-through in attack-lifecycle order. For each stage: what they do, which tools, example observed command lines or artifacts (from reports, defanged), and variations between campaigns/affiliates. A Mermaid flowchart of the chain is a good addition for complex intrusions.

## 6. MITRE ATT&CK / ATLAS mapping
Table per `attack-mapping.md`: Tactic | ID | Name | Procedure | Data source | Source.

## 7. Tooling and malware
Table: Tool | Type (custom malware / commodity / dual-use / LOLBin / RMM) | Purpose in chain | Key detection artifacts (named pipes, mutexes, file paths, default certs, user-agents).

## 8. Indicators of compromise
Split by type. Every row cited and dated; network IOCs defanged.

| Type | Indicator | Context | First/last seen | Pyramid level | Source |
|---|---|---|---|---|---|

Group: file hashes (SHA256 preferred), domains, IPs, URLs, email senders/subjects, file names/paths, registry keys, mutexes, named pipes, certificates/JA3/JA4, user-agents, YARA/Sigma references.

State plainly: which IOCs are likely stale, which are shared infrastructure (CDN, cloud, VPS, Tor) prone to false positives, and where the full IOC lists live (links) if too long to reproduce.

## 9. Infrastructure patterns
Durable patterns beyond individual IOCs: hosting providers/ASNs, domain naming themes (e.g. `<company>-sso`, `<company>-okta`), registrars, TLD preferences, certificate traits, C2 profile characteristics, use of legitimate services (Cloudflare tunnels, ngrok, Telegram, Discord, cloud storage).

## 10. Detection opportunities
Ranked list — most durable first. For each:
- **Behavior** and ATT&CK ID
- **Telemetry** (Defender table / Windows or Sysmon event ID / cloud log)
- **Logic** in plain language or pseudo-Sigma (fields and conditions, not finished KQL)
- **Expected false positives** and tuning ideas
- **Durability** (Pyramid level)

Also list existing public detections worth reusing (SigmaHQ rule titles, vendor hunting queries, YARA rules) with links.

## 11. Hunting hypotheses
2–5 proactive hunts: hypothesis, what to look for, data source, time window.

## 12. Mitigations and hardening
Top controls that break the chain (ATT&CK mitigation IDs M#### where useful). Keep brief; detection is the focus.

## 13. Intelligence gaps and conflicting reporting
What isn't known, where vendors disagree, single-source claims, paywalled detail.

## 14. Detection engineering handoff
Top 3–5 detections to build first, in priority order: behavior, ATT&CK ID, data source, why it matters. Offer to turn any into a Defender XDR custom detection or Sigma rule.

## 15. Sources
Numbered list: title, publisher, date, URL. Tier 1 sources first.
