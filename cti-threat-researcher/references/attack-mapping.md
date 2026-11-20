# MITRE ATT&CK and ATLAS Mapping

## Mapping rules

- **Most specific ID wins.** Use the sub-technique when one fits (T1059.001 PowerShell, not T1059). Use the parent only when the source doesn't say which variant.
- **Map procedures, not keywords.** "Used PowerShell" → T1059.001 is fine, but the row must say *what* the PowerShell did (e.g. "encoded download cradle pulling second stage from a Cloudflare Workers URL"). The procedure is what the detection gets built from.
- **One behavior can map to multiple techniques** (e.g. a scheduled task created via WMI for persistence = T1053.005 + T1047). List both.
- **Cite the source per row**, and mark rows inferred rather than directly reported.
- **Use current IDs.** ATT&CK deprecates and renumbers techniques across versions; when unsure, check attack.mitre.org. Note the ATT&CK version if it matters.
- **Include the matrix**: Enterprise (Windows/macOS/Linux/Cloud/SaaS/IdP/Network/Containers), Mobile, or ICS. Identity- and cloud-heavy actors (help-desk social engineering, OAuth abuse, MFA fatigue) need the cloud/IdP techniques (e.g. T1621 MFA Request Generation, T1078.004 Cloud Accounts, T1556.006 Multi-Factor Authentication modification) — don't force everything into Windows endpoint techniques.
- **Data sources:** for each technique, note the ATT&CK data component that would observe it (e.g. Process Creation, Command Execution, Windows Registry Key Modification, Logon Session Creation, Network Traffic Flow) and translate it to concrete telemetry (see below).

## Table format

| Tactic | Technique ID | Technique name | Procedure (what this actor did) | Detection data source | Source |
|---|---|---|---|---|---|

Order rows by tactic in kill-chain order.

## Telemetry translation (Defender XDR / Windows / cloud)

| ATT&CK data component | Defender XDR advanced hunting table | Windows / Sysmon |
|---|---|---|
| Process creation / command execution | DeviceProcessEvents | 4688 (with cmdline auditing), Sysmon 1 |
| Network connection | DeviceNetworkEvents | Sysmon 3, 5156 |
| DNS | DeviceNetworkEvents (DnsConnectionInspected via DeviceEvents), DnsEvents (Sentinel) | Sysmon 22 |
| File creation/modification | DeviceFileEvents | Sysmon 11, 23, 26 |
| Registry modification | DeviceRegistryEvents | Sysmon 12/13/14, 4657 |
| Module/DLL load | DeviceImageLoadEvents | Sysmon 7 |
| Logon / authentication | DeviceLogonEvents, IdentityLogonEvents, AADSignInEventsBeta / EntraIdSignInEvents, SigninLogs (Sentinel) | 4624, 4625, 4648, 4768, 4769, 4776 |
| Named pipe / process access / injection / scheduled task / service | DeviceEvents (ActionType e.g. NamedPipeEvent, OpenProcessApiCall, CreateRemoteThreadApiCall, ScheduledTaskCreated, ServiceInstalled) | Sysmon 8, 10, 17/18; 4698, 7045 |
| AD / directory changes | IdentityDirectoryEvents, IdentityQueryEvents | 4662, 4720, 4728, 5136 |
| Email | EmailEvents, EmailAttachmentInfo, EmailUrlInfo, UrlClickEvents | — |
| Cloud app / SaaS | CloudAppEvents, AuditLogs, OfficeActivity | — |
| Alerts already firing | AlertInfo, AlertEvidence | — |

Table and ActionType names change; verify against current Microsoft documentation before building on them, and say so if unsure.

## Pyramid of Pain classification

Tag indicators so effort goes where it lasts:

- **Hash values** — trivial to change. Retro-hunt only.
- **IP addresses** — easy. Short shelf life; watch for shared hosting/CDN false positives.
- **Domain names** — simple. Registration patterns (registrar, naming theme, TLD) last longer than the domains.
- **Network/host artifacts** — annoying to change: URI patterns, user-agents, JA3/JA4/JA4S, certificate fields, named pipes, mutexes, registry paths, file paths.
- **Tools** — challenging: detect the tool's behavior, not its hash.
- **TTPs** — tough: behavior chains that hold even when tooling changes. Highest-value detections.

## MITRE ATLAS (AI/ML threats)

Use ATLAS (atlas.mitre.org) when the threat targets or uses AI/ML systems: prompt injection against an LLM app, jailbreaks, model or training-data theft, data poisoning, adversarial examples, abuse of AI agents/tools, or attackers using LLMs operationally. ATLAS IDs use the AML.T#### format (e.g. AML.T0051 LLM Prompt Injection, AML.T0054 LLM Jailbreak — verify current IDs on the site, since ATLAS is revised often). ATLAS also has case studies (AML.CS####) worth citing.

Map to ATLAS **and** ATT&CK when both apply — e.g. an actor using an LLM to write phishing lures is ATT&CK T1566 with an AI-enablement note; an attack against a company's RAG chatbot is ATLAS. If the threat uses AI only as a productivity aid (as several vendor reports describe for state actors), say that plainly rather than inflating it.

## ATT&CK Navigator layer (optional export)

When requested, produce a Navigator layer JSON file with the mapped techniques scored or color-coded (e.g. 1 = observed, 2 = observed + detection opportunity identified). Minimal shape:

```json
{
  "name": "<Actor> - observed techniques",
  "versions": {"layer": "4.5", "navigator": "5.1", "attack": "<current version>"},
  "domain": "enterprise-attack",
  "description": "Sources: ...",
  "techniques": [
    {"techniqueID": "T1059.001", "score": 1, "comment": "Encoded PowerShell download cradle (Source, date)"}
  ],
  "gradient": {"colors": ["#ffffff", "#ff6666"], "minValue": 0, "maxValue": 2}
}
```

Check the current layer/navigator version numbers if accuracy matters for import.
