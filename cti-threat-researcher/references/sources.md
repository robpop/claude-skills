# Sources and Search Strategy

## Contents
1. Vendor naming conventions (alias crosswalk)
2. Source tiers
3. Where IOCs live
4. Search recipes

---

## 1. Vendor naming conventions

Always build a crosswalk first. Common schemes:

| Vendor | Scheme | Examples |
|---|---|---|
| CrowdStrike | Animal by nation/motivation: BEAR (Russia), PANDA (China), KITTEN (Iran), CHOLLIMA (DPRK), SPIDER (eCrime), JACKAL (hacktivist), TIGER (India), BUFFALO (Vietnam) | FANCY BEAR, VANGUARD PANDA, SCATTERED SPIDER, WIZARD SPIDER |
| Microsoft | Weather by origin: Typhoon (China), Blizzard (Russia), Sandstorm (Iran), Sleet (DPRK), Tempest (financially motivated), Storm-#### (developing) | Volt Typhoon, Midnight Blizzard, Octo Tempest |
| Mandiant / Google | APT## (attributed nation-state), FIN## (financial), UNC#### (uncategorized), TEMP.* (legacy) | APT29, FIN7, UNC3944 |
| Palo Alto Unit 42 | Constellations by origin (e.g. Taurus = China, Ursa = Russia, Serpens = Iran, Pisces = DPRK, Libra = financial) plus CL-STA/CL-CRI cluster IDs | Muddled Libra, Insidious Taurus |
| Secureworks | Element/color by origin: BRONZE (China), IRON (Russia), COBALT (Iran), NICKEL (DPRK), GOLD (eCrime) | GOLD BLADE, BRONZE SILHOUETTE |
| Proofpoint | TA### | TA505, TA577 |
| Cisco Talos / others | Varied | — |
| MITRE ATT&CK | G#### groups, S#### software, C#### campaigns — lists "Associated Groups" aliases | G0016 (APT29) |

Note: CrowdStrike Falcon Intelligence reports are largely subscription-only; use CrowdStrike's public blog, Adversary Universe pages, and the annual Global Threat Report for public material, and say when deeper detail would be behind a paywall. Correct the example cells if a search shows the alias pairing differently — vendor clusters don't always map one-to-one, and saying "overlaps with" is better than "is."

## 2. Source tiers

**Tier 1 — primary technical / authoritative**
- Government joint advisories: CISA (#StopRansomware, AA##-### advisories), FBI FLASH/PIN, NSA, NCSC-UK, ASD ACSC, CCCS, BSI — often include STIX/JSON IOC files and ATT&CK tables.
- Vendor research blogs: CrowdStrike, Mandiant/Google Threat Intelligence, Microsoft Threat Intelligence, Palo Alto Unit 42, Cisco Talos, Secureworks CTU, SentinelLabs, ESET WeLiveSecurity, Kaspersky Securelist, Proofpoint, Recorded Future Insikt, Symantec/Broadcom, Sophos X-Ops, Check Point Research, Elastic Security Labs, Huntress, Red Canary, Trend Micro, Volexity, Zscaler ThreatLabz, Arctic Wolf.
- The DFIR Report — full intrusion timelines with command lines and ATT&CK mapping; excellent detection material.
- MITRE ATT&CK group/software/campaign pages and MITRE ATLAS case studies.

**Tier 2 — aggregators and repositories**
- abuse.ch: MalwareBazaar (samples/hashes), ThreatFox (IOCs), URLhaus, Feodo Tracker.
- Malpedia (Fraunhofer) — malware family references and YARA.
- Vendor IOC GitHub repos (e.g. Unit 42 timely-threat-intel, ESET malware-ioc, Volexity threat-intel).
- AlienVault OTX pulses, VirusTotal (public reports), Any.Run / Hybrid Analysis / Joe Sandbox public reports.
- SigmaHQ, Elastic detection-rules, Splunk security_content, Microsoft Sentinel/Defender hunting query repos — existing detections to adapt.

**Tier 3 — context only**
- Security news (BleepingComputer, The Record, SecurityWeek, Dark Reading) — good for "what happened when," weak for technical detail. Follow their links to Tier 1 sources.
- Forums, social posts from individual researchers — useful leads, cite carefully, mark as single-source.

## 3. Where IOCs live

- Appendix / "Indicators of Compromise" section at the bottom of vendor blogs (fetch the full page — snippets omit it).
- CISA advisories: linked STIX XML/JSON and sometimes a PDF table.
- Vendor GitHub IOC repos.
- ThreatFox / MalwareBazaar tagged by family name.

If none are retrievable, say so and list these places for the user to pull them.

## 4. Search recipes

Run separate searches rather than one combined query. Typical set for an actor:

1. `<primary name> threat actor` (overview, recent activity)
2. One search per major alias
3. `<name> CISA advisory`
4. `<name> TTPs` / `<name> intrusion analysis`
5. `<name> indicators of compromise`
6. `<name> <year>` for the current and prior year
7. One search per signature tool or malware family it uses
8. `<name> DFIR Report` or `<name> incident response`
9. `<name> MITRE ATT&CK`
10. `<name> detection sigma` / `<name> KQL hunting`

For malware: add `<family> analysis`, `<family> loader chain`, `<family> C2 protocol`, `<family> persistence`, `<family> malpedia`, `<family> threatfox`.

For a tool: add `<tool> detection`, `<tool> default artifacts`, `<tool> named pipes`, `<tool> abused by threat actors`.

Use extended search mode for very recent activity or hard-to-find technical detail.
