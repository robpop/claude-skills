# defender-detection-engineer

A Claude skill that acts as a senior detection engineer for **Microsoft Defender XDR**. It turns a threat idea into a production-ready custom detection rule in KQL, including rules that use Sentinel tables in the unified Defender portal, and documents every detection with the **Palantir Alerting and Detection Strategy (ADS) Framework**.

## What it does

- Asks a few focused questions when the detection hypothesis is vague (3–5 max, batched), then designs logic anchored on behavior that resists common evasions
- Builds every detection as a complete ADS document, using the ten sections as the design process rather than an afterthought
- Writes KQL that saves as a custom detection, with the required columns and NRT eligibility where possible
- Delivers the full rule package: query, rule configuration, MITRE mapping, entity mapping and severity, all derived from the ADS sections so the document and the deployed rule never disagree
- Includes validation queries (true-positive test, back-test volume, noise baseline) and feeds the results back into the False Positives section
- Writes a Tier 1–ready response runbook with KQL pivot queries
- Defaults to alert-only; recommends automated response actions only after a rule proves a low false-positive rate

## The ADS sections

Every new detection includes all ten sections, in this order. Gaps are marked **TODO** with what's needed to close them, never silently omitted.

1. Goal
2. Categorization (MITRE ATT&CK, plus ATLAS for AI/ML attacks)
3. Strategy Abstract
4. Technical Context
5. Blind Spots and Assumptions
6. False Positives
7. Validation
8. Priority
9. Response
10. Additional Resources

The ADS document is followed by a **Microsoft Defender XDR implementation** section: data sources and NRT eligibility, the detection query (with a comment-free copy for NRT rules), a rule configuration table, and a pre-deployment checklist.

## How responses scale

- **New detection:** full ADS document plus implementation.
- **Tuning or fixing an existing detection:** updates to the affected ADS sections, a before/after volume query and a **Change log** entry. If no ADS exists for the rule, the skill offers to write one.
- **Quick KQL question:** a direct answer, no ADS document.

Requests that bundle several techniques get one ADS per detection.

## When it triggers

Requests like "detect…", "how would I catch…", "write me KQL for…", "tune this custom detection", or any mention of an ADS, an alerting and detection strategy, or detection documentation, across MDE, MDI, MDO, MDA and Sentinel. Simple log triage with no detection rule wanted is out of scope; use `soc-log-alert-triage` for that.

## Install

- **Claude.ai:** zip this folder, then upload it under Skills in Settings. Code execution must be enabled.
- **Claude Code:** copy this folder to `~/.claude/skills/` (all projects) or `.claude/skills/` (one project).

## Notes

Always back-test and validate a rule in your own tenant before deploying it. Table schemas and ActionType values vary by licensing and onboarding; when the skill isn't sure a column or ActionType exists, it gives a `getschema` or `distinct ActionType` query to confirm and lists the dependency under Blind Spots and Assumptions.

## References

- Palantir, *Alerting and Detection Strategy Framework*: https://github.com/palantir/alerting-detection-strategy-framework
