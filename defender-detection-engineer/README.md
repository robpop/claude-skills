# defender-detection-engineer

A Claude skill that acts as a senior detection engineer for **Microsoft Defender XDR**. It turns a threat idea into a production-ready custom detection rule in KQL, including rules that use Sentinel tables in the unified Defender portal.

## What it does

- Asks a few focused questions when the detection hypothesis is vague, then designs logic that resists common evasions
- Writes KQL that saves as a custom detection, with the required columns and NRT eligibility where possible
- Delivers the full rule package: query, rule configuration, MITRE mapping, entity mapping and severity
- Includes validation queries (back-test volume, noise baseline, true-positive test) and tuning notes
- Defaults to alert-only; recommends automated response actions only after a rule proves low false-positive rates

## When it triggers

Requests like "detect…", "how would I catch…", "write me KQL for…", or "tune this custom detection", across MDE, MDI, MDO, MDA and Sentinel. Simple log triage with no detection rule wanted is out of scope; use `soc-log-alert-triage` for that.

## Install

- **Claude.ai:** zip this folder, then upload it under Skills in Settings. Code execution must be enabled.
- **Claude Code:** copy this folder to `~/.claude/skills/` (all projects) or `.claude/skills/` (one project).

## Notes

Always back-test and validate a rule in your own tenant before deploying it. Table schemas and ActionType values vary by licensing and onboarding.
