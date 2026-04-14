# CHAPS Analysis Tool

`tools/chaps-analyze.ps1` is a post-processing script that converts a CHAPS Markdown report into a structured findings analysis. The output is designed for both direct human review and ingestion into AI reporting or threat-modeling tools.

## What it does

- Parses a CHAPS report from PSv3, PSv2, or CMD (all three share the same output format)
- Extracts metadata, counts findings by status prefix per section
- Matches each negative (`[-]`) finding against a bundled JSON knowledge base
- For matched findings, emits: title, section, observation, technical detail, risk, recommendation, MITRE ATT&CK mapping, related findings, references
- Lists unmatched negative findings succinctly
- Summarizes incomplete (`[x]`) checks and informational (`[*]`) evidence counts

The output is neutral-factual. Defender AI tools can reframe it into remediation plans and executive summaries. Pentest AI tools can reframe it into attack plans and validation steps. The same source document serves both audiences.

## Quick start

From the directory containing the CHAPS report and the repo:

```powershell
.\tools\chaps-analyze.ps1 -InputReport Win10-chaps.md > Win10-analysis.md
```

## Parameters

| Parameter | Required | Description |
|---|---|---|
| `-InputReport <path>` | Yes | Path to a CHAPS Markdown report |
| `-KnowledgeOverride <path>` | No | Path to a JSON file that overrides or extends the bundled knowledge base |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Analysis produced |
| 2 | Input file missing or not a CHAPS report |
| 3 | Knowledge base missing or invalid JSON |

## Output structure

```
# CHAPS Analysis Report
## Metadata                   — target, OS, collection date, admin context, analyzer version
## OT/ICS Advisory            — single paragraph near the top; not repeated per check
## Summary                    — counts per section and severity breakdown
## Negative Findings          — matched findings, ordered by severity
## Unclassified Findings      — succinct list of unmatched [-] findings (review gap)
## Appendix A: Incomplete Checks    — [x] findings grouped by section
## Appendix B: Informational Evidence (summary)
```

Each matched finding includes:

- Severity in the heading: Critical, High, Medium, Low, Info
- Section and originating check number
- Verbatim observation from the CHAPS report
- Technical detail (what the setting controls)
- Risk (what goes wrong if left negative)
- Recommendation (what to achieve, not how to configure)
- MITRE ATT&CK mapping
- Related findings (other knowledge-base entries in scope)
- References (CIS Benchmark, STIG, Microsoft docs)

## Extending the knowledge base

The bundled knowledge base is `tools/knowledge/findings.json`. Each entry has the shape:

```json
"finding_key": {
  "title": "Short human-readable title",
  "matches": ["substring 1", "substring 2"],
  "check": "Check 40",
  "section": "Authentication",
  "severity": "High",
  "technical_detail": "What the setting controls.",
  "risk": "What goes wrong if not remediated.",
  "recommendation": "What to achieve.",
  "mitre_attack": [
    {"id": "T1003.001", "name": "OS Credential Dumping: LSASS Memory"}
  ],
  "related_findings": ["other_finding_key"],
  "references": ["CIS Benchmark 2.3.11.7", "STIG V-63687"]
}
```

An analysis run matches each `[-]` finding line against every entry's `matches` list. The first substring hit wins. Patterns should be distinctive enough to avoid cross-matching unrelated checks.

### Local overrides

Organizations can override or extend the bundled knowledge base without editing the bundled file:

```powershell
.\tools\chaps-analyze.ps1 -InputReport report.md -KnowledgeOverride myorg-findings.json
```

Override semantics:
- Entries with the same key as a bundled entry replace it entirely
- New keys are added
- Bundled entries not mentioned in the override are preserved

This lets an organization keep custom severities, added references, or internal remediation language in a separate file that survives CHAPS upgrades.

## Coverage

The Phase 1 knowledge base covers the most commonly-negative checks (~18 entries). Unmatched findings still appear in the analysis under **Unclassified Findings** so reviewers are never left with silent gaps.

See `claude-dev/PLAN.md` for the phasing plan for knowledge base expansion.

## What it does not do

- Fix anything on the target system (read-only analysis of a report file)
- Call any external services (fully offline, no telemetry)
- Require any tools beyond PowerShell 3.0+
- Override organizational policy — severities are defaults, adjust via `-KnowledgeOverride` if your environment scores differently
