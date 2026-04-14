# Interpreting a CHAPS Report

A CHAPS report is a Markdown file with a metadata header, six check-category sections, and a footer. This document explains how to read it and triage the findings.

For the full check catalog, see [CHECKS.md](CHECKS.md).
For remediation guidance on findings, see [REMEDIATION.md](REMEDIATION.md).

## Report Structure

A CHAPS report opens with a metadata table identifying the target system and the run conditions:

```
# CHAPS Report: chaps_PSv3+ 2.0.0

| Field | Value |
|-------|-------|
| Hostname | DESKTOP-ENG01 |
| Start Time | Monday 04/14/2026 09:15:22 -05:00 |
| PS Version | 5 |
| OS Version | Microsoft Windows NT 10.0.19045.0 |
| Auditing Company | Cutaway Security, LLC |
| Site/Plant | plant1 |
| Admin Status | Administrator |
```

The body is six sections, each a level-2 heading:

1. `## System Info Checks`
2. `## Security Checks`
3. `## Authentication Checks`
4. `## Network Checks`
5. `## PowerShell Checks`
6. `## Logging Checks`

The footer closes with a horizontal rule and the completion time.

## Status Prefixes

Every finding line begins with a status prefix that indicates the class of the result:

| Prefix | Meaning | Action |
|:---:|---|---|
| `[+]` | **Positive** — system is configured in line with recommendations. | No action needed; document as a satisfied control. |
| `[-]` | **Negative** — system is configured against recommendations, or a required setting is missing. | Review and remediate. See [REMEDIATION.md](REMEDIATION.md). |
| `[*]` | **Informational** — data dump or context that does not imply good or bad. | Use as evidence or input for other analysis (software inventory, installed hotfixes, network interfaces). |
| `[x]` | **Error** — the check failed to complete. The setting's actual state is unknown. | Investigate: often means missing privilege, missing feature, or environmental limitation. |

Example fragment:

```
## Security Checks

[-] SMBv1 is Enabled
[+] SMBv1 Auditing is Enabled
[+] SMBv2/SMBv3 is Enabled
[-] SMB Server Require Security Signature is Disabled
```

## Triage Workflow

Work through the report in this order to build a prioritized finding list:

### 1. Check the header

- **Admin Status** — if `Normal User`, many admin-required checks will be `[x]` or `[*]`. Re-run as Administrator if possible before relying on the report.
- **PS Version** and **OS Version** — some findings depend on the OS version; note this for the remediation write-up.
- **Start Time** — date-stamp the finding list for tracking remediation over time.

### 2. Scan every section for `[-]` findings

Negative findings are the primary output of an assessment. Each one is a candidate control gap. Cross-reference each `[-]` against [REMEDIATION.md](REMEDIATION.md) for fix guidance.

Common `[-]` findings to prioritize:

- SMBv1 enabled
- WDigest `UseLogonCredential` enabled
- NTLM not configured for v2 + 128-bit
- LSA Protection (`RunAsPPL`) not enabled
- Print Spooler running on non-print servers
- Auto Update not set to scheduled install
- UAC disabled or relaxed
- Old TLS / SSL protocols enabled

### 3. Review `[x]` errors for coverage gaps

An `[x]` means the check did not complete. Common causes:

| Cause | Typical `[x]` lines | What to do |
|---|---|---|
| Non-admin execution | BitLocker, LocalAdmin, WinRM, Event Log sizes | Re-run as Administrator |
| Isolated network / no internet | `Check for Critical and Important Windows patches test failed: no internet connection.` | Expected in air-gapped environments; verify patches by other means |
| Feature not installed | BitLocker on Server editions without the feature | Not a control gap; note in report |
| OS too old / too new for a feature | Credential Guard on Windows 7 | Note in report; consider whether the OS should be upgraded |

An `[x]` for an admin-required check when running as Administrator is a real problem and worth investigating.

### 4. Review `[*]` informational data

Informational lines are raw evidence:

- Installed software inventory (cross-reference to known vulnerability feeds)
- Listening network ports (validate against expected services for the system's role)
- Audit policy status (confirm logging coverage matches site standards)
- Active network interfaces (check for unexpected interfaces)
- Installed hotfixes (compare to current Microsoft patch baseline)

### 5. Confirm `[+]` findings on high-value controls

For sensitive systems (HMI, domain controller, jump host), do not skip past `[+]` findings for:

- BitLocker encryption status
- Secure Boot
- LSA Protection
- AppLocker / WDAC
- SMB signing and encryption
- Event log sizes

Document these as satisfied controls in the assessment write-up.

## Cross-Script Comparison

When the same target is assessed with more than one CHAPS script (e.g., PSv3 and CMD), expect:

- **Same section headers and same check coverage** — every check is attempted by all three scripts.
- **Different line counts** — CMD tends to be longer because it emits one `[*]` line per raw-output row (`netstat`, installed software, `net accounts`). PowerShell scripts summarize more.
- **Different wording** — the underlying method can differ (e.g., `Get-SmbServerConfiguration` vs. registry query). The status prefix (`[+]`/`[-]`/`[*]`/`[x]`) should agree for the same check.
- **A few `[*]` info-only lines in CMD** — for AppLocker, ASR Rules, PowerShell Versions, PowerShell Language Mode. These require PowerShell cmdlets not available from CMD.

Significant `[+]` vs `[-]` disagreement on the same check across scripts indicates a real bug. Report it.

## What the Report Does Not Tell You

- **Whether a control is appropriate for the system's role.** E.g., `[-] Print Spooler running` is a finding on a workstation that does not print; it is expected on a print server.
- **Whether a finding is exploitable in the current environment.** The report lists configuration state; exploitability requires context (network exposure, attacker presence, other controls).
- **Whether remediation is safe.** Some settings can break legacy applications (e.g., disabling SMBv1 on a system that communicates with a 1990s-era controller). Validate remediations in a test environment first.
- **Compliance status for any specific framework.** The check set draws from CIS, STIG, and Microsoft baselines but does not map 1:1 to any single benchmark version.

## From Report to Write-Up

A typical assessment write-up from a CHAPS report includes:

1. **Executive summary** — count of `[+]` / `[-]` / `[x]` findings per category, key risk themes.
2. **Finding-by-finding detail** — each `[-]` finding with:
   - Check name and category
   - Observed state
   - Recommended state (from [REMEDIATION.md](REMEDIATION.md))
   - Risk rationale
   - Remediation steps
3. **Informational evidence** — appendix of software inventory, listening ports, active accounts.
4. **Controls satisfied** — list of `[+]` findings on high-value controls.
5. **Limitations** — any `[x]` that could not be resolved, reason, and recommended follow-up.

The Markdown format makes it straightforward to import findings into a report template, convert to PDF/HTML, or feed into an LLM for summarization.
