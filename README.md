# CHAPS: Configuration Hardening Assessment Scripts

CHAPS is a set of read-only scripts for checking Windows system security configuration where additional assessment software (such as Microsoft Policy Analyzer or commercial tools) cannot be installed. It is designed for Industrial Control System (ICS) and operational technology environments — engineer/operator workstations, HMI systems, historians, and management servers — but runs on any Windows system.

CHAPS is **not a replacement** for the [Microsoft Security Compliance Toolkit](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-compliance-toolkit-10) and Policy Analyzer. Use those when you can install software on the target. Use CHAPS when you can't.

## Scripts

CHAPS ships three script variants that all perform the same 59 checks in the same order. Pick the one that matches the target system:

| Script | Path | Use when |
|---|---|---|
| PowerShell 3+ | `PowerShellv3/chaps_PSv3.ps1` | PowerShell 3.0 or later is available (Windows 8 / Server 2012 and newer) |
| PowerShell 2 | `PowerShellv2/chaps_PSv2.ps1` | Only PowerShell 2.0 is available (Windows 7 / Server 2008 R2) |
| CMD batch | `CMD/chaps.bat` | PowerShell is locked down or unavailable |

All three write **Markdown to stdout**. The operator redirects to a file:

```
.\chaps_PSv3.ps1 > mysystem-report.md
```

See [docs/USAGE.md](docs/USAGE.md) for full running instructions.

## Quick Start

Open a PowerShell window or Command Prompt **as Administrator** on the target system, then run one of:

```powershell
# PowerShell 3+
Set-ExecutionPolicy Bypass -Scope Process
.\chaps_PSv3.ps1 > $env:COMPUTERNAME-chaps.md
```

```powershell
# PowerShell 2
Set-ExecutionPolicy Bypass -Scope Process
.\chaps_PSv2.ps1 > $env:COMPUTERNAME-chaps.md
```

```cmd
REM CMD
chaps.bat > %COMPUTERNAME%-chaps.md
```

The report is a plain Markdown file. Copy it off the target system for review and delete the local copy.

## Documentation

- **[docs/USAGE.md](docs/USAGE.md)** — Detailed running instructions, permissions, output handling, non-admin behavior, troubleshooting.
- **[docs/CHECKS.md](docs/CHECKS.md)** — All 59 checks in canonical order with a brief description of what each verifies.
- **[docs/INTERPRETING_REPORTS.md](docs/INTERPRETING_REPORTS.md)** — How to read the status prefixes (`[+]` / `[-]` / `[*]` / `[x]`), what each category means, how to triage findings.
- **[docs/REMEDIATION.md](docs/REMEDIATION.md)** — Per-check remediation guidance for negative findings: registry keys, Group Policy paths, commands, and references.

## References

The check set and thresholds draw from:

- [Securing Windows Workstations: Developing a Secure Baseline](https://adsecurity.org/?p=3299) — Sean Metcalf
- [Microsoft Security Compliance Toolkit](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-compliance-toolkit-10)
- [CIS Microsoft Windows Benchmarks](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
- [STIG Viewer](https://www.stigviewer.com/)
- [Trimarc: Securing Active Directory](https://www.hub.trimarcsecurity.com/post/securing-active-directory-performing-an-active-directory-security-review)

Per-check references are included inline in `docs/REMEDIATION.md`.

## Collaborators

- Don C. Weber ([@cutaway](https://twitter.com/cutaway)) — [Cutaway Security, LLC](https://www.cutawaysecurity.com)
- Mike Saunders ([@hardwaterhacker](https://twitter.com/hardwaterhacker)) — [RedSiege, LLC](https://www.redsiege.com/)
- Brandon Workentin — [Enaxy, LLC](https://www.enaxy.com)

## License

GNU General Public License v3. See the license block at the top of each script file.
