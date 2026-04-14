# CHAPS v2

CHAPS v2 is a ground-up modernization of the Configuration Hardening Assessment Scripts. The check coverage has grown from the original PowerShell-only script to **63 checks across three script variants** (PowerShell 3+, PowerShell 2, and CMD batch), all producing the same Markdown report format. A new post-processing analyzer tool turns reports into structured findings with MITRE ATT&CK mappings.

This release is targeted at OT/ICS environments -- engineer/operator workstations, HMI systems, historians, and management servers -- where Microsoft Policy Analyzer and commercial assessment tools cannot be installed. It runs on any Windows system from XP through Windows 11 / Server 2022.

## Highlights

- **Three script variants, full check parity** -- same 63 checks in the same canonical order across `chaps_PSv3.ps1`, `chaps_PSv2.ps1`, and `chaps.bat`. Pick the script that matches what's available on the target.
- **Markdown to stdout** -- a single output stream. The operator redirects to a file (`chaps_PSv3.ps1 > report.md`) or copies from the console. No output directories, no temp files, no system modification.
- **Read-only and dependency-free** -- uses only built-in Windows facilities (PowerShell cmdlets, registry, WMI, netsh, wevtutil, auditpol). No modules to install, no configuration changes to the target.
- **Graceful non-admin handling** -- checks that need elevation are skipped with an `[x]` marker explaining what was missed; the script does not abort.
- **Post-processing analyzer** -- `tools/chaps-analyze.ps1` parses a CHAPS report and emits a structured Markdown analysis with severity, recommendations, MITRE ATT&CK mappings, and references, drawing from a 59-entry JSON knowledge base. Output is suitable for direct review or for ingestion into AI reporting / threat-modeling tools.
- **End-user documentation** -- new `docs/` directory: USAGE, CHECKS, INTERPRETING_REPORTS, REMEDIATION, ANALYSIS.

## What's New Since v1

### New checks

Phase 9 added four privilege-escalation and exposure checks that apply to all three scripts:

- **Unquoted Service Paths** -- enumerates service `ImagePath` values and flags any that contain spaces without quoting (classic local-priv-esc vector, MITRE T1574.009).
- **Weak Program Directory Permissions** -- inspects NTFS ACLs on `Program Files`, `Program Files (x86)`, and non-standard top-level `C:\` folders for write/modify rights granted to `Users`, `Authenticated Users`, or `Everyone`.
- **Installed Compilers** -- detects GCC/MinGW, clang, MSVC `cl.exe`, assemblers, Strawberry Perl, `make`, `cmake`. Searches PATH plus common install roots (`C:\Strawberry`, `C:\MinGW`, `C:\msys64`).
- **Network Shares** -- enumerates non-default SMB shares (excludes `ADMIN$`, `C$`, `D$`, `IPC$`).

Earlier modernization phases added 10 hardening checks aligned to current CIS / STIG / Microsoft baselines: UAC configuration, account / lockout policy, Secure Boot, LSA Protection (`RunAsPPL`), service hardening (Print Spooler, RemoteRegistry, SNMP, Telnet), SMB client signing, SCHANNEL TLS protocol versions, audit policy via `auditpol`, RDP NLA + encryption level, and TCP/IP stack hardening (source routing, ICMP redirects, router discovery).

Other additions: USB / PnP device enumeration, antivirus / EDR detection (SecurityCenter2 with `Get-MpComputerStatus` fallback for Server editions), software inventory (registry-based; avoids slow `Win32_Product`), network connections, Sysmon detection, Windows Firewall profile status, Microsoft Defender ASR rules, Windows Exploit Protection (DEP / ASLR / CFG), Windows LAPS + legacy LAPS, NetSessionEnum / RestrictRemoteSAM, MS Office macro settings, and PowerShell wildcard-module + transcription-output-directory checks.

Total: 63 checks per script (up from 59 in early v2 development).

### Output format

All output is now Markdown. Reports open with a metadata table (hostname, time, PS version, OS, admin status), use level-2 headings for each check category, and end with a footer. Status prefixes `[+]` `[-]` `[*]` `[x]` are preserved unchanged so existing tooling that consumes them still works.

### Bug fixes (PSv3)

- `Get-UntrustedFonts`: wrong variable reference (`$ressh` -> `$resuf`)
- `Get-WPAD`: registry path (`HKEY_CURRENT_USER\` -> `HKCU:\`) and wrong variable in hosts check
- `Get-NetBIOS`: WMI class typo (`Win32_NetWorkAdapterConfiguration` -> `Win32_NetworkAdapterConfiguration`)
- `Get-WinRM`: function name typo
- `Get-CredDeviceGuard` and `Get-UntrustedFonts`: version checks now correctly use `-ge 10` instead of `-eq 10` (Windows 11 was being skipped)
- `Get-LocalAdmin`: structural Try/Catch error and wrong variable reference
- Date format `yyyyddMM` corrected to `yyyyMMdd`
- Stubbed `Get-NetSessionEnum` and `Get-MSOffice` fully implemented and enabled

### Stability fixes (cross-script)

- PSv3 `Get-SystemInfo` now has a three-tier fallback (`Get-ComputerInfo` -> `Win32_OperatingSystem` WMI -> `systeminfo` parse) so it works under SSH and over WinRM
- PSv3 `Get-BitLocker` probes for `manage-bde.exe` before invoking it; emits an info line on Server editions where neither path is available
- PSv2 `Get-CredDeviceGuard` and `Get-AntiVirus`: corrected `-Class` parameter usage on `Get-WmiObject` and removed Unicode en-dashes
- CMD: forced CRLF line endings (Windows CMD silently skipped Checks 11-33 on LF-terminated files)
- CMD `[*]` lines no longer emit blank entries when source `wmic` output had trailing whitespace
- CMD `AllowRemoteRPC` line: removed stray `+` prefix and grammar fix

## Analysis Tool

`tools/chaps-analyze.ps1` is new in v2. It accepts a CHAPS Markdown report and produces a structured findings analysis:

```powershell
.\tools\chaps-analyze.ps1 -InputReport target-chaps.md > target-analysis.md
```

Each negative finding is matched against a JSON knowledge base (`tools/knowledge/findings.json`, 59 entries) and rendered with severity, observation, technical detail, risk, recommendation, MITRE ATT&CK mappings, and references. Unmatched negative findings are listed succinctly so the gap is visible. Informational and incomplete-check entries are summarized in appendices.

The knowledge base is editable. Organizations can supply their own override file with `-KnowledgeOverride` to add site-specific guidance without modifying the bundled file.

## Documentation

- `docs/USAGE.md` -- per-script invocation, output handling, non-admin behavior, troubleshooting
- `docs/CHECKS.md` -- all 63 checks in canonical order with brief descriptions and a CMD capability matrix
- `docs/INTERPRETING_REPORTS.md` -- status prefixes, triage workflow, common findings, cross-script comparison
- `docs/REMEDIATION.md` -- per-check remediation guidance with Group Policy paths, registry keys, commands, references
- `docs/ANALYSIS.md` -- usage and knowledge-base extension for the analyzer

## License

CHAPS v2 is dual-licensed:

- **Open Source: GNU GPL v3** -- consulting use, internal organizational use, and academic use are all permitted. Reports produced by running CHAPS are *not* derivative works and carry no GPL obligation.
- **Commercial**: required only for organizations that want to bundle CHAPS into proprietary products or services. Contact `info@cutawaysecurity.com`.

See `LICENSE` and `NOTICE` for details.

## Compatibility

| Script | Target |
|---|---|
| `PowerShellv3/chaps_PSv3.ps1` | PowerShell 3.0 or later (Windows 8 / Server 2012 and newer) |
| `PowerShellv2/chaps_PSv2.ps1` | PowerShell 2.0 (Windows 7 / Server 2008 R2) |
| `CMD/chaps.bat` | CMD on Windows XP and later (worst-case fallback when PowerShell is locked down) |

All three scripts are read-only, require no external dependencies, and produce equivalent output.

## Acknowledgements

CHAPS v2 builds on contributions and feedback from:

- Mike Saunders ([@hardwaterhacker](https://twitter.com/hardwaterhacker), RedSiege LLC)
- Brandon Workentin (Enaxy LLC) -- batch-script foundation that informed the `chaps.bat` rewrite
- @0xKaushik -- feature suggestions integrated as Checks 16 (USB), 17 (AV), 18 (Software), 50 (netstat)
- Everyone who filed the issues and PRs that are closed in this release

## Upgrade Notes

CHAPS v1 users: there is no in-place migration. v2 is a clean rewrite with a different output format (Markdown instead of plain text), a different invocation pattern (redirect stdout instead of fixed output directory), and an expanded check set. Treat v2 as a fresh install: download, run, redirect output to a Markdown file. Old v1 reports remain readable; new reports use the Markdown structure documented in `docs/INTERPRETING_REPORTS.md`.
