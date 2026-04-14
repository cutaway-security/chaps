# ARCHITECTURE.md

## System Overview

CHAPS is a multi-script security assessment toolkit that evaluates Windows system hardening configurations. It provides three script variants (CMD batch, PowerShell v2, PowerShell v3+) to ensure at least one will execute on any Windows system encountered in isolated OT/ICS environments. Each script performs identical read-only checks against registry keys, services, system settings, and security policies, then produces a structured text report with status indicators and an optional markdown report for integration with documentation and AI analysis tools.

## Components

| Component | Purpose | Technology |
|-----------|---------|------------|
| chaps_PSv3.ps1 | Primary assessment script for modern Windows | PowerShell 3.0+ |
| chaps_PSv2.ps1 | Assessment script for legacy PowerShell environments | PowerShell 2.0 |
| chaps.bat | Fallback assessment script for minimal environments | Windows CMD batch |
| Output directory | Per-run timestamped results directory | %TEMP%\{Hostname}_{timestamp} |
| chaps report | Main assessment findings | Markdown to stdout (redirect to .md file) |

## Data Flow

1. **Script Launch** - User runs one of three scripts (PSv3, PSv2, or CMD)
2. **Environment Detection** - Script detects admin status, OS version, PowerShell version
3. **Output Setup** - Creates timestamped output directory in %TEMP%
4. **Check Execution** - Runs each enabled check function in category order:
   - System Info -> Security -> Authentication -> Network -> PowerShell -> Logging
5. **Check Logic** - Each check follows: modern cmdlet -> WMI fallback -> registry -> native command
6. **Result Output** - Each check writes findings with status prefix ([+], [-], [*], [x])
7. **Output** - Markdown to stdout; user redirects to file (`> report.md`) or copies from console
8. **Report Generation** - Markdown with metadata header, summary table, categorized findings, recommendations

## Testing Infrastructure

Adapted from ICSWatchDog project. SSH-based testing against Windows VMs on Proxmox:

1. **Deploy** - scp script to target VM
2. **Execute** - ssh remote PowerShell/CMD execution
3. **Retrieve** - scp output files back to dev workstation
4. **Validate** - Check markdown renders correctly, compare across script variants

VM fleet shared with ICSWatchDog: Win7, Win10, Win11, Server 2016/2019/2022.
Configuration details in claude-dev/remote-testing.example.conf (local copy gitignored).

## File Structure

```
chaps/
    CLAUDE.md                       # Project rules and guidelines
    README.md                       # Public overview, quick start, links to docs/
    docs/
        USAGE.md                    # Running instructions (public)
        CHECKS.md                   # Catalog of all 63 checks (public)
        INTERPRETING_REPORTS.md     # How to read the output (public)
        REMEDIATION.md              # Per-check remediation guidance (public)
        ANALYSIS.md                 # Analysis tool usage (public)
    tools/
        chaps-analyze.ps1           # Post-processing analysis tool (public)
        knowledge/
            findings.json           # Editable knowledge base (public)
    .gitignore
    claude-dev/
        ARCHITECTURE.md             # This file
        PLAN.md                     # Development roadmap and tracking
        RESUME.md                   # Session context and status
        GIT_RELEASE_STEPS.md        # Release process
        REMOTE_TESTING.md           # Proxmox VM testing setup and procedures
        TESTING_STANDARD.md         # Test matrix, pass criteria, parity testing
        CANONICAL_CHECKS.md         # Canonical check order for all three scripts
        vm-lookup                   # Helper script: parse VMID/Proxmox from ~/.ssh/config
        code-standards/
            powershell.md           # PowerShell coding standards
            batch.md                # Batch script coding standards
    CMD/
        chaps.bat                   # CMD batch assessment script
    PowerShellv2/
        chaps_PSv2.ps1              # PowerShell v2 assessment script
    PowerShellv3/
        chaps_PSv3.ps1              # PowerShell v3+ assessment script (reference implementation)
```

## Technology Stack

| Layer | Technology | Version |
|-------|-----------|---------|
| Primary Script | PowerShell | 3.0+ |
| Legacy Script | PowerShell | 2.0 |
| Fallback Script | CMD Batch | Windows XP+ |
| Registry Access | Get-ItemProperty / reg query | Built-in |
| System Queries | Get-CimInstance / Get-WmiObject / wmic | Built-in |
| Network Queries | Get-NetIPAddress / ipconfig / netsh | Built-in |
| Output | Tee-Object / echo redirection | Built-in |

## Configuration

All configuration is via script parameters at the top of each script:
- Boolean flags to enable/disable individual checks (default: all enabled)
- `$Config` switch parameter to display current configuration and exit
- `$auditor_company` - Company name for report header
- `$sitename` - Site/plant identifier for report header
- `$cutsec_footer` - Toggle Cutaway Security footer in output

## Output Status Prefixes

| Prefix | Meaning |
|--------|---------|
| `[+]` | Positive - system configured to recommendation |
| `[-]` | Negative - system configured against recommendation |
| `[*]` | Informational - script info and check details |
| `[$]` | Report information |
| `[x]` | Error - check failed or configuration unknown |

## Constraints

- No external dependencies -- all scripts use only built-in Windows tools
- Read-only operations only -- scripts must never modify system state
- Must handle non-admin execution (skip checks gracefully, report what was skipped)
- Must work on air-gapped systems with no network connectivity
- Must work on systems where software installation is prohibited
- Output must be self-contained and portable (copy off system for analysis)
