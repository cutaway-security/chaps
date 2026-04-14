# CLAUDE.md - Project Rules and Guidelines

## Project Overview

**Project**: CHAPS (Configuration Hardening Assessment PowerShell Scripts)
**Repository**: https://github.com/cutaway-security/chaps
**Development Branch**: claude-dev
**Description**: CHAPS provides CMD, PowerShell v2, and PowerShell v3+ scripts to evaluate the security configuration of standalone Windows systems in isolated OT/ICS environments. It targets systems where Microsoft Policy Analyzer and other commercial assessment tools cannot be installed, such as Engineer/Operator workstations, HMI systems, and management servers.

---

## Essential Documents (Read in Order)

Before starting any development session, read these documents in order:

1. **CLAUDE.md** - This file. Project rules, constraints, and conventions
2. **claude-dev/ARCHITECTURE.md** - System design, data structures, script organization
3. **claude-dev/PLAN.md** - Project roadmap, current phase, milestones, completion status
4. **claude-dev/RESUME.md** - Development status, what is in progress, blockers, session context

**At session start**: Confirm you have read these documents before proceeding. List your understanding of the current state and next steps. Wait for confirmation before proceeding.

---

## Development Process Rules

When encountering issues during development:

1. **STOP** - Do not continue to next task
2. **DIAGNOSE** - Identify root cause with specific error messages and line numbers
3. **FIX** - Implement a solution
4. **VERIFY** - Confirm the fix works with actual testing
5. **DOCUMENT** - Record the issue and solution in RESUME.md
6. **ASK** - If unable to resolve after reasonable attempts, STOP and ask for clarifying directions

**Never assume code works without testing. Never move forward with unresolved issues.**

### Phase Completion Process

Before moving to the next phase:

1. **Verify** - All components of current phase working
2. **Test** - Run tests relevant to the phase
3. **Document** - Update RESUME.md with session activity
4. **Summarize** - Provide summary of completed work
5. **Plan** - List steps for next phase
6. **Confirm** - Wait for user confirmation before proceeding

---

## Absolute Requirements

- NO emoji, icons, or Unicode symbols in source code, output, or documentation
- NO stubs, placeholders, or fake data -- implement real functionality or mark clearly as TODO with explanation
- NO claiming code works without testing -- be honest about untested code
- NO moving forward when issues are unresolved
- NO spaces in file or folder names
- All output files must contain a timestamp in the filename (format: YYYYMMDD_HHMMSS)
- Scripts MUST work without external dependencies -- use only built-in Windows features
- Scripts MUST NOT modify system configuration -- read-only assessment only
- Scripts MUST handle non-admin execution gracefully (skip checks requiring elevation, report what was skipped)

---

## Technical Constraints

### chaps_PSv3.ps1 (PowerShell v3+)

| Constraint | Value |
|------------|-------|
| Language | PowerShell 3.0+ |
| Target OS | Windows 7/Server 2008 R2 and later |
| Operations | Read-only system assessment |
| Dependencies | None (built-in cmdlets only) |
| Execution | `Set-ExecutionPolicy Bypass -scope Process` |
| Output | Markdown to stdout (user redirects to file or copies from console) |

### chaps_PSv2.ps1 (PowerShell v2)

| Constraint | Value |
|------------|-------|
| Language | PowerShell 2.0 |
| Target OS | Windows XP/Server 2003 and later |
| Operations | Read-only system assessment |
| Dependencies | None (built-in cmdlets only, no CIM) |
| Execution | `Set-ExecutionPolicy Bypass -scope Process` |
| Output | Markdown to stdout (user redirects to file or copies from console) |

### chaps.bat (CMD Batch)

| Constraint | Value |
|------------|-------|
| Language | Windows CMD batch scripting |
| Target OS | Windows XP and later (worst-case fallback) |
| Operations | Read-only system assessment |
| Dependencies | None (built-in commands: reg query, wmic, netsh, systeminfo) |
| Output | Markdown to stdout (user redirects to file or copies from console) |

---

## Code Quality Standards

Follow the standard code quality rules for this project's languages:
- PowerShell standards per code-standards/powershell.md
- Batch script standards per code-standards/batch.md

### Project-Specific Standards

- Use consistent status prefixes in all output: `[+]` positive, `[-]` negative, `[*]` info, `[$]` report, `[x]` error
- Every check function must handle missing registry keys, missing cmdlets, and non-admin access gracefully
- Use Try/Catch with fallback methods: modern cmdlet -> legacy WMI -> registry -> native executable
- Each check must produce output that explains what was checked and what the recommended setting is
- Section headers must clearly delineate check categories
- All three scripts (CMD, PSv2, PSv3) should produce equivalent output for the same checks

---

## Project Scope

### In Scope

- Security configuration assessment for standalone Windows systems
- CMD, PowerShell v2, and PowerShell v3+ script implementations
- Markdown output to stdout -- users redirect to file or copy from console
- Single output stream: same content whether viewed in console or redirected to file
- Checks aligned with current hardening recommendations (references cite CIS, STIG, Microsoft baselines for understanding)
- USB/PnP device enumeration, antivirus detection, software inventory, network connections (Issue #2)
- Testing against Windows VMs on Proxmox (adapted from ICSWatchDog methodology)

### Out of Scope

- Remediation or configuration changes on target systems
- Network-based scanning or remote system assessment
- Exploitation tools or offensive capabilities
- GUI or interactive interfaces
- External tool dependencies or module installation
- Windows version gating within scripts (admins choose the right script for their system)

---

## Testing

### Test Environment

- Windows 10/11 workstation (primary target for PSv3)
- Windows Server 2016/2019/2022
- Older Windows versions where available (for PSv2 and CMD validation)
- Test both with and without Administrator privileges

### Test Procedures

- Run each script and verify output contains all expected check sections
- Verify graceful handling of non-admin execution
- Compare output across all three script variants for consistency
- Validate markdown report renders correctly
- Check that output directory and files are created properly

---

## Communication Style

- Focus on substance, skip unnecessary praise
- Be direct about problems -- identify specific issues with line numbers
- Question assumptions and challenge problematic approaches
- Ground claims in evidence, not reflexive validation
- When stuck, explain what was tried and ask specific questions

---

## Documentation Updates Required

When making changes, update the appropriate documents:

| Change Type | Update |
|-------------|--------|
| Architecture change | claude-dev/ARCHITECTURE.md |
| Phase completion | claude-dev/PLAN.md |
| Session activity | claude-dev/RESUME.md |
| Problem encountered | claude-dev/RESUME.md |
| New check added | README.md, all three scripts |
| Usage change | README.md |

---

## Session Workflow

### Starting a Session

1. Read CLAUDE.md (this file)
2. Read claude-dev/ARCHITECTURE.md
3. Read claude-dev/PLAN.md
4. Read claude-dev/RESUME.md
5. State your understanding of current status
6. List proposed next steps
7. Wait for confirmation before proceeding

### During Development

1. Work on one task at a time
2. Test each change before moving on
3. Document issues in RESUME.md
4. Stop and ask if encountering persistent issues

### Ending a Session

1. Update claude-dev/RESUME.md with what was accomplished
2. Update claude-dev/PLAN.md with completion status
3. List any blockers or open questions
4. Provide summary of session
