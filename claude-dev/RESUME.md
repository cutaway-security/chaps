# RESUME.md

## Current State

**Last Session**: 2026-04-13
**Branch**: claude-dev
**Status**: Clean -- full VM test run complete, all scripts pass on all 6 VMs

## What Was Accomplished

### Phases 1-7: Complete (see previous sessions)

### Phase 5 Reset: Testing Infrastructure Aligned with ICSWatchDog Standard (Complete)

See earlier RESUME.md entries.

### Full VM Test Run 2026-04-13

Ran all three CHAPS scripts against all 6 built VMs in the lab:

**PSv3 (skip Win7 -- expected PS version error):**
- Win10Pro-Dev, Win11Pro-Dev, WinServer2016-Dev, WinServer2019-Dev, WinServer2022-Dev: rc=0, 6 sections, 0 stderr
- Win7Pro-Dev: clean version error exit (expected, PASS)

**PSv2 (all 6 VMs):**
- Win7Pro-Dev, Win10Pro-Dev, Win11Pro-Dev, WinServer2016-Dev, WinServer2019-Dev, WinServer2022-Dev: rc=0, 6 sections, 0 stderr

**CMD (all 6 VMs):**
- All 6 VMs: rc=0, 7 sections (6 + footer), 59 checks, 0 stderr

Results stored in `claude-dev/results/` (gitignored).

### Bugs Surfaced and Fixed

1. **Get-SystemInfo** -- `Get-ComputerInfo` fails under non-interactive SSH with "Access is denied" on console buffer. Added three-tier fallback chain: `Get-ComputerInfo` -> `Get-WmiObject Win32_OperatingSystem` -> `systeminfo` command parsing. All tiers wrapped in try/catch.

2. **CMD/chaps.bat line endings** -- File had LF instead of CRLF. Windows CMD parser silently skipped Checks 11-33 on all VMs. Fixed by converting to CRLF. All 59 checks now emit correctly.

3. **Get-BitLocker manage-bde fallback** -- On Server editions where BitLocker feature isn't installed, neither `Get-BitLockerVolume` nor `manage-bde.exe` exists. The fallback threw noisy CommandNotFound to stderr. Added `Get-Command manage-bde.exe` probe; emits `[*]` info line when neither is available. Fixed in both PSv3 and PSv2.

4. **PSv2 Get-CimInstance -> Get-WmiObject migration** -- Two functions (Get-CredDeviceGuard, Get-AntiVirus) retained the Cim-only `-ClassName` parameter after the migration. `Get-WmiObject` expects `-Class`. Also fixed Unicode en-dash characters inherited from earlier branch history in both PSv3 and PSv2.

### Parity Matrix (Win10Pro-Dev, 2026-04-13)

| Measure | PSv3 | PSv2 | CMD |
|---|---|---|---|
| Output lines | 182 | 192 | 554 |
| Section headers | 6 | 6 | 7 (6 + footer) |
| `[+]` positive | 36 | 34 | 22 |
| `[-]` negative | 53 | 63 | 16 |
| `[*]` informational | 54 | 56 | 299 |
| `[x]` error | 1 | 1 | 0 |

All three scripts attempt every canonical check. CMD's higher `[*]` count reflects raw-output checks (`netstat`, `net accounts`, software inventory) which emit one line per data row.

The only remaining `[x]` errors are environmental (isolated lab has no internet, so the WinPatch check can't reach Microsoft Update) and a few Win7-specific event log names that don't exist on that OS -- both expected.

## In Progress

- Phase 8: Documentation and Release Prep
  - VM testing: COMPLETE
  - Remaining: README update, close Issue #2 / PR #5, final release prep

## Blockers

- None.

## Next Steps

1. Update README.md to reflect:
   - New version 2.0.0
   - Markdown output to stdout (users redirect to file)
   - Three scripts: PSv3, PSv2, CMD -- same canonical checks
   - Removed setup steps related to output directory
   - Usage examples for all three scripts
   - Updated check list (59 checks) with brief descriptions
   - Note testing status (tested on Win7, 10, 11, Server 2016/19/22)

2. Close Issue #2 (feature requests: USB, antivirus, software inventory, netstat) -- all implemented in Phase 3.

3. Close PR #5 -- features integrated via rewrite, not direct merge.

4. Pre-release checklist per GIT_RELEASE_STEPS.md.

5. Optional: non-admin test pass to complete the "Non-admin graceful" row in test matrices.

## Open Questions

- None currently.

## Files Modified This Session

| File | Change |
|------|--------|
| PowerShellv3/chaps_PSv3.ps1 | Get-SystemInfo fallback chain, Get-BitLocker manage-bde probe, fixed en-dash in Get-CredDeviceGuard |
| PowerShellv2/chaps_PSv2.ps1 | Same fixes + Get-CimInstance -> Get-WmiObject with -Class param fix |
| CMD/chaps.bat | Converted LF -> CRLF line endings |
| claude-dev/TESTING_STANDARD.md | Populated test matrices with 2026-04-13 results, parity matrix, bug summary |
| claude-dev/RESUME.md | This file |
| claude-dev/PLAN.md | Phase 8 marked in progress |
