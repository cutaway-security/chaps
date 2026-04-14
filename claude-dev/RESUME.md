# RESUME.md

## Current State

**Last Session**: 2026-04-14
**Branch**: claude-dev
**Status**: Clean -- Phase 9 complete (4 new checks across all scripts, all VMs pass)

## What Was Accomplished

### Phases 1-8: Complete (see earlier sessions)

### Phase 9: Additional Privilege Escalation and Exposure Checks (Complete)

Added four new checks across all three scripts. Total checks went from 59 to 63. All canonical numbering shifted accordingly.

**New checks:**

| # | Name | Detects |
|---|---|---|
| 24 | Unquoted Service Paths | Service `ImagePath` values with spaces but no quotes (local privesc) |
| 25 | Weak Program Directory Permissions | NTFS ACLs on Program Files / vendor dirs that grant Modify/Write to non-admins |
| 26 | Installed Compilers | GCC, MinGW, clang, MSVC, NASM, Strawberry Perl, Python (LotL risk) |
| 53 | Network Shares | Non-default SMB shares (excludes ADMIN$, C$, IPC$, etc.) |

**Numbering changes (all renumbered consistently across scripts and docs):**
- Old Security 24-30 → New 27-33
- Old Auth 31-39 → New 34-42
- Old Network 40-49 → New 43-52, plus new 53 (Network Shares)
- Old PowerShell 50-56 → New 54-60
- Old Logging 57-59 → New 61-63

**Implementation summary:**

- **PSv3 (chaps_PSv3.ps1)**: Added Get-UnquotedServicePaths, Get-WeakProgramPermissions, Get-InstalledCompilers, Get-NetworkShares functions. Standard pattern: registry/Get-Acl/Get-Command. Total: 2,671 lines, 69 functions.

- **PSv2 (chaps_PSv2.ps1)**: Same four functions ported to PSv2-compatible syntax (no -Depth on Get-ChildItem, Win32_Share via WMI). Total: 2,631 lines, 69 functions.

- **CMD (chaps.bat)**: New checks plus renumbering of all 39 downstream Check N: subheadings. Check 24 (unquoted paths) implemented as dump-and-review using `wmic ... | findstr` -- pure CMD detection of unquoted+space+exe across nested for loops with quote-character comparison was too fragile, so the check lists all unquoted candidates for manual review. Check 25 (permissions) uses temp-file ACL inspection with icacls. Check 26 (compilers) uses `where` + filesystem search of common install roots. Check 53 (shares) uses `net share` with admin-share filter. Total: 63 checks, all CRLF.

**Test results (2026-04-14 full VM run):**

| Script | Win7 | Win10 | Win11 | Srv2016 | Srv2019 | Srv2022 |
|---|---|---|---|---|---|---|
| PSv3 | (version error, expected) | OK 198L | OK 220L | OK 198L | OK 202L | OK 201L |
| PSv2 | OK 206L | OK 197L | OK 219L | OK 197L | OK 201L | OK 201L |
| CMD | OK 712L 63ch | OK 798L 63ch | OK 822L 63ch | OK 751L 63ch | OK 775L 63ch | OK 754L 63ch |

All scripts: rc=0, 0 stderr, all expected sections present, all four new checks executing.

**Bugs fixed during Phase 9 implementation:**

1. **CMD Check 24 quote-character comparison**: Direct `if "!var:~0,1!"=="^""` patterns inside nested for/if blocks consistently caused parser errors. Resolved by switching to a simpler dump-and-review approach using `findstr /r /c:"^PathName=[A-Za-z]:"` to filter unquoted-looking entries. The auto-detection of "space before .exe" requires more involved CMD parsing than is reliable; the trade-off is that the assessor reviews the output instead.

2. **CMD Check 25 nested for/if depth**: The original implementation had four levels of nested parentheses (if-admin → for-each-base → if-exists → for-each-dir → call). CMD's parser broke on directory paths containing spaces. Resolved by using temp files (`dir /ad /b > tmp.txt`, then `for /f "usebackq" ... in (tmp.txt)`) which avoids the nesting issue entirely.

**Documentation updated:**

- `claude-dev/CANONICAL_CHECKS.md` -- regenerated with all 63 checks in correct sections
- `docs/CHECKS.md` -- regenerated with renumbered catalog and four new check rows
- `docs/REMEDIATION.md` -- added remediation guidance for all four new checks; renumbered all existing check entries; reordered file so checks appear in canonical numerical order
- `claude-dev/PLAN.md` -- Phase 9 marked complete

## In Progress

- Phase 8 release prep (deferred from before Phase 9):
  - Close Issue #2 and PR #5
  - Clean up review.local/ after user review of new check outputs
  - Delete stale remote branches
  - Pre-release checklist and tagging

## Blockers

- None.

## Next Steps

1. **User review of the four new checks in `claude-dev/review.local/`.** Spot-check Win10 and one server VM for each new check to confirm output looks right. Pay attention to:
   - Check 24: dump format -- is the manual-review note clear enough?
   - Check 25: false positive on `C:\Temp` (which we created for testing) -- expected, will not appear in real assessments unless that folder exists
   - Check 26: spot-check on a system with Strawberry Perl or VS Build Tools to verify detection works
   - Check 53: the lab VMs have no custom shares, so all reported `[+] No non-default SMB shares detected` -- want to validate detection on a system with shares
2. **Commit and push Phase 9 changes.**
3. **Resume Phase 8 release prep.**

## Open Questions

- Is the dump-and-review approach for Check 24 acceptable, or do you want me to invest more time in a CMD-only auto-detection? (PSv3/PSv2 do auto-detect; only CMD is the limitation.)
- Should the Compiler check (#26) emit `[*]` instead of `[-]` when compilers are found? Right now it reports `[-]` to flag attention, but a build server legitimately needs them.

## Files Modified This Session

| File | Change |
|------|--------|
| PowerShellv3/chaps_PSv3.ps1 | +4 new check functions, +4 toggles, +4 Show-Config lines, +4 main calls |
| PowerShellv2/chaps_PSv2.ps1 | Same +4 functions in PSv2-compatible syntax |
| CMD/chaps.bat | +4 new checks, renumbered 39 downstream check headers |
| claude-dev/CANONICAL_CHECKS.md | Regenerated with all 63 checks |
| docs/CHECKS.md | Regenerated with renumbered catalog |
| docs/REMEDIATION.md | Added remediation for 4 new checks; renumbered existing entries; reordered |
| claude-dev/PLAN.md | Phase 9 marked complete |
| claude-dev/RESUME.md | This file |
