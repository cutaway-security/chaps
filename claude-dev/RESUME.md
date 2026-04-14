# RESUME.md

## Current State

**Last Session**: 2026-04-14
**Branch**: claude-dev (uncommitted Phase 11 changes in working tree)
**Status**: Phase 11 (Licensing) COMPLETE in working tree, awaiting user review and commit. Phase 12 (Release Tooling) ready to start. Phase 8 release tagging blocked on Phase 12.

## What Was Just Done -- Phase 11 (Licensing and Header Standardization)

Decision: dual-license CHAPS as GPL v3 + Commercial. Allows consulting / internal-org / academic use freely; requires a paid license only for parties bundling CHAPS into proprietary products. Copyright standardized to `Copyright (c) 2019-2026 Cutaway Security, LLC`.

Files added:

- `LICENSE` -- full GPL v3 text (FSF canonical, 674 lines)
- `NOTICE` -- dual-license statement, copyright, commercial-license contact (info@cutawaysecurity.com), permitted-use clarifications, attribution requirements

Files modified:

- `PowerShellv3/chaps_PSv3.ps1` -- header collapsed from ~26 lines of GPL boilerplate to short block citing LICENSE + NOTICE
- `PowerShellv2/chaps_PSv2.ps1` -- same standardized header
- `CMD/chaps.bat` -- same standardized header (CMD comment style)
- `tools/chaps-analyze.ps1` -- inserted standardized header above SYNOPSIS
- `README.md` -- replaced one-line License section with full Project License section
- `claude-dev/PLAN.md` -- added Phases 11 + 12, marked Phase 8 blocked on them, added 4 Decision Log entries
- `claude-dev/RESUME.md` -- this file

Working tree:

```
modified:   CMD/chaps.bat
modified:   PowerShellv2/chaps_PSv2.ps1
modified:   PowerShellv3/chaps_PSv3.ps1
modified:   README.md
modified:   claude-dev/PLAN.md
modified:   claude-dev/RESUME.md
modified:   tools/chaps-analyze.ps1
new file:   LICENSE
new file:   NOTICE
```

Nothing committed yet -- user review point.

## Up Next -- Deployment Process Work

### Immediate (before any further coding)

1. **User review** of Phase 11 changes. Read LICENSE/NOTICE/README license section and one script header to confirm wording matches intent.
2. **Commit Phase 11** in one logical commit: `Adopt dual-license posture (GPL v3 + Commercial)`.
3. **Push to origin/claude-dev**.

### Phase 12 -- Release Tooling and Deployment Process

Tasks (in order):

1. Add `.gitattributes` at repo root with `export-ignore` entries:
   - `claude-dev/   export-ignore`
   - `CLAUDE.md     export-ignore`
   - (LICENSE, NOTICE, README, scripts, docs, tools all ship -- no entry needed)
   - Defensive safety net so `git archive` and GitHub auto-tarballs strip dev files even if the manual `git rm` step is missed.
2. Add `claude-dev/release.sh` adapted from ICSWatchDog (`/home/cutaway/Projects/ICSWatchDog/claude-dev/release.sh`):
   - Preflight: branch=claude-dev, clean tree, tags don't already exist, in sync with origin
   - Manual pre-release checklist confirmation (PLAN/RESUME/README/NOTICE current; no sensitive data)
   - Tag `dev-v#`, push tag
   - Create `release-v#` branch
   - `git rm -rq claude-dev/`, `git rm -q CLAUDE.md`
   - Verify required files present (README, LICENSE, NOTICE, three scripts, docs/, tools/)
   - Verify dev files absent
   - Print copy-paste manual commands for force-push to main, tag v#, GitHub release
   - Force-push to main is NEVER automated
3. Update `claude-dev/GIT_RELEASE_STEPS.md`:
   - Reference `release.sh` for Steps 1-5
   - Add LICENSE, NOTICE, README license section to pre-release checklist
   - Confirm "Files Removed During Release" table does NOT include LICENSE or NOTICE
4. Update `claude-dev/GIT_RELEASE_STEPS.md` "ship" table to reflect: LICENSE and NOTICE both ship; .gitattributes ships.

### Phase 8 (resumed) -- Release Tagging

Once Phase 12 lands and is committed:

- Run `./claude-dev/release.sh 2`
- Manually run the printed force-push, tag-v2, GitHub-release-create commands
- Update PLAN.md and RESUME.md post-release

## Blockers

None. Awaiting user review of Phase 11 working-tree changes.

## Files Modified This Session

| File | Change |
|------|---|
| LICENSE (new) | Full GPL v3 text |
| NOTICE (new) | Dual-license statement, copyright, contact, permitted-use clarifications |
| PowerShellv3/chaps_PSv3.ps1 | Standardized 12-line header replacing inline GPL boilerplate |
| PowerShellv2/chaps_PSv2.ps1 | Same standardized header |
| CMD/chaps.bat | Same standardized header (CMD comment style) |
| tools/chaps-analyze.ps1 | Inserted standardized header above SYNOPSIS |
| README.md | Project License section rewritten; mirrors NOTICE |
| claude-dev/PLAN.md | Added Phases 11 + 12; Phase 8 blocked; 4 Decision Log entries |
| claude-dev/RESUME.md | This file |
