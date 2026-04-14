# RESUME.md

## Current State

**Last Session**: 2026-04-14
**Branch**: claude-dev (uncommitted Phase 12 changes in working tree; Phase 11 already pushed)
**Status**: Phase 12 complete in working tree, awaiting user review and commit. Phase 8 release tagging unblocks immediately after.

## What Was Just Done -- Phase 12 (Release Tooling and Deployment Process)

Goal: bring CHAPS release process up to ICSWatchDog standard. Repeatable preflight automation, manual force-push, defensive safety net for `git archive` consumers.

### Files added

- **`.gitattributes`** (repo root) -- `export-ignore` entries for `claude-dev/` and `CLAUDE.md`; also enforces `*.bat text eol=crlf` so the CRLF-on-CMD bug (Windows silently skipping LF-terminated batch lines) cannot re-emerge from a fresh checkout on Linux.
- **`claude-dev/release.sh`** (executable, syntax-checked) -- adapted from `/home/cutaway/Projects/ICSWatchDog/claude-dev/release.sh`. Automates Steps 1-5 of GIT_RELEASE_STEPS.md and prints the manual Step 6-9 commands.

### Files modified

- **`claude-dev/GIT_RELEASE_STEPS.md`**:
  - Added "Automated vs. Manual" preamble pointing at `release.sh`
  - Pre-release checklist now includes LICENSE, NOTICE, README license section, and analyzer smoke test
  - "DO ship" list now includes LICENSE, NOTICE, `.gitattributes`
  - New "Defensive Safety Net" section explains `.gitattributes` behavior
- **`claude-dev/PLAN.md`** -- Phase 12 marked complete in working tree
- **`claude-dev/RESUME.md`** -- this file

### What `release.sh` does

1. **Preflight**: confirms repo root, branch=claude-dev, clean tree, dev-tag/rel-tag/rel-branch don't already exist, in sync with origin
2. **Manual checklist confirmation**: prompts user to confirm PLAN/RESUME/README/LICENSE/NOTICE current; no sensitive data; scripts/analyzer working
3. **Automated content checks**: every script has the `Cutaway Security, LLC` copyright header; no `[TBD]` markers in shipping files
4. **Tag claude-dev** as `dev-v#`, push to origin
5. **Create release branch** `release-v#`
6. **Strip dev files**: `git rm -rq claude-dev/` and `git rm -q CLAUDE.md`, commit
7. **Verify release branch**: required files present (README, LICENSE, NOTICE, three scripts, docs/, tools/, knowledge base); forbidden paths absent
8. **Print manual commands** for force-push to main, tag v#, GitHub release

Force-push to `main` is **never** automated. The script always stops at the manual command print.

### Working tree

```
new file:   .gitattributes
new file:   claude-dev/release.sh
modified:   claude-dev/GIT_RELEASE_STEPS.md
modified:   claude-dev/PLAN.md
modified:   claude-dev/RESUME.md
```

Nothing committed yet -- user review point.

## Up Next -- Steps to Review Before Proceeding

### Immediate review (before commit)

Read these files to confirm the deployment process matches your intent:

1. **`.gitattributes`** -- 3 entries: `claude-dev/ export-ignore`, `CLAUDE.md export-ignore`, `*.bat text eol=crlf`. Confirm the BAT line-ending rule is wanted (it is defensive against a known-recurring bug; says "BAT files always CRLF on checkout").
2. **`claude-dev/release.sh`** -- preflight + Steps 1-5 + printed manual commands. Spot-check:
   - Manual checklist items (lines ~95-105) match what you actually want to confirm before each release
   - Required-file list (lines ~150-160) is the right set for verification
   - Printed Step 6-9 commands at the bottom match how you want to ship
3. **`claude-dev/GIT_RELEASE_STEPS.md`** -- the "Automated vs. Manual" preamble, the updated pre-release checklist, the LICENSE/NOTICE/`.gitattributes` ship list, the new "Defensive Safety Net" section.

### Optional dry-run before commit

The release script can be tested without side effects up to the tag-creation step. To smoke-test the preflight + manual checklist + automated checks only, run with a fake version and abort at the first prompt:

```bash
./claude-dev/release.sh 99    # answer "n" at the manual checklist prompt to abort cleanly
```

This exercises every check up to the tag step without touching git state.

### Commit step

When approved, commit Phase 12 in one logical commit (suggested message: "Add release.sh and .gitattributes for repeatable releases") and push to `origin/claude-dev`.

### Then -- Phase 8 (resumed): Release Tagging

With Phase 11 + 12 committed and pushed, ship v2:

1. `./claude-dev/release.sh 2`
2. Answer prompts; provide a short tag message (e.g. `"Markdown rewrite, parity across PSv3/PSv2/CMD, analyzer tool"`)
3. Review `git log --stat release-v2 | head -40` and `git diff main..release-v2 --stat`
4. Run the printed Step 6-9 commands manually:
   - Force-push `release-v2` to `main`
   - Tag `v2` on main, push tag
   - Clean up `release-v2` local branch
   - `gh release create v2 --title "v2" --notes-file <release-notes>` (release notes file to be written)
5. Update PLAN.md and RESUME.md with the post-release state

## Blockers

None. Awaiting user review of Phase 12 working-tree changes.

## Recently Committed

- `6ffc027` License Updated -- Phase 11: dual-license posture, LICENSE + NOTICE files, standardized headers, README Project License section, copyright `2019-2026 Cutaway Security, LLC`
- `2267fca` Phase 8 items 1-4: close issue/PRs, delete stale branches
