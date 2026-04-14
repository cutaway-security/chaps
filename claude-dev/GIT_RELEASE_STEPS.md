# GIT_RELEASE_STEPS.md

**Repository:** `https://github.com/cutaway-security/chaps.git`

## Overview

All development occurs on the `claude-dev` branch. Releases strip development files and force-push to `main`. Main is a deployment target only -- no work is committed there directly.

### Tag and Branch Naming

| Item | Format | Example | Purpose |
|------|--------|---------|---------|
| Dev snapshot tag | `dev-v#` | `dev-v3` | Marks the claude-dev state that produced a release |
| Release branch | `release-v#` | `release-v3` | Temporary branch for stripping dev files |
| Main release tag | `v#` | `v3` | Marks the public release on main; used for rollbacks |

List existing tags before creating a new one:

```bash
git tag
```

## Automated vs. Manual

Steps 1-5 of this procedure are automated by `claude-dev/release.sh`. Steps 6-9 (force-push to main, tag the main release, clean up, create the GitHub release) are intentionally left manual -- destructive operations on `main` are never automated.

Quick path:

```bash
./claude-dev/release.sh <version>   # e.g. 2
# then run the printed Step 6-9 commands manually
```

The remainder of this document is the underlying manual procedure that `release.sh` automates and the reference for any step that needs to be performed by hand.

## Pre-Release Checklist

- [ ] All changes committed and pushed on `claude-dev`
- [ ] PLAN.md reflects current completion status
- [ ] RESUME.md is up to date
- [ ] README.md is accurate for the public release
- [ ] LICENSE and NOTICE files are present and current
- [ ] README "Project License" section matches NOTICE
- [ ] No sensitive data, credentials, or internal references in code or docs
- [ ] No `[TBD]` or placeholder markers visible to end users
- [ ] All three scripts (CMD, PSv2, PSv3) produce expected output
- [ ] Markdown report output renders correctly
- [ ] Output status prefixes are consistent across all scripts
- [ ] `tools/chaps-analyze.ps1` runs cleanly against a sample report

## Release Steps

### 1. Verify starting state

Confirm you are on `claude-dev` with a clean working tree:

```bash
git status
```

Expected: `On branch claude-dev` with `nothing to commit, working tree clean`. If there are uncommitted changes, commit or stash them before proceeding.

### 2. Tag the release on claude-dev

```bash
git tag -a dev-v# -m "Release v#: <brief description>"
git push origin --tags
```

### 3. Create a release branch

```bash
git checkout -b release-v#
git status
```

Confirm: `On branch release-v#`.

### 4. Remove development files

```bash
git rm -r claude-dev/
git rm CLAUDE.md
git status
```

Confirm: only `claude-dev/` and `CLAUDE.md` deletions are staged. No unexpected changes.

```bash
git commit -m "Remove development files for release v#"
```

### 5. Verify the release branch

- [ ] All user-facing files are present and correct
- [ ] No Claude development files remain (`ls claude-dev/` should fail, `ls CLAUDE.md` should fail)
- [ ] All three scripts are present in their directories
- [ ] README.md accurately describes all features

### 6. Force-push to main

Main is a deployment target only. Force-push replaces it entirely with the clean release branch.

Confirm you are on the release branch before proceeding:

```bash
git status
```

Expected: `On branch release-v#` with `nothing to commit, working tree clean`.

```bash
git checkout main
git reset --hard release-v#
git push origin main --force
```

### 7. Tag the release on main

```bash
git tag -a v# -m "Release v#"
git push origin --tags
```

### 8. Verify deployment

- [ ] Repository main branch shows clean release
- [ ] No development files visible
- [ ] README.md renders correctly on GitHub

### 9. Clean up

```bash
git checkout claude-dev
git branch -d release-v#
```

### 10. Create GitHub release (if applicable)

```bash
gh release create v# --title "v#" --notes "Release notes here"
```

## Post-Release

- Update PLAN.md on claude-dev with next phase goals
- Update RESUME.md with release summary

## Rollback

If a release needs to be reverted, reset main to the previous release tag:

```bash
git checkout main
git reset --hard v<PREVIOUS#>
git push origin main --force
```

## Files Removed During Release

The following files exist only on the `claude-dev` branch and are stripped before pushing to `main`:

| File | Purpose |
|------|---------|
| `CLAUDE.md` | Claude Code project configuration |
| `claude-dev/PLAN.md` | Development plan and task tracking |
| `claude-dev/RESUME.md` | Session history and context |
| `claude-dev/ARCHITECTURE.md` | Technical architecture reference |
| `claude-dev/GIT_RELEASE_STEPS.md` | This file |
| `claude-dev/code-standards/powershell.md` | PowerShell coding standards |
| `claude-dev/code-standards/batch.md` | Batch script coding standards |
| `claude-dev/REMOTE_TESTING.md` | Proxmox VM testing procedures |
| `claude-dev/TESTING_STANDARD.md` | Test matrix and pass criteria |
| `claude-dev/CANONICAL_CHECKS.md` | Canonical check order reference |
| `claude-dev/vm-lookup` | VMID/Proxmox parser for ~/.ssh/config |
| `claude-dev/results/` | Local test output (gitignored, but remove directory anyway) |
| `claude-dev/*.local/` | Local-only review directories (e.g., review.local, gitignored) |

The following DO ship with the release (public-facing):
- `README.md`
- `LICENSE` (full GPL v3 text)
- `NOTICE` (dual-license statement, copyright, contact, attribution)
- `.gitattributes` (defensive `export-ignore` safety net)
- `PowerShellv3/chaps_PSv3.ps1`
- `PowerShellv2/chaps_PSv2.ps1`
- `CMD/chaps.bat`
- `docs/` (USAGE, CHECKS, INTERPRETING_REPORTS, REMEDIATION, ANALYSIS)
- `tools/chaps-analyze.ps1` and `tools/knowledge/findings.json`

## Defensive Safety Net: .gitattributes

The repo root ships a `.gitattributes` that marks `claude-dev/` and `CLAUDE.md` with `export-ignore`. This causes `git archive` and GitHub's auto-generated release tarball / zip downloads to strip those paths automatically, even if a future release path skips the manual `git rm` step. The `.gitattributes` file itself is harmless to ship and is part of the release.
