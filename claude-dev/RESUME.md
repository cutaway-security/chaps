# RESUME.md

## Current State

**Last Session**: 2026-04-14
**Branch**: claude-dev (clean, in sync with origin)
**Status**: CHAPS v2 RELEASED. Post-release branding update landed same day. All planned phases (1-13) complete.

## Release Summary

CHAPS v2 shipped to master on 2026-04-14 and received a same-day branding follow-up (acronym + logos).

### Release artifacts

- **GitHub release**: https://github.com/cutaway-security/chaps/releases/tag/v2
- **Tags**: `dev-v2` (on claude-dev, commit `7c3983d`), `v2` (on master, commit `1bb098d` -- immutable)
- **Release notes**: `claude-dev/RELEASE_NOTES_v2.md` (preserved on claude-dev; not shipped to master)
- **Social preview**: `images/chaps_logo_shield_only.png` uploaded via GitHub Settings -> General -> Social preview

### What shipped at v2 tag (1bb098d, 15 files)

- `README.md`, `LICENSE`, `NOTICE`, `.gitattributes`, `.gitignore`
- `PowerShellv3/chaps_PSv3.ps1`, `PowerShellv2/chaps_PSv2.ps1`, `CMD/chaps.bat`
- `docs/USAGE.md`, `docs/CHECKS.md`, `docs/INTERPRETING_REPORTS.md`, `docs/REMEDIATION.md`, `docs/ANALYSIS.md`
- `tools/chaps-analyze.ps1`, `tools/knowledge/findings.json`

### Master HEAD (8cd1715, 19 files)

v2 tag contents plus:

- Updated `README.md` title + logo block
- Updated `NOTICE` attribution line
- `images/chaps_logo_full.png`, `chaps_logo_small-letters.png`, `chaps_logo_big-letters.png`, `chaps_logo_shield_only.png`

## Recent commits

- `1d4987f` Fix CHAPS acronym expansion in dev-only files (claude-dev)
- `8cd1715` Fix CHAPS acronym expansion; add project logo to README (master, cherry-picked)
- `b310ca3` same change on claude-dev (cherry source)
- `4752ef3` Mark v2 release complete in PLAN.md and RESUME.md
- `35df259` Renormalize CMD/chaps.bat line endings per .gitattributes
- `1bb098d` **v2 TAG** -- Remove dev files for release v2 (on master only)
- `7c3983d` **dev-v2 TAG** -- Updated release process (Phase 12)
- `6ffc027` License Updated (Phase 11)

## Up Next

No active phase. Backlog items from earlier phases remain:

### Backlog (deferred from earlier phases)

- **Phase 10 third batch**: role-aware severity adjustments (DC vs. workstation vs. HMI) in the analyzer
- **Phase 10 third batch**: optional batch mode (directory of reports -> rollup analysis)
- **Phase 12 deferred**: `claude-dev/test-fleet.sh` -- single command to run all three scripts against all VMs and collect output
- **Knowledge-base expansion**: cover edge cases surfaced during real-world v2 use; add entries as users report unmatched findings

### Immediate next steps (user-facing)

- **Verify the GitHub social preview render.** Upload happened via web UI; to test how LinkedIn / Slack / Twitter will render it:
  - Paste the repo URL into LinkedIn's post composer (don't publish) -- the preview card shows exactly what followers will see
  - Same check on Twitter/X and Slack DM to yourself
  - Or use https://www.opengraph.xyz/ with `https://github.com/cutaway-security/chaps` -- pulls the current social preview without needing to paste into a real platform
  - If the image looks cropped: GitHub renders social previews at 1280x640 (2:1). A square 500x500 will be letterboxed with GitHub's background; that's normal. If it looks too tight, a future variant with horizontal padding would render better.
- **Post the LinkedIn announcement.** Draft is in the conversation (not committed to the repo).
- **Watch for issues / PRs** against v2.

### If a v2.0.1 / v2.1 release is warranted later

- All acronym and logo fixes are already on master, so the next release via `release.sh` will carry them forward automatically.
- Use `./claude-dev/release.sh 2.0.1` or `./claude-dev/release.sh 2.1`.

## Blockers

None.

## Notes for Next Session

- **Branch divergence is intentional.** Master now has 1 commit (`8cd1715`) that is NOT on claude-dev as a distinct commit -- it was cherry-picked. The *content* matches claude-dev's commit `b310ca3`. Fine. For reference:
  ```bash
  git fetch origin
  git diff origin/master..origin/claude-dev --stat
  ```
- **`.gitattributes` line-ending fight.** Switching between master and claude-dev with the BAT file's normalized state currently triggers a smudge-filter modification warning. Workaround: `git checkout -f <branch>`. Long-term fix: apply the same renormalization commit (`35df259`) to master, either by cherry-pick or in the next release. Low priority.
- **`release.sh` has been proven against a real release procedure** (v2 was executed manually, but step-for-step matches). Ready for the next release.
