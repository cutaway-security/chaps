# RESUME.md

## Current State

**Last Session**: 2026-04-14
**Branch**: claude-dev (clean, in sync with origin)
**Status**: CHAPS v2 RELEASED. All planned phases (1-12) complete.

## Release Summary

CHAPS v2 shipped to master on 2026-04-14.

- **GitHub release**: https://github.com/cutaway-security/chaps/releases/tag/v2
- **Tags**: `dev-v2` (on claude-dev, commit `7c3983d`), `v2` (on master, commit `1bb098d`)
- **Release notes**: `claude-dev/RELEASE_NOTES_v2.md` (preserved on claude-dev; stripped from master)

### What v2 contains

Three scripts with check parity (63 checks each) producing Markdown to stdout:
- `PowerShellv3/chaps_PSv3.ps1`
- `PowerShellv2/chaps_PSv2.ps1`
- `CMD/chaps.bat`

Plus:
- `tools/chaps-analyze.ps1` -- post-processing analyzer
- `tools/knowledge/findings.json` -- 59-entry analyzer knowledge base
- Public docs in `docs/`: USAGE, CHECKS, INTERPRETING_REPORTS, REMEDIATION, ANALYSIS
- `LICENSE` (GPL v3), `NOTICE` (dual-license terms)
- `.gitattributes` (defensive `export-ignore` + `*.bat text eol=crlf`)

### Release commits

- `35df259` Renormalize CMD/chaps.bat line endings per .gitattributes (post-release housekeeping on claude-dev only)
- `7c3983d` Updated release process (Phase 12)
- `6ffc027` License Updated (Phase 11)
- `2267fca` Phase 8 items 1-4: close issue/PRs, delete stale branches
- `ac432f7` Expand analysis knowledge base to 59 entries (Phase 10 second batch)

Master `v2` tag points at `1bb098d` "Remove dev files for release v2".

## Up Next

No active phase. Backlog items, in no particular order, that could be picked up next session:

### Backlog (deferred from earlier phases)

- **Phase 10 third batch**: role-aware severity adjustments (DC vs. workstation vs. HMI) in the analyzer
- **Phase 10 third batch**: optional batch mode (directory of reports -> rollup analysis)
- **Phase 12 deferred**: `claude-dev/test-fleet.sh` -- single command to run all three scripts against all VMs and collect output
- **Knowledge-base expansion**: cover edge cases surfaced during real-world v2 use; add entries as users report unmatched findings

### Post-v2 monitoring

- Watch GitHub for new issues / PRs against v2
- Track which negative findings the analyzer fails to match in real reports; feed misses back into `tools/knowledge/findings.json`
- If a v2.0.1 patch release becomes necessary: use `./claude-dev/release.sh 2.0.1` (interactive) or follow the documented manual procedure in `claude-dev/GIT_RELEASE_STEPS.md`

## Blockers

None.

## Notes for Next Session

- `release.sh` was written but the v2 release was driven manually (the script is interactive and reserved for human-driven runs). The script is now proven to match the manual procedure step-for-step and is ready for the next release.
- The `.gitattributes` `*.bat text eol=crlf` rule caused a one-time renormalization of `CMD/chaps.bat` in claude-dev after the release. Future fresh clones on Linux will check out `chaps.bat` as CRLF automatically -- the previously-recurring CMD-LF bug should be permanently prevented.
- Master and claude-dev have diverged (intentional, by design). Master is for releases only; never commit to it directly. To compare what shipped vs. what's in dev:
  ```bash
  git fetch origin
  git diff origin/master..origin/claude-dev --stat
  ```
