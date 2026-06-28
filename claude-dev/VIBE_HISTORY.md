# VIBE_HISTORY.md

AI session-continuity memory. Claude writes and reads this file for continuity
across sessions; it is not a document you are expected to maintain by hand.
Newest entry first. Durable decisions and lessons accumulate here over the
project's lifetime.

---

## 2026-06-28 -- Migrated to the RESUME-retired model (PLAN + VIBE_HISTORY)

**What landed**

- `claude-dev/RESUME.md` -- **retired and removed.** CHAPS now follows the current
  Cutaway model: PLAN.md carries the working state, VIBE_HISTORY carries the
  decision trail and the resume pointer. RESUME's durable content was already in
  the v2 entry below; its live next-steps moved to PLAN's Current Phase.
- `claude-dev/PLAN.md` -- Current Phase block gained **Next Steps** (verify the v2
  social preview, post the LinkedIn announcement, watch for v2 issues) and
  **Blockers: None**.
- `CLAUDE.md` -- session protocol now reads CLAUDE -> ARCHITECTURE -> PLAN ->
  VIBE_HISTORY; doc-update table and Session Workflow repointed off RESUME.
- `claude-dev/ARCHITECTURE.md`, `GIT_RELEASE_STEPS.md`, `TESTING_STANDARD.md`,
  and `release.sh` (preflight checklist) repointed off RESUME.

**Durable decisions**

- CHAPS adopts the framework-wide RESUME retirement codified on 2026-06-28. The
  model was piloted on the live cutsec_website project, then rolled into
  `templates/common/` and the `cutsec-init` skill; CHAPS is the first existing
  project migrated to it.
- No source or script logic (PSv2/PSv3/CMD, the analyzer) changed -- this is a
  dev-doc and process-doc migration only. RESUME was dev-only and stripped at
  release, so master is unaffected.

**Next session**

- v2 is released and stable; no active phase. Immediate items are the post-release
  user-facing next steps now tracked in PLAN's Current Phase. Backlog (Phase 10
  role-aware severity and batch mode, Phase 12 `test-fleet.sh`, knowledge-base
  expansion) lives in the PLAN phase sections.

---

## 2026-06-28 -- claude-dev prepped for skills + VIBE_HISTORY

**What landed**

- `claude-dev/VIBE_HISTORY.md` -- this file, added so CHAPS carries the AI
  session-continuity memory the current Cutaway framework expects. Seeded with
  this entry plus a backfilled v2-release entry (below).
- `CLAUDE.md` -- VIBE_HISTORY wired into the session protocol: added to the
  "Essential Documents (Read in Order)" list, the "Documentation Updates
  Required" table (durable decision or lesson -> VIBE_HISTORY), and the Session
  Workflow start/end steps. Added a "Tooling / Skills" section and a `humanizer`
  note in Communication Style.

**Durable decisions**

- CHAPS adopts the Cutaway framework skills mid-project. `cutsec-init` is not
  used -- the project is already populated and the skill refuses a populated
  `claude-dev/`. The other skills apply to ongoing work.
- `multi-ai-code-review` is used during CHAPS **update planning and
  implementation** (architecture mode for plans and analyzer/check changes;
  diagnostic mode for false-positive root-cause against a CHAPS scan report or
  `claude-dev/results/*.md`).
- CHAPS development is **not** sensitive. CHAPS source, plans, and scan output
  from the CutSec test environment are fine to send to `multi-ai-code-review`.
  Client data is not part of CHAPS development; CutSec test-environment output
  must not be mistaken for sensitive material.
- `VIBE_HISTORY.md` is `claude-dev`-only and is stripped at release, same as
  `RELEASE_NOTES_v2.md` and the rest of `claude-dev/` (`.gitattributes`
  `export-ignore`).

**Lessons**

- The `claude-dev` branch name collides with the `claude-dev/` directory in git
  CLI calls; disambiguate with `refs/heads/claude-dev` or `-- ` when scripting.

**Project context**

- Sibling project ICSWatchDog: CHAPS reuses its Proxmox VM fleet (Win7/10/11,
  Server 2016/2019/2022), its SSH-based remote-testing standard, and its
  dual-license pattern (CHAPS uses GPL v3 as the open half; ICSWatchDog uses
  CC BY-SA because it ships content, not software).

**Next session**

- Next-phase scope is to be set in a dedicated CHAPS coding session. This prep
  session intentionally records no next-phase ideas.

---

## 2026-04-14 -- CHAPS v2 released

**What landed**

- CHAPS v2 shipped to `master` and a same-day branding follow-up landed
  (acronym expansion corrected to "Configuration Hardening Assessment PowerShell
  Scripts"; project logos added to README and GitHub social preview).
- Three assessment scripts at parity: `PowerShellv3/chaps_PSv3.ps1` (reference),
  `PowerShellv2/chaps_PSv2.ps1`, `CMD/chaps.bat` -- 63 canonical checks each,
  markdown to stdout.
- `tools/chaps-analyze.ps1` post-processing analyzer plus
  `tools/knowledge/findings.json` (59-entry knowledge base; 94-100% coverage on
  test reports).
- Public docs set under `docs/` (USAGE, CHECKS, INTERPRETING_REPORTS,
  REMEDIATION, ANALYSIS); dual-license posture (GPL v3 + commercial) in
  `LICENSE` and `NOTICE`.
- Release tooling: `.gitattributes` (`export-ignore` for `claude-dev/` and
  `CLAUDE.md`; `*.bat text eol=crlf`) and `claude-dev/release.sh` (preflight +
  dev-file strip; force-push to main stays manual).

**Release artifacts**

- GitHub release: https://github.com/cutaway-security/chaps/releases/tag/v2
- Tags: `dev-v2` (claude-dev, `7c3983d`), `v2` (master, `1bb098d` -- immutable,
  15-file ship list).
- master HEAD advanced to `8cd1715` (v2 + acronym fix + 4 logo images = 19
  files) via cherry-pick of the user-facing branding subset; the dev-only half
  of the branding fix stayed on claude-dev (`1d4987f`). master advancing past
  the v2 tag is expected -- master is the live default branch, not a snapshot.

**Durable decisions**

- PSv3 is the reference implementation; PSv2 and CMD are ports held at check
  parity (canonical order in `claude-dev/CANONICAL_CHECKS.md`).
- Single markdown stream to stdout; users redirect or copy. No Tee-Object, no
  output-file management inside the scripts.
- One neutral analysis tool (not separate defender/attacker tools): AI tooling
  reframes neutral structured facts per audience; one knowledge base is cheaper
  to maintain. PowerShell, not Python, to avoid a second runtime for OT admins.
- Dual-license GPL v3 + commercial: running CHAPS is use, not distribution, and
  a report is not a derivative work; copyleft is the lever against proprietary
  bundlers. (Full rationale in PLAN.md Decision Log.)

**Lessons**

- Windows CMD silently skips lines in an LF-terminated batch file. The
  `*.bat text eol=crlf` `.gitattributes` rule exists to prevent recurrence;
  switching branches can trigger a smudge-filter modification warning on
  `CMD/chaps.bat` -- workaround `git checkout -f <branch>`.

**Project history at a glance**

Exact SHAs and timestamps live in `git log`; this is the narrative arc.

- **Origin (community CHAPS):** began as a single PSv3 assessment script and
  evolved through community pull requests -- PowerSploit removal, output-directory
  changes, and typo/grammar passes -- up to the commit that added the `claude-dev`
  development infrastructure.
- **claude-dev rebuild (Phases 1-13):** consolidated divergent branches (1) and
  fixed PSv3 bugs/stubs and added hardening checks (2-3); converted PSv3 output
  to markdown (4); established the ICSWatchDog-aligned Proxmox/SSH testing
  standard (5); built PSv2 and CMD at parity (6-7); closed issues/PRs and ran the
  full VM fleet test, then tagged and shipped (8); added four privesc/exposure
  checks taking the set 59 -> 63 (9); built `chaps-analyze.ps1` and grew the
  knowledge base to 59 entries (10); adopted the dual-license posture and
  standardized headers (11); added `.gitattributes`/`release.sh` release tooling
  (12); and corrected acronym/branding post-release (13).

**Next session**

- v2 is released and stable. No active phase. Deferred backlog: role-aware
  severity adjustments (DC vs. workstation vs. HMI) in the analyzer; optional
  batch/rollup analysis mode; `claude-dev/test-fleet.sh`; and knowledge-base
  expansion as real-world v2 use surfaces unmatched findings.
