#!/usr/bin/env bash
#
# claude-dev/release.sh
#
# Automates Steps 1-5 of GIT_RELEASE_STEPS.md and stops before any
# destructive action. Force-pushing to main and tagging the release on
# main are printed as copy-paste commands for you to run manually.
#
# Usage: ./claude-dev/release.sh <version>
#        e.g. ./claude-dev/release.sh 2
#
# Run from the repo root.

set -euo pipefail

# ----- args -----
if [ $# -ne 1 ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 2"
    exit 1
fi

VERSION="$1"
DEV_TAG="dev-v${VERSION}"
REL_TAG="v${VERSION}"
REL_BRANCH="release-v${VERSION}"

# ----- output helpers -----
if [ -t 1 ]; then
    RED=$'\033[0;31m'
    YELLOW=$'\033[0;33m'
    GREEN=$'\033[0;32m'
    BOLD=$'\033[1m'
    RESET=$'\033[0m'
else
    RED=""; YELLOW=""; GREEN=""; BOLD=""; RESET=""
fi

say()  { echo "${BOLD}$*${RESET}"; }
ok()   { echo "  ${GREEN}OK${RESET}: $*"; }
warn() { echo "  ${YELLOW}WARN${RESET}: $*"; }
die()  { echo "${RED}ERROR${RESET}: $*" >&2; exit 1; }

confirm() {
    local reply
    read -r -p "$1 [y/N] " reply
    [ "$reply" = "y" ] || [ "$reply" = "Y" ]
}

# ----- preflight -----
say "=== Preflight checks ==="

[ -d ".git" ] || die "Must be run from the repo root (no .git directory here)"

CUR_BRANCH=$(git rev-parse --abbrev-ref HEAD)
[ "$CUR_BRANCH" = "claude-dev" ] || die "Must be on claude-dev branch (currently on $CUR_BRANCH)"
ok "On claude-dev branch"

if [ -n "$(git status --porcelain)" ]; then
    die "Working tree is not clean. Commit or stash changes first."
fi
ok "Working tree is clean"

if git rev-parse "$DEV_TAG" >/dev/null 2>&1; then
    die "Tag $DEV_TAG already exists. Pick a different version or delete the tag."
fi
ok "Tag $DEV_TAG does not yet exist"

if git rev-parse "$REL_TAG" >/dev/null 2>&1; then
    die "Tag $REL_TAG already exists. Pick a different version."
fi
ok "Tag $REL_TAG does not yet exist"

if git show-ref --quiet "refs/heads/$REL_BRANCH"; then
    die "Branch $REL_BRANCH already exists. Delete it or pick a different version."
fi
ok "Branch $REL_BRANCH does not yet exist"

if git fetch origin claude-dev >/dev/null 2>&1; then
    LOCAL=$(git rev-parse claude-dev)
    REMOTE=$(git rev-parse origin/claude-dev 2>/dev/null || echo "")
    if [ -n "$REMOTE" ] && [ "$LOCAL" != "$REMOTE" ]; then
        die "Local claude-dev differs from origin/claude-dev. Push or pull first."
    fi
    ok "claude-dev is in sync with origin"
else
    warn "Could not fetch origin/claude-dev (offline?). Continuing."
fi

# ----- manual checklist -----
echo ""
say "=== Manual pre-release checklist ==="
echo "Confirm each of the following is true before proceeding:"
echo "  - PLAN.md reflects current completion status"
echo "  - RESUME.md is up to date with this release's work"
echo "  - README.md is accurate for the public release"
echo "  - LICENSE and NOTICE files are current and present"
echo "  - README Project License section matches NOTICE"
echo "  - No sensitive data, credentials, or internal references in shipping files"
echo "  - All three scripts (PSv3, PSv2, CMD) produce expected output"
echo "  - tools/chaps-analyze.ps1 runs cleanly against a sample report"
echo ""
if ! confirm "All of the above confirmed?"; then
    die "Aborted. Update the items above, then re-run."
fi

# ----- automated content checks -----
echo ""
say "=== Automated checks ==="

MISSING_HDR=0
for f in PowerShellv3/chaps_PSv3.ps1 PowerShellv2/chaps_PSv2.ps1 CMD/chaps.bat tools/chaps-analyze.ps1; do
    if ! grep -q "Cutaway Security, LLC" "$f"; then
        echo "  MISSING copyright header: $f"
        MISSING_HDR=$((MISSING_HDR+1))
    fi
done
[ $MISSING_HDR -eq 0 ] || die "$MISSING_HDR script(s) missing standardized copyright header"
ok "All scripts carry the standardized Cutaway Security, LLC copyright header"

TBD_HITS=$(grep -rn '\[TBD\]' README.md docs/ tools/ PowerShellv3/ PowerShellv2/ CMD/ 2>/dev/null || true)
if [ -n "$TBD_HITS" ]; then
    echo "$TBD_HITS"
    warn "Found [TBD] markers in shipping files (see above)"
    if ! confirm "Proceed anyway?"; then
        die "Aborted. Resolve [TBD] markers, then re-run."
    fi
else
    ok "No [TBD] markers in shipping files"
fi

# ----- Step 2: tag claude-dev -----
echo ""
say "=== Step 2: Tag claude-dev as $DEV_TAG ==="
read -r -p "Brief description for the tag message: " TAG_MSG
[ -n "$TAG_MSG" ] || die "Tag message cannot be empty"

git tag -a "$DEV_TAG" -m "Release v${VERSION}: ${TAG_MSG}"
ok "Created tag $DEV_TAG locally"

git push origin "$DEV_TAG"
ok "Pushed $DEV_TAG to origin"

# ----- Step 3: release branch -----
echo ""
say "=== Step 3: Create $REL_BRANCH ==="
git checkout -b "$REL_BRANCH"
ok "Checked out $REL_BRANCH"

# ----- Step 4: remove dev files -----
echo ""
say "=== Step 4: Remove development files ==="
git rm -rq claude-dev/
git rm -q CLAUDE.md
ok "Dev files removed (claude-dev/, CLAUDE.md)"

git commit -q -m "Remove dev files for release v${VERSION}"
ok "Release commit created"

# ----- Step 5: verify -----
echo ""
say "=== Step 5: Verify release branch ==="

MISSING=0
for required_file in README.md LICENSE NOTICE \
                     PowerShellv3/chaps_PSv3.ps1 \
                     PowerShellv2/chaps_PSv2.ps1 \
                     CMD/chaps.bat \
                     tools/chaps-analyze.ps1 \
                     tools/knowledge/findings.json; do
    if [ ! -f "$required_file" ]; then
        echo "  MISSING FILE: $required_file"
        MISSING=$((MISSING+1))
    fi
done
for required_dir in docs PowerShellv3 PowerShellv2 CMD tools tools/knowledge; do
    if [ ! -d "$required_dir" ]; then
        echo "  MISSING DIR: $required_dir"
        MISSING=$((MISSING+1))
    fi
done
[ $MISSING -eq 0 ] || die "$MISSING required items missing from release branch"
ok "All required user-facing files present"

ABSENT_VIOLATIONS=0
for forbidden in claude-dev CLAUDE.md; do
    if [ -e "$forbidden" ]; then
        echo "  STILL PRESENT: $forbidden"
        ABSENT_VIOLATIONS=$((ABSENT_VIOLATIONS+1))
    fi
done
[ $ABSENT_VIOLATIONS -eq 0 ] || die "$ABSENT_VIOLATIONS dev items still present on release branch"
ok "All dev items absent"

# ----- manual commands -----
echo ""
say "=============================================================="
say "  Release branch $REL_BRANCH is ready."
say "=============================================================="
echo ""
echo "Review before shipping:"
echo ""
echo "    git log --stat $REL_BRANCH | head -40"
echo "    git diff main..$REL_BRANCH --stat"
echo "    git ls-tree -r $REL_BRANCH --name-only | grep -E '^(claude-dev|CLAUDE)' || echo OK"
echo ""
echo "When you are satisfied, ship the release by running these commands"
echo "MANUALLY. Force-push to main is never automated."
echo ""
echo "    # Step 6: Force-push to main"
echo "    git checkout main"
echo "    git reset --hard $REL_BRANCH"
echo "    git push origin main --force"
echo ""
echo "    # Step 7: Tag the release on main"
echo "    git tag -a $REL_TAG -m \"Release v${VERSION}\""
echo "    git push origin $REL_TAG"
echo ""
echo "    # Step 8: Clean up the local release branch"
echo "    git checkout claude-dev"
echo "    git branch -d $REL_BRANCH"
echo ""
echo "    # Step 9: Create the GitHub release"
echo "    gh release create $REL_TAG --title \"v${VERSION}\" --notes-file <release-notes-file>"
echo ""
echo "If something looks wrong, abandon the release with:"
echo ""
echo "    git checkout claude-dev"
echo "    git branch -D $REL_BRANCH"
echo "    git tag -d $DEV_TAG"
echo "    git push origin :refs/tags/$DEV_TAG"
echo ""
