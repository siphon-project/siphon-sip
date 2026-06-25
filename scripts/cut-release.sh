#!/usr/bin/env bash
#
# cut-release.sh — cut a lockstep SIPhon release.
#
# The git tag is the single source of truth for the version. This script is the
# ONLY place the version is set: it bumps Cargo.toml to match the requested
# version, runs the full gate, commits, tags, and pushes. The tag push triggers
# .github/workflows/release.yaml, which fans out to crates.io (siphon-sip), PyPI
# (siphon-sip, version derived from the tag via hatch-vcs), GHCR, and a GitHub
# Release with the deb/rpm/tarball + SBOM. release.yaml's verify-version job
# refuses to publish if Cargo.toml ever drifts from the tag.
#
# Usage:
#   scripts/cut-release.sh 1.0.0
#   scripts/cut-release.sh 1.1.0-rc1
#   PERF_OK=1 scripts/cut-release.sh 1.0.0     # skip the interactive perf/mem prompt
#
# Per CLAUDE.md the performance + memory-leak baseline MUST pass before a
# release. That run is hardware-specific and long, so this script does NOT run
# it for you — it requires you to confirm it passed (or set PERF_OK=1).

set -euo pipefail

die() { echo "error: $*" >&2; exit 1; }

# ── Args ───────────────────────────────────────────────────────────────────
[ $# -eq 1 ] || die "usage: $0 <version>  (e.g. 1.0.0)"
VERSION="$1"
# Strip a leading v if the caller passed v1.0.0.
VERSION="${VERSION#v}"
echo "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$' \
  || die "version '$VERSION' is not semver (X.Y.Z or X.Y.Z-prerelease)"
TAG="v$VERSION"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# ── Preconditions ──────────────────────────────────────────────────────────
[ "$(git rev-parse --abbrev-ref HEAD)" = "main" ] || die "not on main"
[ -z "$(git status --porcelain)" ] || die "working tree not clean — commit or stash first"
git rev-parse -q --verify "refs/tags/$TAG" >/dev/null && die "tag $TAG already exists"

echo "==> fetching origin"
git fetch --quiet origin
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] \
  || die "local main is not in sync with origin/main — pull/rebase first"

# ── Correctness gate ───────────────────────────────────────────────────────
echo "==> cargo test"
PYO3_PYTHON="${PYO3_PYTHON:-python3}" cargo test --quiet

echo "==> SDK tests"
if [ -x sdk/.venv/bin/python ]; then
  ( cd sdk && .venv/bin/python -m pytest tests/ -q )
else
  ( cd sdk && python -m pytest tests/ -q )
fi

# ── Performance + memory-leak baseline (manual, per CLAUDE.md) ──────────────
if [ "${PERF_OK:-0}" != "1" ]; then
  echo
  echo "CLAUDE.md requires the 16-row perf baseline + mem-leak test to PASS"
  echo "(Failures/Retransmits == 0, allocated flat) on the README hardware before"
  echo "a release. Run them now if you haven't:"
  echo "    scripts/scale_test.sh ...        (all 16 rows)"
  echo "    scripts/mem_leak_test.sh         (and MODE=b2bua scripts/mem_leak_test.sh)"
  printf 'Have those passed on this hardware? [y/N] '
  read -r answer
  [ "$answer" = "y" ] || [ "$answer" = "Y" ] || die "aborted — run the perf/mem baseline first (or set PERF_OK=1)"
fi

# ── Set the version, commit, tag, push ─────────────────────────────────────
echo "==> setting Cargo.toml version to $VERSION"
# Only the package version (the first `version = ` under [package]).
sed -i -E "0,/^version = \".*\"/s//version = \"$VERSION\"/" Cargo.toml
# Refresh the lockfile entry so Cargo.lock doesn't drift (CI would catch it).
cargo update --quiet --package siphon-sip --precise "$VERSION" 2>/dev/null || cargo update --quiet --package siphon-sip

git add Cargo.toml Cargo.lock
git commit --quiet -m "release: $TAG"
git tag -a "$TAG" -m "Release $TAG"

echo "==> pushing main + $TAG"
git push --quiet origin main
git push --quiet origin "$TAG"

echo
echo "Released $TAG — release.yaml is now publishing crates.io + PyPI + GHCR + GitHub Release."
echo "Watch it:  gh run watch \$(gh run list --workflow=release.yaml --limit 1 --json databaseId --jq '.[0].databaseId')"
