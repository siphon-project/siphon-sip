#!/usr/bin/env bash
#
# Point siphon-bin's siphon-sip dependency at this checkout, and prove it took.
#
# Every official artifact — container image, .deb, .rpm, release tarball — is
# built from the siphon-bin package rather than the plain siphon-sip one, so
# that the scriptable `http` namespace is compiled in. But siphon-bin git-deps
# siphon-sip at branch=main and its Cargo.lock pins a SHA, so without this the
# artifact released as vX.Y.Z would contain whatever `main` happened to be
# instead of that tag's lib. Release and image builds both run this first.
#
# One [patch] entry covers the whole graph: siphon-bin and every extension crate
# are required to spell the repo URL byte-identically (cargo does not follow
# GitHub's rename redirect and would otherwise resolve two separate copies of
# siphon-sip), so patching that single source catches siphon-http's edge too.
#
# The config is written here and never committed — the siphon-bin CI legs build
# against the git deps deliberately, as a bit-rot guard, and a committed patch
# would void that.
#
# Running this locally DOES rewrite the tracked siphon-bin/Cargo.lock, because
# re-resolving is the only way to make the patch bite (see below). That is
# invisible in CI, where checkouts are throwaway, but it dirties a local tree —
# and cut-release.sh refuses to cut with a dirty tree. Undo with:
#     git checkout siphon-bin/Cargo.lock && rm -rf siphon-bin/.cargo
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO_ROOT/siphon-bin"

mkdir -p .cargo
{
    echo '[patch."https://github.com/siphon-project/siphon-sip"]'
    echo 'siphon-sip = { path = ".." }'
} > .cargo/config.toml

# A [patch] is IGNORED when Cargo.lock already pins that dependency: cargo says
# "patch ... was not used in the crate graph" as a WARNING and cheerfully builds
# the git copy. Re-resolving this one package is what makes the patch bite.
cargo update -p siphon-sip

# And because the failure mode above is a warning rather than an error, assert
# the outcome instead of trusting it. A git-sourced siphon-sip in the graph here
# means the artifact would not be built from this tree — which is the entire
# bug this script exists to prevent, and it would be invisible in the log noise.
if cargo tree --invert siphon-sip | grep -q 'siphon-sip v.*(https://'; then
    echo "error: siphon-sip resolved from git, not from $REPO_ROOT." >&2
    echo "       The [patch] did not apply, so this build would not be the released tree." >&2
    cargo tree --invert siphon-sip >&2
    exit 1
fi

echo "siphon-sip pinned to $REPO_ROOT:"
cargo tree --invert siphon-sip
