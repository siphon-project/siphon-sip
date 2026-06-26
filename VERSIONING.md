# Versioning

SIPhon (`siphon-sip`) follows [Semantic Versioning 2.0.0](https://semver.org/),
with one hard rule below.

## Lockstep — one version, everywhere, always

The **crate** (`siphon-sip` on crates.io), the **`siphon` binary**, the **Docker
image** (`ghcr.io/siphon-project/siphon-sip`), and the **Python SDK**
(`siphon-sip` on PyPI) **always carry the same version.** There is no
independent SDK version — the SDK version *is* the SIPhon version, by
construction.

The **git tag is the single source of truth**, and it cannot drift, because
nothing stores a hand-edited version that could disagree with it:

| Surface | How it gets its version |
|---|---|
| crate / binary / image | `Cargo.toml` `version`, set **only** by `scripts/cut-release.sh` to match the tag |
| SDK (PyPI) | derived **directly from the git tag** via `hatch-vcs` — there is deliberately no `version =` line in `sdk/pyproject.toml` |
| guard | `release.yaml`'s `verify-version` job **refuses to publish** if `Cargo.toml` ≠ the tag |

➡️ **Never hand-edit a version.** To release, run `scripts/cut-release.sh X.Y.Z`
— it is the *only* thing that sets `Cargo.toml`, commits `release: vX.Y.Z`,
tags, and pushes. The tag push publishes crate + SDK + image + GitHub Release,
all at `X.Y.Z`, in lockstep.

## What a version protects (the public contract)

A bump reflects the **highest-severity change across any of these surfaces** in
the release:

1. **Python scripting API** — `from siphon import …`: every documented
   decorator, namespace, method, and property. *This is the primary
   contract — operators' routing scripts depend on it.*
2. **`siphon.yaml` config schema** — documented keys and their semantics.
3. **CLI flags + documented runtime behavior.**
4. **`siphon-sip` SDK surface** — mirrors (1).

**Out of contract:** the Rust crate's `pub` API. SIPhon is a platform/binary,
not a library; the crate is published for installability (`cargo install
siphon-sip`) and ecosystem presence, not as a stable library API — it may
change in **minor** releases. If you depend on `siphon-sip` as a crate, pin an
exact version.

## The rule

**MAJOR (`X.0.0`)** — breaks a protected surface:

- Remove / rename / incompatibly change a scripting method, namespace,
  decorator, or signature.
- Remove / rename / repurpose a config key.
- Remove a CLI flag, or change a default in a way that breaks existing
  deployments.
- Removals happen only **one major after** a deprecation.

**MINOR (`x.Y.0`)** — backward-compatible additions:

- New scripting API, namespaces, decorators; new config keys (with safe
  defaults); new CLI flags.
- New IMS interfaces / protocol features.
- **Deprecations** — mark deprecated, keep it working (removal is the next
  major).
- MSRV bump (called out in the changelog).

**PATCH (`x.y.Z`)** — backward-compatible fixes:

- Bug fixes, security fixes, performance improvements, behavior-neutral
  dependency bumps.
- **RFC / 3GPP standards-compliance corrections** — *even when they change
  observable wire behavior.* SIPhon's contract is "standards-compliant", so a
  correction toward the spec is a fix, not a break. **Document it loudly in the
  changelog.**

## Special cases

- **Pre-releases:** `X.Y.Z-rc.N` to validate against a live IMS estate before
  the stable tag (`cut-release.sh` accepts the `-prerelease` form). Docker
  `latest` and the crates.io "newest" pointer advance only on **stable**
  releases, never pre-releases.
- **Security:** ship as a PATCH, expedited; backport to the supported line.
- **Performance is not a version decision — it is a release gate.** Every
  release must re-run the 16-row README perf baseline with **0 Failed / 0
  Retransmits** on every row (see `CLAUDE.md`). A perf *improvement* that raises
  the floor → PATCH + update the README table.
- **Lockstep cost:** a docs-only or SDK-only change still bumps everything
  (PATCH). Accepted — one number across the whole project is worth it.

## Maintenance

Once there are production deployments, keep a `release/X.x` branch and backport
security + critical correctness fixes as `X.x.(z+1)` while `main` advances to
`X.(y+1)` / `(X+1).0`. Deferred until actually needed.
