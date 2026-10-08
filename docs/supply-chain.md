# Supply chain & SBOM

If you run SIPhon in critical infrastructure, your security and procurement teams
will ask two questions: *what is in this binary?* and *how do you know it's not
vulnerable?* This page answers both. It covers what SIPhon publishes with every
release, how to consume it in your own scanning pipeline, and how vulnerabilities
are tracked and reported.

This is the operator/procurement view. For **runtime** hardening of a live proxy —
rate limiting, scanner blocking, TLS, auth — see
[Hardening & security](cookbook/security.md).

- [Software Bill of Materials (SBOM)](#software-bill-of-materials-sbom)
- [Consuming the SBOM](#consuming-the-sbom)
- [Generating an SBOM yourself](#generating-an-sbom-yourself)
- [Dependency vulnerability monitoring](#dependency-vulnerability-monitoring)
- [Reporting a vulnerability](#reporting-a-vulnerability)
- [Known gaps](#known-gaps)

---

## Software Bill of Materials (SBOM)

Every tagged release from **v1.0.0** onward ships a full SBOM in **two industry
formats**, generated from the exact dependency graph that built the release
artifacts and attached to the [GitHub Release](https://github.com/siphon-project/siphon-sip/releases):

| Format | Spec version | Asset name |
| --- | --- | --- |
| **SPDX** | SPDX 2.3 (JSON) | `siphon-sip-vX.Y.Z.spdx.json` |
| **CycloneDX** | CycloneDX 1.4 (JSON) | `siphon-sip-vX.Y.Z.cdx.json` |

Both are produced by [`cargo-sbom`](https://github.com/psastras/sbom-rs) in CI as
part of the release workflow, so they reflect the resolved `Cargo.lock` for that
tag — every crate, its version, and its license. Two formats because scanners and
compliance tools differ in what they ingest: SPDX is the ISO/IEC 5962 standard and
what most license-compliance tooling expects; CycloneDX is what most
vulnerability scanners (Grype, Trivy, Dependency-Track) consume natively.

!!! note "What the SBOM covers"
    The SBOM enumerates the **Rust dependency graph** of the `siphon-sip` crate.
    SIPhon also links a few C libraries (libsctp, jemalloc, netlink) and embeds
    CPython via PyO3 — those system/interpreter components are outside the Cargo
    graph and are not enumerated per-package by `cargo-sbom`. Pin and scan them
    through your base image / OS package manager as usual.

---

## Consuming the SBOM

Download the format your tooling prefers from the release assets, then feed it in.
A few common flows:

**Scan for known vulnerabilities with [Grype](https://github.com/anchore/grype):**

```bash
grype sbom:./siphon-sip-v1.0.0.cdx.json
```

**Scan with [Trivy](https://github.com/aquasecurity/trivy):**

```bash
trivy sbom ./siphon-sip-v1.0.0.cdx.json
```

**Continuous monitoring with [Dependency-Track](https://dependencytrack.org/):**
upload the CycloneDX document to a project via the API or UI, and it re-evaluates
the component list against new advisories over time — no re-scan of the binary
needed.

**License compliance:** feed the SPDX document to your compliance tool of choice
(FOSSA, ORT, or a simple `jq` over the `licenseConcluded` fields). SIPhon and its
dependencies are OSI-permissive by policy (see below).

---

## Generating an SBOM yourself

The release SBOM is not magic — you can reproduce it from any checkout, which is
useful for a fork, an unreleased commit, or verifying the published document:

```bash
cargo install cargo-sbom

cargo sbom --output-format spdx_json_2_3      > siphon-sip.spdx.json
cargo sbom --output-format cyclone_dx_json_1_4 > siphon-sip.cdx.json
```

Because the output is derived from `Cargo.lock`, a checkout of the same tag
produces an equivalent component list to the published asset.

---

## Dependency vulnerability monitoring

An SBOM is a snapshot; advisories are continuous. A crate that was clean at
release time can have an advisory filed against it a week later without a single
line of code changing. SIPhon handles that with a scheduled
[`cargo-deny`](https://embarkstudios.github.io/cargo-deny/) audit rather than a
one-time gate:

- **RustSec advisories** are checked **weekly** (Mondays) and on any change to the
  dependency set (`Cargo.toml` / `Cargo.lock` / `deny.toml`) in
  [`.github/workflows/audit.yml`](https://github.com/siphon-project/siphon-sip/blob/main/.github/workflows/audit.yml).
  A new advisory surfaces here within a week even if no code changed — which is
  exactly why it's a schedule, not a per-PR check.
- **A yanked crate fails the audit** (`yanked = "deny"`).
- **License policy is enforced** — dependencies must resolve to an OSI-permissive
  license from an explicit allow-list (MIT, Apache-2.0, BSD, ISC, MPL-2.0, …).
- **Source policy is enforced** — crates must come from crates.io; unknown
  registries and unknown git sources are denied.

The full policy lives in
[`deny.toml`](https://github.com/siphon-project/siphon-sip/blob/main/deny.toml).
You can run the same checks against your own checkout:

```bash
cargo install cargo-deny
cargo deny check              # advisories + licenses + sources + bans
```

---

## The bundled Python interpreter

The `.deb`, the `.rpm` and the release tarballs carry their own free-threaded
CPython, installed under `/usr/lib/siphon/python` (`python/` next to the binary
in the tarball). It is a
[python-build-standalone](https://github.com/astral-sh/python-build-standalone)
build, which is relocatable where a distribution's Python is not.

- **Pinned by version and SHA-256** in
  [`scripts/bundle-python.sh`](https://github.com/siphon-project/siphon-sip/blob/main/scripts/bundle-python.sh).
  The release fetches exactly that archive and refuses anything whose checksum
  differs, so moving to another build is a reviewed change to that file.
- **It is patched by a SIPhon release, not by your distribution.** A CPython
  security fix reaches an installed package only when a SIPhon release picks up
  the new interpreter. `siphon` logs the exact version at startup (the `python
  runtime` line).
- **Its licences ship with it**, as `LICENSE.txt` in the bundle root: CPython's
  own and those of the libraries built into it (OpenSSL, SQLite, and so on).
- **It is not in the SBOM**, which describes the Rust crate graph only (see
  [Known gaps](#known-gaps)).

Packages you add with the bundled `pip` are yours to track.

---

## Reporting a vulnerability

Please report security issues **privately** — do not open a public GitHub issue
for a suspected vulnerability. See
[`SECURITY.md`](https://github.com/siphon-project/siphon-sip/blob/main/SECURITY.md)
for the disclosure process. In short: use GitHub's
[private vulnerability reporting](https://github.com/siphon-project/siphon-sip/security/advisories/new)
on the repository's **Security** tab, or reach the maintainer through
[Real Time Telecom](https://realtime-telecom.nl). You'll get an acknowledgement and
a coordinated-disclosure timeline.

---

## Known gaps

Stated honestly, because a supply-chain page that overclaims is worse than none:

- **No container-image SBOM/provenance yet.** The published SBOM describes the
  Rust crate graph, not the Docker image layers. Image-level SBOM and SLSA build
  provenance (via `docker buildx --sbom=true --provenance=true`) are not yet
  wired. Until they are, scan the published image with your registry scanner and
  treat the crate SBOM as the authoritative component list for the SIPhon binary
  itself.
- **The bundled Python interpreter is not in the SBOM.** The packages and
  tarballs ship a CPython and the C libraries built into it; neither appears in
  the published SBOM. Its version and checksum are in `scripts/bundle-python.sh`
  at the release tag.
- **No cryptographic signing of release artifacts yet.** Artifacts are published
  through GitHub Releases and OIDC Trusted Publishing to crates.io / PyPI (no
  long-lived tokens), but the tarballs/SBOMs are not yet Sigstore-signed. Verify
  by matching the SBOM to a `cargo sbom` of the corresponding tag.

## See also

- [Hardening & security](cookbook/security.md) — runtime hardening of a live proxy.
- [Deployment & operations](deployment.md) — the production runbook these artifacts slot into.
