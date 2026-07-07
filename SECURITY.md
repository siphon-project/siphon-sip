# Security Policy

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
discussions, or pull requests.**

Report privately through either channel:

- **Preferred:** GitHub [private vulnerability reporting](https://github.com/siphon-project/siphon-sip/security/advisories/new)
  — the **"Report a vulnerability"** button on the repository's **Security** tab.
- **Alternative:** reach the maintainer through
  [Real Time Telecom B.V.](https://realtime-telecom.nl).

Please include enough detail to reproduce: affected version or commit, a
description of the issue and its impact, and a proof of concept or steps to
trigger it where possible.

## What to expect

- **Acknowledgement** of your report within a few business days.
- An assessment and, for confirmed issues, a **coordinated-disclosure timeline**.
- Credit in the release notes and advisory when a fix ships, unless you prefer to
  remain anonymous.

Please give us reasonable time to investigate and release a fix before any public
disclosure.

## Supported versions

SIPhon is pre-1.0 and versioned in lockstep across the `siphon-sip` crate and the
`siphon-sip` Python SDK (driven by the git tag). Security fixes ship in the
**latest release**; there are no long-term-support branches yet. Run the latest
tagged version to stay current on fixes.

## Supply chain

Every tagged release ships an SBOM (SPDX + CycloneDX), and dependency advisories
are audited on a schedule with `cargo-deny`. See
[Supply chain & SBOM](https://siphon-sip.org/supply-chain/) for how to consume the
SBOM and reproduce the audit.
