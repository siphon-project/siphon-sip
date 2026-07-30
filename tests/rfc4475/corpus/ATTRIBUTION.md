# RFC 4475 torture-test corpus — provenance

## What these files are

The 50 `.dat` files in this directory are the SIP test messages from
**RFC 4475, "Session Initiation Protocol (SIP) Torture Test Messages"**
(R. Sparks, A. Hawrylyshen, A. Johnston, J. Rosenberg, H. Schulzrinne;
IETF, May 2006), section 3.

They are stored byte-exact and are *not* to be reformatted, re-indented, or
line-ending-normalised. The messages are deliberately adversarial about
whitespace, header folding, escaping, embedded nulls and binary bodies, which
is precisely what any normalisation destroys. Several of them would stop
testing anything if touched:

- `TC_WSINV.dat` — folded headers, mixed header-name case, escaped quotes in a
  display name, whitespace in unusual positions.
- `TC_MPART01.dat` — multipart MIME with a binary PKCS#7 part. Contains NUL
  bytes and bare `0x0D` octets *inside the body*, which are message content,
  not line endings.
- `TC_INTMETH.dat` — a method name and Request-URI built from the full set of
  characters the grammar permits.
- `TC_ESCNULL_V.dat` — escaped nulls in URIs.

A repository-level `.gitattributes` marks `*.dat` here as binary so that no
end-of-line conversion is applied on checkout or commit.

## Licence

RFC 4475 is an IETF RFC. Reproduction of RFC text is governed by the IETF
Trust Legal Provisions (BCP 78); the messages reproduced here are the test
vectors the RFC exists to publish, and are used for their stated purpose.

Full RFC: <https://www.rfc-editor.org/rfc/rfc4475.txt>

## How they were obtained

The RFC renders some messages with meta-notation (`<allOneLine>`,
`<repeat count=...>`) rather than literal bytes, so the machine-readable form
was taken from the ETSI TTCN-3 SIP library's codec validation corpus rather
than transcribed from the RFC text:

- Source: `LibSip/codec/validation/TortureTests/data/`
- Repository: <https://forge.etsi.org/rep/LIBS/LibSip.git>
- Branch/tag: `v1.7.0`
- Commit: `a1295ce03447f4b130b660b54ac49470a799d929`
- Retrieved: 2026-07-29

Note that the LibSip repository ships no licence file of its own. The BSD-3-Clause
notice that covers the ETSI IMS test suites lives in a *different* repository
(`IMS_CON_BC/LICENSE`, "Copyright 2019 ETSI") and does not appear here. This is
why the licensing position above rests on RFC 4475 as the origin of the content
rather than on ETSI's redistribution of it.

## Filenames

The upstream `TC_<name>_V` / `TC_<name>_I` filenames are preserved verbatim so
each fixture can be traced back to its source. **The `_V` / `_I` suffix is not
used as the test oracle**, because it records whether the upstream project's own
TTCN-3 codec decodes the message, which is not the same question as RFC 4475's
verdict. The two disagree on 13 of the 50 files:

- Nine `_V`-suffixed files are RFC 4475 §3.1.2 *invalid* messages:
  `baddate`, `badvers`, `bigcode`, `escruri`, `lwsstart`, `mismatch01`,
  `mismatch02`, `scalar02`, `scalarlg`. The upstream suite annotates one of
  these itself: *"NOTE: TC_ESCRURI_V is defined as a negative test"*.
- Four `_I`-suffixed files are RFC 4475 §3.3/§3.4 messages that parse cleanly
  and are rejected at the application layer, not the parser: `insuf` (§3.3.1,
  missing To/From/Call-ID), `inv2543` (§3.4.1), `mcl01` (§3.3.9),
  `multi01` (§3.3.8).

`TC_TEST_I.dat` is not an RFC 4475 message at all — it is an addition carried by
the upstream corpus (it references `jasomi.com`, absent from the RFC). It is
malformed on its own terms: no SIP-Version on the request line, and a header
line with no colon.

Classification therefore keys off the RFC section each message comes from. See
the `CORPUS` table in `../corpus_tests.rs`.
