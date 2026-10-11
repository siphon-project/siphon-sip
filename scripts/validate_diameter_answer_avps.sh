#!/usr/bin/env bash
#
# Validate a script-built Diameter answer that repeats a top-level AVP against
# Wireshark's Diameter dissector.
#
# The tests in src/script/api/diameter_server.rs read the answer back with the
# decoder that shares a dictionary with the encoder. This feeds tshark a Cx
# Multimedia-Auth-Answer (TS 29.229) whose two SIP-Auth-Data-Item AVPs were
# appended with `DiameterAnswer.insert_avp`, and asserts tshark, with its own
# dictionary, finds both, in order, each with its members, and the
# Vendor-Specific-Application-Id and Auth-Session-State that
# `DiameterRequest.answer` copies from the request.
#
#   scripts/validate_diameter_answer_avps.sh
#
# Needs tshark and text2pcap (wireshark-common). CI runners have neither, so
# run it locally after touching the AVP builders in
# src/script/api/diameter_server.rs.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# tshark is commonly AppArmor-confined to a short list of readable paths, and a
# checkout under $HOME is often not on it, so the capture lives under TMPDIR.
WORK="${TMPDIR:-/tmp}/siphon-diameter-answer-validation"
HEX="$WORK/answer.hex"
PCAP="$WORK/answer.pcap"

for tool in tshark text2pcap; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "$tool not found, install wireshark-common" >&2
    exit 1
  fi
done

mkdir -p "$WORK"
rm -f "$HEX" "$PCAP"

echo "building the answer the way a script does"
SIPHON_DIAMETER_ANSWER_HEX_OUT="$HEX" \
  PYO3_PYTHON="${PYO3_PYTHON:-python3}" \
  cargo test --lib script::api::diameter_server::tests::emit_answer_with_repeated_avp_for_external_dissection -- --exact >/dev/null

if [[ ! -s "$HEX" ]]; then
  echo "the encoder produced nothing" >&2
  exit 1
fi

# 3868 is Diameter's registered port, so tshark's own dissector claims it.
text2pcap -q -T "3868,3868" "$HEX" "$PCAP"

status=0

expect() {
  local field="$1" want="$2" got
  # occurrence=a joins repeated AVPs with ',', tshark's default aggregator.
  got="$(tshark -r "$PCAP" -T fields -E occurrence=a -e "$field" 2>/dev/null | head -1)"
  if [[ "$got" != "$want" ]]; then
    echo "  FAIL $field: tshark read '$got', we meant '$want'" >&2
    status=1
    return
  fi
  echo "  ok   $field = $got"
}

tree="$(tshark -r "$PCAP" -V -O diameter 2>/dev/null)"

count() {
  local label="$1" pattern="$2" want="$3" got
  got="$(grep -cF "$pattern" <<<"$tree" || true)"
  if [[ "$got" != "$want" ]]; then
    echo "  FAIL $label: $got in the dissected tree, we meant $want" >&2
    status=1
    return
  fi
  echo "  ok   $label"
}

echo "reading it back with tshark"
expect diameter.cmd.code 303
expect diameter.flags.request False
expect diameter.applicationId 16777216
expect diameter.Result-Code 2001
expect diameter.Session-Id "scscf.ims.mnc001.mcc001.3gppnetwork.org;7;7"
# The script set neither of these: `answer()` copied them from the request,
# as TS 29.229 clause 6.1.8 lists them in the answer.
expect diameter.Auth-Session-State 1
expect diameter.Vendor-Id 10415
expect diameter.Auth-Application-Id 16777216
# Wireshark's dictionary prefixes the TS 29.229 AVPs with "3GPP-"; the bare
# names are the RFC 4740 ones, which have other codes.
expect diameter.3GPP-SIP-Number-Auth-Items 2
# One per SIP-Auth-Data-Item, in the order the script appended them.
expect diameter.3GPP-SIP-Item-Number 1,2
expect diameter.3GPP-SIP-Authentication-Scheme Digest-AKAv1-MD5,Digest-AKAv1-MD5

count "two SIP-Auth-Data-Item groups" "AVP Code: 612 3GPP-SIP-Auth-Data-Item" 2
count "a SIP-Authenticate in each" "AVP Code: 609 3GPP-SIP-Authenticate" 2
count "a SIP-Authorization in each" "AVP Code: 610 3GPP-SIP-Authorization" 2
count "a Confidentiality-Key in each" "AVP Code: 625 Confidentiality-Key" 2
count "an Integrity-Key in each" "AVP Code: 626 Integrity-Key" 2
count "one Result-Code" "AVP Code: 268 Result-Code" 1
count "one Vendor-Specific-Application-Id" "AVP Code: 260 Vendor-Specific-Application-Id" 1
count "one Auth-Session-State" "AVP Code: 277 Auth-Session-State" 1

if grep -q "Unknown AVP" <<<"$tree"; then
  echo "  FAIL an AVP tshark does not recognise" >&2
  status=1
fi
if [[ -n "$(tshark -r "$PCAP" -Y '_ws.malformed || _ws.expert' 2>/dev/null)" ]]; then
  echo "  FAIL tshark flagged the answer as malformed or raised expert info" >&2
  status=1
else
  echo "  ok   nothing malformed, no expert info"
fi

if [[ $status -ne 0 ]]; then
  echo "Diameter answer validation FAILED" >&2
  exit 1
fi

echo "Diameter answer validated against tshark's Diameter dissector"
