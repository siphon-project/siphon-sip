#!/usr/bin/env bash
#
# Validate the header E bit and the Error-Message AVP of the answers siphon
# sends against Wireshark's Diameter dissector.
#
# RFC 6733 sets the E bit for a protocol error (3xxx, section 7.1.3) and lets
# the generic answer-message of section 7.2 report a permanent failure (5xxx,
# section 7.1.5), while a permanent failure answered in the grammar of the
# command leaves it clear. Error-Message must not carry the M bit (section
# 4.5). This feeds tshark three answers to a Cx Registration-Termination
# request and asserts it reads the flags we meant:
#
#   1. a handler refusing with 5012 (`request.answer(5012)`): no E bit
#   2. a handler answering 3002 (`request.reject(3002, "no route")`): E bit
#   3. siphon answering 5012 for a handler that raised: E bit, Error-Message
#
#   scripts/validate_diameter_answer_flags.sh
#
# Needs tshark and text2pcap (wireshark-common). CI runners have neither, so
# run it locally after touching src/diameter/forward.rs.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# tshark is commonly AppArmor-confined to a short list of readable paths, and a
# checkout under $HOME is often not on it, so the capture lives under TMPDIR.
WORK="${TMPDIR:-/tmp}/siphon-diameter-answer-flags-validation"
HEX="$WORK/answers.hex"
PCAP="$WORK/answers.pcap"

for tool in tshark text2pcap; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "$tool not found, install wireshark-common" >&2
    exit 1
  fi
done

mkdir -p "$WORK"
rm -f "$HEX" "$PCAP"

echo "building the answers"
SIPHON_DIAMETER_ANSWER_FLAGS_HEX_OUT="$HEX" \
  PYO3_PYTHON="${PYO3_PYTHON:-python3}" \
  cargo test --lib diameter::forward::tests::emit_answers_for_external_dissection -- --exact >/dev/null

if [[ ! -s "$HEX" ]]; then
  echo "the encoder produced nothing" >&2
  exit 1
fi

# 3868 is Diameter's registered port, so tshark's own dissector claims it.
text2pcap -q -T "3868,3868" "$HEX" "$PCAP"

status=0

expect() {
  local frame="$1" field="$2" want="$3" got
  got="$(tshark -r "$PCAP" -Y "frame.number == $frame" -T fields -E occurrence=f -e "$field" 2>/dev/null | head -1)"
  if [[ "$got" != "$want" ]]; then
    echo "  FAIL frame $frame $field: tshark read '$got', we meant '$want'" >&2
    status=1
    return
  fi
  echo "  ok   frame $frame $field = $got"
}

echo "reading them back with tshark"
for frame in 1 2 3; do
  expect "$frame" diameter.cmd.code 304
  expect "$frame" diameter.flags.request False
  expect "$frame" diameter.flags.proxyable True
done

expect 1 diameter.Result-Code 5012
expect 1 diameter.flags.error False
expect 1 diameter.Error-Message ""

expect 2 diameter.Result-Code 3002
expect 2 diameter.flags.error True
expect 2 diameter.Error-Message "no route"

expect 3 diameter.Result-Code 5012
expect 3 diameter.flags.error True
expect 3 diameter.Error-Message "on_request handler raised"

tree="$(tshark -r "$PCAP" -V -O diameter 2>/dev/null)"

# The flags line sits right under the code line of the AVP it belongs to.
total="$(grep -cF "AVP Code: 281 Error-Message" <<<"$tree" || true)"
clear="$(grep -A1 -F "AVP Code: 281 Error-Message" <<<"$tree" | grep -cF "AVP Flags: 0x00" || true)"
if [[ "$total" != "2" || "$clear" != "2" ]]; then
  echo "  FAIL Error-Message: $clear of $total (we meant 2 of 2) carry no flag" >&2
  status=1
else
  echo "  ok   Error-Message carries neither V nor M in both"
fi

if grep -q "Unknown AVP" <<<"$tree"; then
  echo "  FAIL an AVP tshark does not recognise" >&2
  status=1
fi
if [[ -n "$(tshark -r "$PCAP" -Y '_ws.malformed || _ws.expert' 2>/dev/null)" ]]; then
  echo "  FAIL tshark flagged an answer as malformed or raised expert info" >&2
  status=1
else
  echo "  ok   nothing malformed, no expert info"
fi

if [[ $status -ne 0 ]]; then
  echo "Diameter answer flag validation FAILED" >&2
  exit 1
fi

echo "Diameter answer flags validated against tshark's Diameter dissector"
