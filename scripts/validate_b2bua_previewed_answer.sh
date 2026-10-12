#!/usr/bin/env bash
#
# Validate the 2xx a B2BUA caller is sent after an unreliable provisional
# previewed the answer, against Wireshark's SIP and SDP dissectors.
#
# The tests in src/dispatcher/answer_after_preview_tests.rs read siphon's
# responses back with siphon's own parser, so they share whatever siphon gets
# wrong about a body it adds to a response and the Content-Length that goes
# with it. This feeds the 183 and the 200 siphon sends the caller to tshark and
# asserts it reads the same session description in both (RFC 3261 §13.2.1,
# RFC 6337 §3.1.1).
#
# Three calls, two frames each: a callee whose 200 carries no SDP (frames 1
# and 2), one whose 200 repeats the answer (3 and 4), and one whose 200 changes
# it (5 and 6). In all three the 200 must name the session the 183 named: the
# same o= session id (RFC 4566 §5.2), at the same version unless the
# description changed, and then at the next one (RFC 3264 §8).
#
#   scripts/validate_b2bua_previewed_answer.sh
#
# Needs tshark and text2pcap (wireshark-common). CI runners have neither, so
# run it locally after touching the B-leg response path in
# src/dispatcher/b2bua/response/.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# tshark is commonly AppArmor-confined to a short list of readable paths, and a
# checkout under $HOME is often not on it, so the capture lives under TMPDIR.
WORK="${TMPDIR:-/tmp}/siphon-b2bua-previewed-answer-validation"
HEX="$WORK/previewed_answer.hex"
PCAP="$WORK/previewed_answer.pcap"

for tool in tshark text2pcap; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "$tool not found, install wireshark-common" >&2
    exit 1
  fi
done

mkdir -p "$WORK"
rm -f "$HEX" "$PCAP"

echo "relaying a reliable 183 and its 200 to a caller without 100rel, three times"
SIPHON_B2BUA_PREVIEWED_ANSWER_HEX_OUT="$HEX" \
  PYO3_PYTHON="${PYO3_PYTHON:-python3}" \
  cargo test --lib dispatcher::answer_after_preview_tests::emit_previewed_answer_for_external_dissection -- --exact >/dev/null

if [[ ! -s "$HEX" ]]; then
  echo "siphon sent the caller nothing" >&2
  exit 1
fi

# 5060 is SIP's registered port, so tshark's own dissector claims it.
text2pcap -q -u "5060,5060" "$HEX" "$PCAP"

status=0

# One field of one frame, as tshark's dissector read it.
field() {
  local frame="$1" name="$2"
  tshark -r "$PCAP" -Y "frame.number == $frame" -T fields -E occurrence=a -e "$name" 2>/dev/null | head -1
}

expect() {
  local frame="$1" name="$2" want="$3" got
  got="$(field "$frame" "$name")"
  if [[ "$got" != "$want" ]]; then
    echo "  FAIL frame $frame $name: tshark read '$got', we meant '$want'" >&2
    status=1
    return
  fi
  echo "  ok   frame $frame $name = $got"
}

# A field tshark must read the same in the 183 at frame $1 and in the 200 that
# follows it.
expect_same() {
  local first="$1" name="$2" preview answer
  preview="$(field "$first" "$name")"
  answer="$(field "$((first + 1))" "$name")"
  if [[ -z "$answer" || "$answer" != "$preview" ]]; then
    echo "  FAIL $name: the 183 has '$preview', the 200 has '$answer'" >&2
    status=1
    return
  fi
  echo "  ok   frames $first and $((first + 1)) $name is the same in both: $answer"
}

echo "reading them back with tshark"
expect 1 sip.Status-Code 183
expect 2 sip.Status-Code 200
expect 2 sip.CSeq.method INVITE
expect 2 sip.Content-Type application/sdp
# The preview is unreliable: no RSeq and no Require on the caller's dialog.
expect 1 sip.RSeq ""
expect 1 sip.Require ""
# RFC 6337 §3.1.1: "the same exact answer in the 2xx", o= version included.
expect_same 1 sdp.owner
expect_same 1 sdp.connection_info
expect_same 1 sdp.media
expect_same 1 sip.Content-Length

# A 200 that repeats the answer: the same bytes, origin and version included.
expect 3 sip.Status-Code 183
expect 4 sip.Status-Code 200
expect_same 3 sdp.owner.sessionid
expect_same 3 sdp.owner.version
expect_same 3 sdp.owner
expect_same 3 sdp.connection_info
expect_same 3 sdp.media
expect_same 3 sip.Content-Length

# A 200 that changes the answer: the same session, one version on, with the
# callee's own description.
expect 5 sip.Status-Code 183
expect 6 sip.Status-Code 200
expect_same 5 sdp.owner.sessionid
expect_same 5 sdp.owner.username
expect_same 5 sdp.owner.address
expect 5 sdp.owner.version 2
expect 6 sdp.owner.version 3
expect 6 sdp.media "audio 52000 RTP/AVP 0"

malformed="$(tshark -r "$PCAP" -Y "_ws.malformed" -T fields -e frame.number 2>/dev/null)"
if [[ -n "$malformed" ]]; then
  echo "  FAIL tshark calls frame(s) $malformed malformed" >&2
  status=1
else
  echo "  ok   no malformed frame"
fi

if [[ "$status" -ne 0 ]]; then
  echo "tshark does not read the previewed answer in the 2xx" >&2
  exit 1
fi
echo "tshark reads the same answer in the 183 and in the 200"
