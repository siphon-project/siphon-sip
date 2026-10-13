#!/usr/bin/env bash
#
# Validate the answer siphon gives a callee's UPDATE on the early dialog, and
# the 2xx the caller is sent afterwards, against Wireshark's SIP and SDP
# dissectors.
#
# The tests in src/dispatcher/early_update_answer_tests.rs read siphon's
# messages back with siphon's own parser, so they share whatever siphon gets
# wrong about a session description it builds and the Content-Length that goes
# with it. This feeds both messages to tshark and asserts it reads the
# precondition status of an answerer with nothing to reserve in the 200 to the
# UPDATE (RFC 3312 §5.2), and the callee's description as the UPDATE left it,
# without its precondition attributes, in the caller's 2xx (RFC 3261 §13.2.1).
#
# Two calls, two frames each. In both the callee answers in a reliable 183
# with nothing reserved and sends an UPDATE with a new offer from another
# address and port. In the first the caller, which does not use 100rel, was
# shown the 183's description (frames 1 and 2); in the second a script relayed
# the 183 without its body (frames 3 and 4).
#
#   scripts/validate_b2bua_early_update_answer.sh
#
# Needs tshark and text2pcap (wireshark-common). CI runners have neither, so
# run it locally after touching src/dispatcher/b2bua/early_update_answer.rs,
# src/media/answer.rs or src/media/precondition.rs.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# tshark is commonly AppArmor-confined to a short list of readable paths, and a
# checkout under $HOME is often not on it, so the capture lives under TMPDIR.
WORK="${TMPDIR:-/tmp}/siphon-b2bua-early-update-answer-validation"
HEX="$WORK/early_update_answer.hex"
PCAP="$WORK/early_update_answer.pcap"

for tool in tshark text2pcap; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "$tool not found, install wireshark-common" >&2
    exit 1
  fi
done

mkdir -p "$WORK"
rm -f "$HEX" "$PCAP"

echo "answering a callee's UPDATE for a caller without 100rel, twice"
SIPHON_B2BUA_EARLY_UPDATE_ANSWER_HEX_OUT="$HEX" \
  PYO3_PYTHON="${PYO3_PYTHON:-python3}" \
  cargo test --lib dispatcher::early_update_answer_tests::emit_answered_update_for_external_dissection -- --exact >/dev/null

if [[ ! -s "$HEX" ]]; then
  echo "siphon sent nothing" >&2
  exit 1
fi

# 5060 is SIP's registered port, so tshark's own dissector claims it.
text2pcap -q -u "5060,5060" "$HEX" "$PCAP"

status=0

# One field of one frame, as tshark's dissector read it: every occurrence, in
# order, joined with `|`.
field() {
  local frame="$1" name="$2"
  tshark -r "$PCAP" -Y "frame.number == $frame" -T fields -E occurrence=a -E aggregator='|' -e "$name" 2>/dev/null | head -1
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

# What the answer to the UPDATE says of the preconditions: siphon's own access
# network ready, the callee's as the callee reported it, each desired status at
# the strength offered with its tags turned round (RFC 3312 §5.2, table 4).
ANSWERED_STATUS="curr:qos local sendrecv|curr:qos remote sendrecv|des:qos optional local sendrecv|des:qos mandatory remote sendrecv"

echo "reading them back with tshark"
for update in 1 3; do
  expect "$update" sip.Status-Code 200
  expect "$update" sip.CSeq.method UPDATE
  expect "$update" sip.Content-Type application/sdp
  expect "$update" sip.Retry-After ""
  # The stream siphon's INVITE offered this callee, unchanged.
  expect "$update" sdp.owner.username siphon
  expect "$update" sdp.connection_info.address 192.0.2.10
  expect "$update" sdp.media "audio 40000 RTP/AVP 0"
  expect "$update" sdp.media_attr "$ANSWERED_STATUS"
done

# The caller's 2xx: the callee's address and port as its UPDATE gave them, and
# none of its precondition attributes.
for answer in 2 4; do
  expect "$answer" sip.Status-Code 200
  expect "$answer" sip.CSeq.method INVITE
  expect "$answer" sip.Content-Type application/sdp
  expect "$answer" sdp.owner.username siphon
  expect "$answer" sdp.connection_info.address 198.51.100.9
  expect "$answer" sdp.media "audio 50002 RTP/AVP 0"
  expect "$answer" sdp.media_attr ""
done
# A caller that was shown the 183's description gets a revision of that
# session: its session id, one version on (RFC 3264 §8).
expect 2 sdp.owner.sessionid 2
expect 2 sdp.owner.version 3
# A caller that was shown none gets its first description: the first version
# of its own dialog's session.
expect 4 sdp.owner.version 0

malformed="$(tshark -r "$PCAP" -Y "_ws.malformed" -T fields -e frame.number 2>/dev/null)"
if [[ -n "$malformed" ]]; then
  echo "  FAIL tshark calls frame(s) $malformed malformed" >&2
  status=1
else
  echo "  ok   no malformed frame"
fi

if [[ "$status" -ne 0 ]]; then
  echo "tshark does not read the answer to the UPDATE and the caller's 2xx as meant" >&2
  exit 1
fi
echo "tshark reads the answered preconditions in the 200 to the UPDATE and the callee's description in the caller's 2xx"
