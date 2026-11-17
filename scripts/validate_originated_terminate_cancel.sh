#!/usr/bin/env bash
#
# Validate the CANCEL that ends a call siphon placed while it rings, against
# Wireshark's SIP dissector.
#
# The tests in src/dispatcher/originated_terminate_tests.rs read siphon's
# requests back with siphon's own parser, so they share whatever siphon's
# serializer gets wrong. This feeds the INVITE, the CANCEL `b2bua.terminate()`
# sends for it and the ACK to the 487 to tshark, as the octets siphon put on
# the wire, and asserts what RFC 3261 §9.1 requires of the CANCEL: the
# INVITE's Request-URI, Call-ID, To, From and CSeq number, the method CANCEL,
# one Via matching the INVITE's top one (branch included), and the INVITE's
# Route. The ACK is the INVITE transaction's own (§17.1.1.3): same branch.
#
#   scripts/validate_originated_terminate_cancel.sh
#
# Needs tshark and text2pcap (wireshark-common). CI runners have neither, so
# run it locally after touching the CANCEL path of an originated call
# (src/dispatcher/b2bua/originate_cancel.rs, terminate.rs, response/teardown.rs).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# tshark is commonly AppArmor-confined to a short list of readable paths, and a
# checkout under $HOME is often not on it, so the capture lives under TMPDIR.
WORK="${TMPDIR:-/tmp}/siphon-originated-terminate-cancel-validation"
HEX="$WORK/terminate_cancel.hex"
PCAP="$WORK/terminate_cancel.pcap"

for tool in tshark text2pcap; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "$tool not found, install wireshark-common" >&2
    exit 1
  fi
done

mkdir -p "$WORK"
rm -f "$HEX" "$PCAP"

echo "placing a call, ringing it, and ending it by Call-ID"
SIPHON_ORIGINATED_TERMINATE_CANCEL_HEX_OUT="$HEX" \
  PYO3_PYTHON="${PYO3_PYTHON:-python3}" \
  cargo test --lib dispatcher::originated_terminate_tests::emit_terminate_cancel_for_external_dissection -- --exact >/dev/null

if [[ ! -s "$HEX" ]]; then
  echo "siphon sent the callee nothing" >&2
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

# A field tshark must read in frame $1, and read the same in the INVITE.
expect_as_invite() {
  local frame="$1" name="$2" invite other
  invite="$(field 1 "$name")"
  other="$(field "$frame" "$name")"
  if [[ -z "$invite" || "$other" != "$invite" ]]; then
    echo "  FAIL $name: the INVITE has '$invite', frame $frame has '$other'" >&2
    status=1
    return
  fi
  echo "  ok   frame $frame $name is the INVITE's: $other"
}

echo "reading them back with tshark"
expect 1 sip.Method INVITE
expect 1 sip.CSeq.method INVITE

expect 2 sip.Method CANCEL
expect 2 sip.CSeq.method CANCEL
expect 2 sip.Content-Length 0
for name in sip.r-uri sip.Call-ID sip.From sip.To sip.CSeq.seq sip.Via.branch sip.Via.sent-by.address sip.Via.sent-by.port sip.Via.transport sip.Route; do
  expect_as_invite 2 "$name"
done
# §9.1: the To of the INVITE, which has no tag, though the 180 brought one.
expect 2 sip.to.tag ""
# A single Via.
vias="$(tshark -r "$PCAP" -Y "frame.number == 2" -T fields -E occurrence=a -E aggregator='|' -e sip.Via.branch 2>/dev/null)"
if [[ "$vias" == *"|"* ]]; then
  echo "  FAIL frame 2 carries more than one Via: $vias" >&2
  status=1
else
  echo "  ok   frame 2 carries one Via"
fi

expect 3 sip.Method ACK
expect 3 sip.CSeq.method ACK
for name in sip.r-uri sip.Call-ID sip.From sip.CSeq.seq sip.Via.branch sip.Route; do
  expect_as_invite 3 "$name"
done
# §17.1.1.3: the To of the response being acknowledged, tag and all.
expect 3 sip.to.tag callee-tag

if tshark -r "$PCAP" -Y "sip.Method == BYE" -T fields -e frame.number 2>/dev/null | grep -q .; then
  echo "  FAIL a BYE went out for an INVITE with no final response" >&2
  status=1
else
  echo "  ok   no BYE"
fi

malformed="$(tshark -r "$PCAP" -Y "_ws.malformed || _ws.expert.severity >= 0x00600000" -T fields -e frame.number 2>/dev/null)"
if [[ -n "$malformed" ]]; then
  echo "  FAIL tshark calls frame(s) $malformed malformed" >&2
  status=1
else
  echo "  ok   no malformed frame"
fi

frames="$(tshark -r "$PCAP" -Y sip -T fields -e frame.number 2>/dev/null | wc -l)"
if [[ "$frames" -ne 3 ]]; then
  echo "  FAIL tshark read $frames SIP frames, we sent 3" >&2
  status=1
fi

if [[ "$status" -ne 0 ]]; then
  echo "tshark does not read the CANCEL RFC 3261 §9.1 describes" >&2
  exit 1
fi
echo "tshark reads the INVITE, its CANCEL on the same branch and the ACK to the 487"
