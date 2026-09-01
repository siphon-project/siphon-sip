#!/usr/bin/env bash
#
# Validate the TS 103 221-2 X2 PDU encoder against a third-party dissector.
#
# Every unit test in src/li/pdu.rs is our reading of clause 5 checking our own
# encoder, so a field we misread is a field they agree on. This feeds the bytes
# we emit to somebody else's decoder, the x2x3PduDissector project, and
# asserts it reads back the fields we meant. That is a genuinely independent
# opinion, which is the point.
#
#   scripts/validate_x2_pdu.sh
#
# Needs tshark and text2pcap (wireshark-common). The dissector is fetched on
# first run and cached.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# tshark is commonly confined (AppArmor) to a short list of readable paths, and
# a checkout under $HOME/workspace is not on it — it fails with a permission
# error on the capture file that has nothing to do with file modes. So the
# capture, and the plugin it loads, live somewhere it is allowed to read.
WORK="${TMPDIR:-/tmp}/siphon-x2-pdu-validation"
DISSECTOR="$WORK/x2x3PduDissector.lua"
HEX="$WORK/x2_pdu.hex"
PCAP="$WORK/x2_pdu.pcap"

# The dissector registers itself on TCP port 0, so the real port is named
# explicitly with -d. `x2x3` is the protocol's filter name, lowercased.
X2_PORT=42069

for tool in tshark text2pcap; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "$tool not found — install wireshark-common" >&2
    exit 1
  fi
done

mkdir -p "$WORK"

if [[ ! -f "$DISSECTOR" ]]; then
  echo "fetching the third-party dissector"
  curl -fsSL \
    https://raw.githubusercontent.com/hyavari/x2x3PduDissector/main/x2x3PduDissector.lua \
    -o "$DISSECTOR"
fi

echo "encoding a PDU"
SIPHON_X2_PDU_HEX_OUT="$HEX" \
  PYO3_PYTHON=python3 \
  cargo test --lib li::pdu::tests::emit_x2_pdu_for_external_dissection -- --exact >/dev/null

if [[ ! -s "$HEX" ]]; then
  echo "the encoder produced nothing" >&2
  exit 1
fi

# -T gives it a TCP header so the dissector's tcp.port hook can fire.
text2pcap -q -T "1234,$X2_PORT" "$HEX" "$PCAP"

dissect() {
  tshark -q -r "$PCAP" \
    -X "lua_script:$DISSECTOR" \
    -d "tcp.port==$X2_PORT,x2x3" \
    -T fields "$@" 2>/dev/null | head -1
}

status=0
expect() {
  local field="$1" want="$2" got
  got="$(dissect -e "$field")"
  if [[ "$got" != "$want" ]]; then
    echo "  FAIL $field: the dissector read '$got', we meant '$want'" >&2
    status=1
    return
  fi
  echo "  ok   $field = $got"
}

echo "reading it back with somebody else's dissector"
expect x2x3.pduType 1
expect x2x3.payloadFormat 9
expect x2x3.payloadDirection 3
expect x2x3.xid 00010203-0405-0607-0809-0a0b0c0d0e0f
expect x2x3.correlationId 0x1122334455667788
# 40 mandatory + timestamp (4+8) + sequence number (4+4) + matched target
# identifier (4+6) = 70.
expect x2x3.headerLength 70
expect x2x3.payloadLength 38

# Wireshark hands the payload to its own SIP dissector, so this also proves the
# payload starts exactly where the header length says: an off-by-one and SIP
# would not parse at all.
expect sip.Method INVITE
expect sip.r-uri sip:bob@example.com

# The conditional attributes are not exposed as filterable fields, so they are
# checked in the rendered tree. The timestamp is the one worth asserting: it is
# the only attribute whose encoding (seconds then nanoseconds, both 32-bit) we
# could get wrong in a way that still produces a well-formed PDU.
tree="$(tshark -q -r "$PCAP" \
  -X "lua_script:$DISSECTOR" \
  -d "tcp.port==$X2_PORT,x2x3" -V 2>/dev/null)"

check_tree() {
  local label="$1" pattern="$2"
  if grep -qE "$pattern" <<<"$tree"; then
    echo "  ok   $label"
  else
    echo "  FAIL $label: not found in the dissected tree" >&2
    status=1
  fi
}

check_tree "version 0.5" 'Version: Major: 0, Minor: 5'
check_tree "timestamp attribute" '2023-11-14 23:13:20\.123456789'
check_tree "sequence number attribute" 'Sequence Number'
check_tree "matched target identifier" 'LI-001'

if [[ $status -ne 0 ]]; then
  echo "X2 PDU validation FAILED" >&2
  exit 1
fi

echo "X2 PDU validated against the third-party dissector"
