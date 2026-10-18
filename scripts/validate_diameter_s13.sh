#!/usr/bin/env bash
#
# Validate the S13 messages (ME-Identity-Check, TS 29.272) against Wireshark's
# Diameter dissector.
#
# The tests in src/script/diameter_dispatch.rs compare what an EIR's script
# answers with messages written out by hand from the ABNF. This feeds tshark,
# which has its own dictionary, the octets this node emits:
#
#   - the Capabilities-Exchange-Answer of a node advertising `s13`,
#   - the ME-Identity-Check-Answers a script's `@diameter.on_request("S13:ECR")`
#     handler built, for a listed terminal and for an unknown one,
#
# and then the hand-written messages themselves, so that what their comments
# claim is checked by the same independent decoder.
#
#   scripts/validate_diameter_s13.sh
#
# Needs tshark and text2pcap (wireshark-common). CI runners have neither, so
# run it locally after touching the S13 entries of src/diameter/dictionary.rs
# or the answer path of src/script/diameter_dispatch.rs.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# tshark is commonly AppArmor-confined to a short list of readable paths, and a
# checkout under $HOME is often not on it, so the capture lives under TMPDIR.
WORK="${TMPDIR:-/tmp}/siphon-diameter-s13-validation"
HEX="$WORK/s13.all"
PCAP="$WORK/s13.pcap"

for tool in tshark text2pcap; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "$tool not found, install wireshark-common" >&2
    exit 1
  fi
done

# One packet per message, in this order.
FRAMES=(cea eca eca_unknown written_ecr written_eca written_eca_unknown)

mkdir -p "$WORK"
for name in "${FRAMES[@]}"; do
  : >"$WORK/$name.hex"
done

echo "building the messages the way a script does"
SIPHON_S13_HEX_DIR="$WORK" \
  PYO3_PYTHON="${PYO3_PYTHON:-python3}" \
  cargo test --lib script::diameter_dispatch::s13_serving_tests::emit_s13_messages_for_external_dissection -- --exact >/dev/null

: >"$HEX"
for name in "${FRAMES[@]}"; do
  if [[ ! -s "$WORK/$name.hex" ]]; then
    echo "no $name was produced" >&2
    exit 1
  fi
  cat "$WORK/$name.hex" >>"$HEX"
done

# 3868 is Diameter's registered port, so tshark's own dissector claims it.
text2pcap -q -T "3868,3868" "$HEX" "$PCAP"

status=0

# The value of `field` in frame `number`; repeated AVPs are joined with ','.
expect() {
  local frame="$1" field="$2" want="$3" got
  got="$(tshark -r "$PCAP" -Y "frame.number == $frame" -T fields -E occurrence=a -e "$field" 2>/dev/null | head -1)"
  if [[ "$got" != "$want" ]]; then
    echo "  FAIL frame $frame $field: tshark read '$got', we meant '$want'" >&2
    status=1
    return
  fi
  echo "  ok   frame $frame $field = $got"
}

# The header of every message: command, direction and application.
header() {
  local frame="$1" command="$2" request="$3" application="$4"
  expect "$frame" diameter.cmd.code "$command"
  expect "$frame" diameter.flags.request "$request"
  expect "$frame" diameter.applicationId "$application"
}

IMSI="001010000000001"
IMEI="00100001000001"

echo "the capabilities exchange of an EIR"
# RFC 6733 clause 6.11 and TS 29.272 clause 7.1.8: S13 inside a
# Vendor-Specific-Application-Id with Vendor-Id 10415. The first Vendor-Id of
# the message is the node's own. The application also goes out as a bare
# Auth-Application-Id, as every CEA siphon sends does.
expect 1 diameter.cmd.code 257
expect 1 diameter.flags.request False
expect 1 diameter.Result-Code 2001
expect 1 diameter.Vendor-Id 0,10415
expect 1 diameter.Auth-Application-Id 16777252,16777252

echo "S13: the ME-Identity-Check-Answer a script's handler built"
header 2 324 False 16777252
expect 2 diameter.flags.error False
expect 2 diameter.Result-Code 2001
expect 2 diameter.Auth-Application-Id 16777252
# Wireshark's dictionary still names value 1 BLACKLISTED; TS 29.272 clause
# 7.3.51 names it PROHIBITEDLISTED.
expect 2 diameter.Equipment-Status 1
# Equipment-Status carries V and M with Vendor-Id 10415 (Table 7.3.1/1), the
# only vendor AVP of the answer.
expect 2 diameter.avp.vendorId 10415
expect 2 diameter.avp.flags 0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0xc0
expect 2 diameter.avp.code 263,260,266,258,268,277,264,296,1445

echo "S13: the answer for a terminal the EIR does not know"
header 3 324 False 16777252
expect 3 diameter.flags.error False
# TS 29.272 clause 7.4.3.5: inside an Experimental-Result, and no Result-Code.
expect 3 diameter.Experimental-Result-Code 5422
expect 3 diameter.Result-Code ""
expect 3 diameter.Equipment-Status ""
expect 3 diameter.Vendor-Id 10415,10415

echo "the hand-written messages the tests read"
header 4 324 True 16777252
expect 4 diameter.User-Name "$IMSI"
expect 4 diameter.IMEI "$IMEI"
expect 4 diameter.Software-Version 01
expect 4 diameter.avp.code 263,260,266,258,277,264,296,283,1401,1402,1403,1
header 5 324 False 16777252
expect 5 diameter.Result-Code 2001
expect 5 diameter.Equipment-Status 1
header 6 324 False 16777252
expect 6 diameter.Experimental-Result-Code 5422
expect 6 diameter.Result-Code ""

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

echo "names read from Wireshark's dictionary"
# The header names the application once per message: the five after the CEA.
count "S13 by name in every S13 message" "ApplicationId: 3GPP S13/S13' (16777252)" 5
count "Terminal-Information in the request" "AVP Code: 1401 Terminal-Information" 1
count "Equipment-Status in two answers" "AVP Code: 1445 Equipment-Status" 2
# Each value line appears twice in the tree: under the AVP and inside it.
count "Equipment-Status 1 in two answers" "Equipment-Status: BLACKLISTED (1)" 4
count "DIAMETER_ERROR_EQUIPMENT_UNKNOWN in two answers" "Experimental-Result-Code: DIAMETER_ERROR_EQUIPMENT_UNKNOWN (5422)" 4

if grep -q "Unknown AVP" <<<"$tree"; then
  echo "  FAIL an AVP tshark does not recognise" >&2
  status=1
fi
if [[ -n "$(tshark -r "$PCAP" -Y '_ws.malformed || _ws.expert' 2>/dev/null)" ]]; then
  echo "  FAIL tshark flagged a message as malformed or raised expert info" >&2
  status=1
else
  echo "  ok   nothing malformed, no expert info"
fi

if [[ $status -ne 0 ]]; then
  echo "Diameter S13 validation FAILED" >&2
  exit 1
fi

echo "Diameter S13 messages validated against tshark's Diameter dissector"
