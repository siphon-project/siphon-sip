#!/usr/bin/env bash
#
# Validate the answers a Rust request handler builds against Wireshark's
# Diameter dissector.
#
# Feeds tshark three answers to an S6a Authentication-Information-Request and
# asserts it reads the fields we meant:
#
#   1. success with Authentication-Info { E-UTRAN-Vector { RAND, XRES, AUTN,
#      KASME } }: a vendor-specific grouped AVP two levels deep
#   2. Experimental-Result { Vendor-Id 10415, Experimental-Result-Code 5001 }
#      in the place of the Result-Code (RFC 6733 section 7.6)
#   3. the 5012 sent for a handler that failed: E bit, Error-Message
#
#   scripts/validate_diameter_native_answers.sh
#
# Needs tshark and text2pcap (wireshark-common). CI runners have neither, so
# run it locally after touching src/diameter/native/.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# tshark is commonly AppArmor-confined to a short list of readable paths, and a
# checkout under $HOME is often not on it, so the capture lives under TMPDIR.
WORK="${TMPDIR:-/tmp}/siphon-diameter-native-answers-validation"
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
SIPHON_DIAMETER_NATIVE_ANSWERS_HEX_OUT="$HEX" \
  PYO3_PYTHON="${PYO3_PYTHON:-python3}" \
  cargo test --lib diameter::native::tests::emit_answers_for_external_dissection -- --exact >/dev/null

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
  expect "$frame" diameter.cmd.code 318
  expect "$frame" diameter.applicationId 16777251
  expect "$frame" diameter.flags.request False
  expect "$frame" diameter.flags.proxyable True
  expect "$frame" diameter.hopbyhopid 0x11112222
  expect "$frame" diameter.endtoendid 0x33334444
  expect "$frame" diameter.Origin-Host hss.epc.mnc001.mcc001.3gppnetwork.org
  expect "$frame" diameter.Origin-Realm epc.mnc001.mcc001.3gppnetwork.org
done

expect 1 diameter.Session-Id "mme.epc.example.com;1;1"
expect 1 diameter.Result-Code 2001
expect 1 diameter.flags.error False
expect 1 diameter.Auth-Session-State 1
expect 1 diameter.Vendor-Id 10415
expect 1 diameter.RAND 11111111111111111111111111111111
expect 1 diameter.XRES 2222222222222222
expect 1 diameter.AUTN 33333333333333333333333333333333
expect 1 diameter.KASME 4444444444444444444444444444444444444444444444444444444444444444

expect 2 diameter.Result-Code ""
expect 2 diameter.flags.error False
expect 2 diameter.Vendor-Id 10415
expect 2 diameter.Experimental-Result-Code 5001
expect 2 diameter.Auth-Session-State 1

expect 3 diameter.Result-Code 5012
expect 3 diameter.flags.error True
expect 3 diameter.Error-Message "native handler failed"

tree="$(tshark -r "$PCAP" -V -O diameter 2>/dev/null)"

for avp in "AVP Code: 1413 Authentication-Info" "AVP Code: 1414 E-UTRAN-Vector" "AVP Code: 297 Experimental-Result"; do
  if ! grep -qF "$avp" <<<"$tree"; then
    echo "  FAIL tshark did not read '$avp'" >&2
    status=1
  else
    echo "  ok   $avp"
  fi
done

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
  echo "Diameter native answer validation FAILED" >&2
  exit 1
fi

echo "Diameter native answers validated against tshark's Diameter dissector"
