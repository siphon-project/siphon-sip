#!/usr/bin/env bash
#
# Validate the E.164 numbers in the S6c and SGd requests against Wireshark's
# Diameter dissector.
#
# MSISDN (TS 29.329 clause 6.3.2) and SC-Address (TS 29.338 clause 6.3.3.2)
# are TBCD-strings with no nature-of-address octet before the digits. The
# tests in src/diameter/s6c.rs and sgd.rs pin octets we derived from those
# clauses. This feeds tshark a Send-Routing-Info-for-SM request, a
# Report-SM-Delivery-Status request and an MT-Forward-Short-Message request
# and asserts tshark reads the numbers we meant. The MSISDN is 19995550100,
# whose first octet (0x91) is what an indicator octet would also look like.
#
#   scripts/validate_diameter_sms_addresses.sh
#
# Needs tshark and text2pcap (wireshark-common). CI runners have neither, so
# run it locally after touching the address encoding in src/diameter/.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# tshark is commonly AppArmor-confined to a short list of readable paths, and a
# checkout under $HOME is often not on it, so the capture lives under TMPDIR.
WORK="${TMPDIR:-/tmp}/siphon-diameter-sms-address-validation"
HEX="$WORK/requests.hex"
PCAP="$WORK/requests.pcap"

for tool in tshark text2pcap; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "$tool not found, install wireshark-common" >&2
    exit 1
  fi
done

mkdir -p "$WORK"
rm -f "$HEX" "$PCAP"

echo "encoding the requests"
SIPHON_SMS_ADDRESSES_HEX_OUT="$HEX" \
  PYO3_PYTHON="${PYO3_PYTHON:-python3}" \
  cargo test --lib diameter::s6c::tests::emit_sms_addresses_for_external_dissection -- --exact >/dev/null

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

# The octets of a number as a TBCD-string, the way tshark prints an
# OctetString: 31611111111 -> 1316111111f1.
tbcd() {
  local digits="$1" out="" index
  (( ${#digits} % 2 )) && digits="${digits}f"
  for (( index = 0; index < ${#digits}; index += 2 )); do
    out+="${digits:index+1:1}${digits:index:1}"
  done
  echo "$out"
}

echo "reading the Send-Routing-Info-for-SM request back with tshark"
# TS 29.338 clause 5.3.2.3: command 8388647, application 16777312.
expect 1 diameter.cmd.code 8388647
expect 1 diameter.applicationId 16777312
expect 1 diameter.flags.request True
# tshark decodes the MSISDN itself: the number, not only the octets. The
# octets are the six of the digits, with nothing before them.
expect 1 e164.msisdn 19995550100
expect 1 diameter.MSISDN "$(tbcd 19995550100)"
expect 1 diameter.SC-Address "$(tbcd 31611111111)"

echo "reading the Report-SM-Delivery-Status request back with tshark"
# Clause 5.3.2.7: command 8388649.
expect 2 diameter.cmd.code 8388649
expect 2 diameter.applicationId 16777312
expect 2 diameter.SC-Address "$(tbcd 441632960000)"

echo "reading the MT-Forward-Short-Message request back with tshark"
# Clause 6.3.2.5: command 8388646, application 16777313.
expect 3 diameter.cmd.code 8388646
expect 3 diameter.applicationId 16777313
expect 3 diameter.SC-Address "$(tbcd 31611111111)"

tree="$(tshark -r "$PCAP" -V -O diameter 2>/dev/null)"

if grep -q "Unknown AVP" <<<"$tree"; then
  echo "  FAIL an AVP tshark does not recognise" >&2
  status=1
fi
if [[ -n "$(tshark -r "$PCAP" -Y '_ws.malformed || _ws.expert' 2>/dev/null)" ]]; then
  echo "  FAIL tshark flagged a request as malformed or raised expert info" >&2
  status=1
else
  echo "  ok   nothing malformed, no expert info"
fi

if [[ $status -ne 0 ]]; then
  echo "S6c and SGd address validation FAILED" >&2
  exit 1
fi

echo "S6c and SGd addresses validated against tshark's Diameter dissector"
