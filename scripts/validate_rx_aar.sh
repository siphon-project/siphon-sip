#!/usr/bin/env bash
#
# Validate the Rx AA-Request encoder against Wireshark's Diameter dissector.
#
# The known-answer tests in src/diameter/rx.rs and src/script/api/diameter.rs
# pin bytes we chose, so they share whatever we misread of TS 29.214. That is
# how SpecificAction put IP-CAN_CHANGE on the value of
# INDICATION_OF_OUT_OF_CREDIT without a test noticing. This feeds the AAR that
# `diameter.rx_aar` builds to tshark, which decodes it with its own dictionary,
# and asserts it reads back what we meant.
#
#   scripts/validate_rx_aar.sh
#
# Needs tshark and text2pcap (wireshark-common). CI runners have neither, so
# run it locally after touching src/diameter/rx.rs.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# tshark is commonly AppArmor-confined to a short list of readable paths, and a
# checkout under $HOME is often not on it, so the capture lives under TMPDIR.
WORK="${TMPDIR:-/tmp}/siphon-rx-aar-validation"
HEX="$WORK/rx_aar.hex"
PCAP="$WORK/rx_aar.pcap"

for tool in tshark text2pcap; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "$tool not found, install wireshark-common" >&2
    exit 1
  fi
done

mkdir -p "$WORK"
rm -f "$HEX" "$PCAP"

echo "encoding an AAR the way diameter.rx_aar does"
SIPHON_RX_AAR_HEX_OUT="$HEX" \
  PYO3_PYTHON=python3 \
  cargo test --lib script::api::diameter::tests::emit_rx_aar_for_external_dissection -- --exact >/dev/null

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

check_tree() {
  local label="$1" pattern="$2"
  if grep -qE "$pattern" <<<"$tree"; then
    echo "  ok   $label"
  else
    echo "  FAIL $label: not found in the dissected tree" >&2
    status=1
  fi
}

# The flags line sits right under the code line of the AVP it belongs to.
check_flags() {
  local label="$1" code_line="$2" flags_line="$3" count="$4" got
  got="$(grep -A1 -F "$code_line" <<<"$tree" | grep -cF "$flags_line" || true)"
  if [[ "$got" != "$count" ]]; then
    echo "  FAIL $label: $got of $count AVPs had '$flags_line'" >&2
    status=1
    return
  fi
  echo "  ok   $label"
}

echo "reading it back with tshark"
expect diameter.cmd.code 265
expect diameter.applicationId 16777236
expect diameter.Session-Id "pcscf.ims.mnc001.mcc001.3gppnetwork.org;1;1"
expect diameter.Destination-Host pcrf1.ims.mnc001.mcc001.3gppnetwork.org
expect diameter.Specific-Action 6,7,9
expect diameter.Rx-Request-Type 0

# TS 29.214 §5.3.13 names, read from Wireshark's dictionary rather than ours.
check_tree "6 is IP-CAN_CHANGE" 'Specific-Action: IP-CAN_CHANGE \(6\)'
check_tree "7 is INDICATION_OF_OUT_OF_CREDIT" 'Specific-Action: INDICATION_OF_OUT_OF_CREDIT \(7\)'
check_tree "9 is INDICATION_OF_FAILED_RESOURCES_ALLOCATION" \
  'Specific-Action: INDICATION_OF_FAILED_RESOURCES_ALLOCATION \(9\)'
check_tree "Rx-Request-Type is INITIAL_REQUEST" 'Rx-Request-Type: INITIAL_REQUEST \(0\)'

# Table 5.3.1: Specific-Action must carry M and V, Rx-Request-Type must not
# carry M.
check_flags "Specific-Action flags M+V" "AVP Code: 513 Specific-Action" \
  "AVP Flags: 0xc0, Vendor-Specific: Set, Mandatory: Set" 3
check_flags "Rx-Request-Type flags V only" "AVP Code: 533 Rx-Request-Type" \
  "AVP Flags: 0x80, Vendor-Specific: Set" 1

if grep -q "Unknown AVP" <<<"$tree"; then
  echo "  FAIL an AVP tshark does not recognise" >&2
  status=1
fi
if [[ -n "$(tshark -r "$PCAP" -Y '_ws.malformed || _ws.expert' 2>/dev/null)" ]]; then
  echo "  FAIL tshark flagged the AAR as malformed or raised expert info" >&2
  status=1
else
  echo "  ok   nothing malformed, no expert info"
fi

if [[ $status -ne 0 ]]; then
  echo "Rx AAR validation FAILED" >&2
  exit 1
fi

echo "Rx AAR validated against tshark's Diameter dissector"
