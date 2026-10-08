#!/usr/bin/env bash
#
# Validate the Rf Accounting-Request encoder against Wireshark's Diameter
# dissector.
#
# The known-answer tests in src/diameter/rf.rs and src/script/api/diameter.rs
# pin bytes we chose, so they share whatever we misread of TS 32.299. This
# feeds an ACR-EVENT built the way `diameter.rf_acr_event` builds one to
# tshark, which decodes it with its own dictionary, and asserts it reads back
# what we meant.
#
#   scripts/validate_rf_acr.sh
#
# Needs tshark and text2pcap (wireshark-common). CI runners have neither, so
# run it locally after touching the IMS-Information encoder in
# src/diameter/ro.rs or src/diameter/rf.rs.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# tshark is commonly AppArmor-confined to a short list of readable paths, and a
# checkout under $HOME is often not on it, so the capture lives under TMPDIR.
WORK="${TMPDIR:-/tmp}/siphon-rf-acr-validation"
HEX="$WORK/rf_acr.hex"
PCAP="$WORK/rf_acr.pcap"

for tool in tshark text2pcap; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "$tool not found, install wireshark-common" >&2
    exit 1
  fi
done

mkdir -p "$WORK"
rm -f "$HEX" "$PCAP"

echo "encoding an ACR-EVENT the way diameter.rf_acr_event does"
SIPHON_RF_ACR_HEX_OUT="$HEX" \
  PYO3_PYTHON=python3 \
  cargo test --lib script::api::diameter::tests::emit_rf_acr_for_external_dissection -- --exact >/dev/null

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

# How deep an AVP sits in the dissected tree, as the indent of its code line.
indent_of() {
  grep -m1 -F "$1" <<<"$tree" | sed -E 's/^( *).*/\1/' | awk '{ print length($0) }'
}

echo "reading it back with tshark"
expect diameter.cmd.code 271
expect diameter.applicationId 3
expect diameter.Session-Id "pcscf.ims.mnc001.mcc001.3gppnetwork.org;1;1"
expect diameter.Accounting-Record-Type 1
expect diameter.3GPP-SIP-Method REGISTER

# One AVP per access-net-spec, read from Wireshark's dictionary rather than
# ours. The first value has no comma in it, so the aggregator's ',' is
# unambiguous here.
terminal="3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=0010100010000101"
expect diameter.Access-Network-Information "$terminal,$terminal;network-provided"

# Wireshark hands the value to its P-Access-Network-Info dissector; the cell
# identity it reads out of it is the 3GPP test network.
check_tree() {
  local label="$1" pattern="$2"
  if grep -qE "$pattern" <<<"$tree"; then
    echo "  ok   $label"
  else
    echo "  FAIL $label: not found in the dissected tree" >&2
    status=1
  fi
}
check_tree "access-type is 3GPP-E-UTRAN-FDD" 'access-type: 3GPP-E-UTRAN-FDD'
check_tree "the cell is in MCC 001" 'Mobile Country Code \(MCC\): Test network \(001\)'
check_tree "the second value is network-provided" '^ +network-provided$'

# TS 32.299: Access-Network-Information is a 3GPP AVP carrying V and M.
check_flags "Access-Network-Information flags M+V" \
  "AVP Code: 1263 Access-Network-Information" \
  "AVP Flags: 0xc0, Vendor-Specific: Set, Mandatory: Set" 2

# It is a member of IMS-Information, which is a member of Service-Information.
service="$(indent_of "AVP Code: 873 Service-Information")"
ims="$(indent_of "AVP Code: 876 IMS-Information")"
access="$(indent_of "AVP Code: 1263 Access-Network-Information")"
if [[ -n "$service" && -n "$ims" && -n "$access" && "$service" -lt "$ims" && "$ims" -lt "$access" ]]; then
  echo "  ok   Access-Network-Information nests under IMS-Information under Service-Information"
else
  echo "  FAIL nesting: Service-Information at '$service', IMS-Information at '$ims'," \
    "Access-Network-Information at '$access'" >&2
  status=1
fi

if grep -q "Unknown AVP" <<<"$tree"; then
  echo "  FAIL an AVP tshark does not recognise" >&2
  status=1
fi
if [[ -n "$(tshark -r "$PCAP" -Y '_ws.malformed || _ws.expert' 2>/dev/null)" ]]; then
  echo "  FAIL tshark flagged the ACR as malformed or raised expert info" >&2
  status=1
else
  echo "  ok   nothing malformed, no expert info"
fi

if [[ $status -ne 0 ]]; then
  echo "Rf ACR validation FAILED" >&2
  exit 1
fi

echo "Rf ACR validated against tshark's Diameter dissector"
