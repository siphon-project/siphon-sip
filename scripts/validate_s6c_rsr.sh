#!/usr/bin/env bash
#
# Validate the S6c Report-SM-Delivery-Status request encoder against
# Wireshark's Diameter dissector.
#
# The known-answer tests in src/diameter/s6c.rs pin bytes we chose, so they
# share whatever we misread of TS 29.338. That is how the outcome went out
# under SM-RP-MTI without a test noticing. This feeds one RSR per
# SM-Delivery-Cause to tshark, which decodes them with its own dictionary, and
# asserts it reads back what we meant.
#
#   scripts/validate_s6c_rsr.sh
#
# Needs tshark and text2pcap (wireshark-common). CI runners have neither, so
# run it locally after touching the RSR encoder in src/diameter/s6c.rs.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# tshark is commonly AppArmor-confined to a short list of readable paths, and a
# checkout under $HOME is often not on it, so the capture lives under TMPDIR.
WORK="${TMPDIR:-/tmp}/siphon-s6c-rsr-validation"
HEX="$WORK/s6c_rsr.hex"
PCAP="$WORK/s6c_rsr.pcap"

for tool in tshark text2pcap; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "$tool not found, install wireshark-common" >&2
    exit 1
  fi
done

mkdir -p "$WORK"
rm -f "$HEX" "$PCAP"

echo "encoding one RSR per SM-Delivery-Cause"
SIPHON_S6C_RSR_HEX_OUT="$HEX" \
  PYO3_PYTHON=python3 \
  cargo test --lib diameter::s6c::tests::emit_rsr_for_external_dissection -- --exact >/dev/null

if [[ ! -s "$HEX" ]]; then
  echo "the encoder produced nothing" >&2
  exit 1
fi

# 3868 is Diameter's registered port, so tshark's own dissector claims it.
text2pcap -q -T "3868,3868" "$HEX" "$PCAP"

status=0

# One line per RSR, the three of them joined with ','.
expect() {
  local field="$1" want="$2" got
  got="$(tshark -r "$PCAP" -T fields -e "$field" 2>/dev/null | paste -sd, -)"
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

echo "reading them back with tshark"
# TS 29.338 clause 5.3.2.7: command 8388649, application 16777312.
expect diameter.cmd.code 8388649,8388649,8388649
expect diameter.applicationId 16777312,16777312,16777312
expect diameter.flags.request True,True,True
# Clause 5.3.3.19: UE_MEMORY_CAPACITY_EXCEEDED, ABSENT_USER, SUCCESSFUL_TRANSFER.
expect diameter.SM-Delivery-Cause 0,1,2
expect diameter.User-Name 001010000000001,001010000000001,001010000000001

# Table 5.3.3.1/1: all three are 3GPP AVPs carrying V and M.
flags="AVP Flags: 0xc0, Vendor-Specific: Set, Mandatory: Set"
check_flags "User-Identifier flags M+V" "AVP Code: 3102 User-Identifier" "$flags" 3
check_flags "SM-Delivery-Outcome flags M+V" "AVP Code: 3316 SM-Delivery-Outcome" "$flags" 3
check_flags "MME-SM-Delivery-Outcome flags M+V" \
  "AVP Code: 3317 MME-SM-Delivery-Outcome" "$flags" 3
check_flags "SM-Delivery-Cause flags M+V" "AVP Code: 3321 SM-Delivery-Cause" "$flags" 3

# The cause is a member of MME-SM-Delivery-Outcome, which is a member of
# SM-Delivery-Outcome; the subscriber is a member of User-Identifier.
outcome="$(indent_of "AVP Code: 3316 SM-Delivery-Outcome")"
node="$(indent_of "AVP Code: 3317 MME-SM-Delivery-Outcome")"
cause="$(indent_of "AVP Code: 3321 SM-Delivery-Cause")"
if [[ -n "$outcome" && -n "$node" && -n "$cause" && "$outcome" -lt "$node" && "$node" -lt "$cause" ]]; then
  echo "  ok   SM-Delivery-Cause nests under MME-SM-Delivery-Outcome under SM-Delivery-Outcome"
else
  echo "  FAIL nesting: SM-Delivery-Outcome at '$outcome', MME-SM-Delivery-Outcome at" \
    "'$node', SM-Delivery-Cause at '$cause'" >&2
  status=1
fi
identifier="$(indent_of "AVP Code: 3102 User-Identifier")"
name="$(indent_of "AVP Code: 1 User-Name")"
if [[ -n "$identifier" && -n "$name" && "$identifier" -lt "$name" ]]; then
  echo "  ok   User-Name nests under User-Identifier"
else
  echo "  FAIL nesting: User-Identifier at '$identifier', User-Name at '$name'" >&2
  status=1
fi

if grep -q "Unknown AVP" <<<"$tree"; then
  echo "  FAIL an AVP tshark does not recognise" >&2
  status=1
fi
if [[ -n "$(tshark -r "$PCAP" -Y '_ws.malformed || _ws.expert' 2>/dev/null)" ]]; then
  echo "  FAIL tshark flagged an RSR as malformed or raised expert info" >&2
  status=1
else
  echo "  ok   nothing malformed, no expert info"
fi

if [[ $status -ne 0 ]]; then
  echo "S6c RSR validation FAILED" >&2
  exit 1
fi

echo "S6c RSR validated against tshark's Diameter dissector"
