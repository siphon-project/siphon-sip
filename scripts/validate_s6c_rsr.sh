#!/usr/bin/env bash
#
# Validate the S6c Report-SM-Delivery-Status request encoder against
# Wireshark's Diameter dissector.
#
# The known-answer tests in src/diameter/s6c.rs pin bytes we chose, so they
# share whatever we misread of TS 29.338. That is how the outcome went out
# under SM-RP-MTI without a test noticing. This feeds seven RSRs to tshark,
# covering every cause, every node a delivery can be reported through and the
# absent user diagnostic. tshark decodes them with its own dictionary, and
# this asserts it reads back what we meant.
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

echo "encoding the RSRs"
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

# One line per RSR, joined with ','. An RSR without the AVP is an empty entry.
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

# The value of `field` in frame `number`.
field_in_frame() {
  tshark -r "$PCAP" -Y "frame.number == $1" -T fields -e "$2" 2>/dev/null
}

# The dissected tree of one frame.
tree_of_frame() {
  tshark -r "$PCAP" -Y "frame.number == $1" -V -O diameter 2>/dev/null
}

# One RSR: the node group tshark must find, and only that one, holding the
# cause and the diagnostic (empty when none was sent).
expect_outcome() {
  local frame="$1" node_line="$2" cause="$3" diagnostic="$4" frame_tree got other
  frame_tree="$(tree_of_frame "$frame")"
  if ! grep -qF "$node_line" <<<"$frame_tree"; then
    echo "  FAIL frame $frame: no '$node_line'" >&2
    status=1
    return
  fi
  for other in "${NODE_LINES[@]}"; do
    if [[ "$other" != "$node_line" ]] && grep -qF "$other" <<<"$frame_tree"; then
      echo "  FAIL frame $frame: also carries '$other'" >&2
      status=1
      return
    fi
  done
  got="$(field_in_frame "$frame" diameter.SM-Delivery-Cause)"
  if [[ "$got" != "$cause" ]]; then
    echo "  FAIL frame $frame: SM-Delivery-Cause '$got', we meant '$cause'" >&2
    status=1
    return
  fi
  got="$(field_in_frame "$frame" diameter.Absent-User-Diagnostic-SM)"
  if [[ "$got" != "$diagnostic" ]]; then
    echo "  FAIL frame $frame: Absent-User-Diagnostic-SM '$got', we meant '$diagnostic'" >&2
    status=1
    return
  fi
  echo "  ok   frame $frame: ${node_line#AVP Code: }, cause $cause${diagnostic:+, diagnostic $diagnostic}"
}

echo "reading them back with tshark"
all() { local value="$1" out="$1"; for _ in 2 3 4 5 6 7; do out="$out,$value"; done; echo "$out"; }
# TS 29.338 clause 5.3.2.7: command 8388649, application 16777312.
expect diameter.cmd.code "$(all 8388649)"
expect diameter.applicationId "$(all 16777312)"
expect diameter.flags.request "$(all True)"
expect diameter.User-Name "$(all 001010000000001)"

# Clauses 5.3.3.15 to 5.3.3.18, named by Wireshark's dictionary, not ours.
NODE_LINES=(
  "AVP Code: 3317 MME-SM-Delivery-Outcome"
  "AVP Code: 3318 MSC-SM-Delivery-Outcome"
  "AVP Code: 3319 SGSN-SM-Delivery-Outcome"
  "AVP Code: 3320 IP-SM-GW-SM-Delivery-Outcome"
)
# Clause 5.3.3.19: 0 UE_MEMORY_CAPACITY_EXCEEDED, 1 ABSENT_USER,
# 2 SUCCESSFUL_TRANSFER. The order is that of
# `outcomes_for_external_dissection` in src/diameter/s6c.rs.
expect_outcome 1 "${NODE_LINES[0]}" 0 ""
expect_outcome 2 "${NODE_LINES[0]}" 1 ""
expect_outcome 3 "${NODE_LINES[0]}" 2 ""
expect_outcome 4 "${NODE_LINES[1]}" 1 1
expect_outcome 5 "${NODE_LINES[2]}" 1 6
expect_outcome 6 "${NODE_LINES[3]}" 1 12
expect_outcome 7 "${NODE_LINES[2]}" 2 ""

# Table 5.3.3.1/1: all of them are 3GPP AVPs carrying V and M.
flags="AVP Flags: 0xc0, Vendor-Specific: Set, Mandatory: Set"
check_flags "User-Identifier flags M+V" "AVP Code: 3102 User-Identifier" "$flags" 7
check_flags "SM-Delivery-Outcome flags M+V" "AVP Code: 3316 SM-Delivery-Outcome" "$flags" 7
check_flags "MME-SM-Delivery-Outcome flags M+V" "${NODE_LINES[0]}" "$flags" 3
check_flags "MSC-SM-Delivery-Outcome flags M+V" "${NODE_LINES[1]}" "$flags" 1
check_flags "SGSN-SM-Delivery-Outcome flags M+V" "${NODE_LINES[2]}" "$flags" 2
check_flags "IP-SM-GW-SM-Delivery-Outcome flags M+V" "${NODE_LINES[3]}" "$flags" 1
check_flags "SM-Delivery-Cause flags M+V" "AVP Code: 3321 SM-Delivery-Cause" "$flags" 7
check_flags "Absent-User-Diagnostic-SM flags M+V" \
  "AVP Code: 3322 Absent-User-Diagnostic-SM" "$flags" 3

# The cause and the diagnostic are members of the node's group, which is a
# member of SM-Delivery-Outcome; the subscriber is a member of User-Identifier.
# Frame 5 carries all of them.
tree="$(tree_of_frame 5)"
outcome="$(indent_of "AVP Code: 3316 SM-Delivery-Outcome")"
node="$(indent_of "${NODE_LINES[2]}")"
cause="$(indent_of "AVP Code: 3321 SM-Delivery-Cause")"
diagnostic="$(indent_of "AVP Code: 3322 Absent-User-Diagnostic-SM")"
if [[ -n "$outcome" && -n "$node" && -n "$cause" && -n "$diagnostic" \
  && "$outcome" -lt "$node" && "$node" -lt "$cause" && "$cause" -eq "$diagnostic" ]]; then
  echo "  ok   the cause and the diagnostic nest under the node's group under SM-Delivery-Outcome"
else
  echo "  FAIL nesting: SM-Delivery-Outcome at '$outcome', the node's group at '$node'," \
    "SM-Delivery-Cause at '$cause', Absent-User-Diagnostic-SM at '$diagnostic'" >&2
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
tree="$(tshark -r "$PCAP" -V -O diameter 2>/dev/null)"

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
