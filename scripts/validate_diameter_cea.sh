#!/usr/bin/env bash
#
# Validate the Capabilities-Exchange-Answer of the Diameter listener against
# Wireshark's Diameter dissector.
#
# The tests in src/diameter/server.rs read the CEA back with the decoder that
# shares a dictionary with the encoder. This feeds three CEAs to tshark, which
# decodes them with its own: one admitting a peer on a node that serves S6a,
# Cx and Rf, one refusing a peer that has none of those, and one from a relay.
#
#   scripts/validate_diameter_cea.sh
#
# Needs tshark and text2pcap (wireshark-common). CI runners have neither, so
# run it locally after touching the handshake in src/diameter/server.rs or the
# CER/CEA encoder in src/diameter/peer.rs.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# tshark is commonly AppArmor-confined to a short list of readable paths, and a
# checkout under $HOME is often not on it, so the capture lives under TMPDIR.
WORK="${TMPDIR:-/tmp}/siphon-diameter-cea-validation"
HEX="$WORK/cea.hex"
PCAP="$WORK/cea.pcap"

for tool in tshark text2pcap; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "$tool not found, install wireshark-common" >&2
    exit 1
  fi
done

mkdir -p "$WORK"
rm -f "$HEX" "$PCAP"

echo "running the handshakes"
SIPHON_DIAMETER_CEA_HEX_OUT="$HEX" \
  PYO3_PYTHON="${PYO3_PYTHON:-python3}" \
  cargo test --lib diameter::server::tests::emit_cea_for_external_dissection -- --exact >/dev/null

if [[ ! -s "$HEX" ]]; then
  echo "the encoder produced nothing" >&2
  exit 1
fi

# 3868 is Diameter's registered port, so tshark's own dissector claims it.
text2pcap -q -T "3868,3868" "$HEX" "$PCAP"

status=0

# The value of `field` in frame `number`; repeated AVPs are joined with ','.
expect() {
  local frame="$1" field="$2" want="$3" got
  got="$(tshark -r "$PCAP" -Y "frame.number == $frame" -T fields -E occurrence=a \
    -e "$field" 2>/dev/null)"
  if [[ "$got" != "$want" ]]; then
    echo "  FAIL frame $frame $field: tshark read '$got', we meant '$want'" >&2
    status=1
    return
  fi
  echo "  ok   frame $frame $field = $got"
}

echo "reading them back with tshark"
for frame in 1 2 3; do
  expect "$frame" diameter.cmd.code 257
  expect "$frame" diameter.flags.request False
  expect "$frame" diameter.applicationId 0
done

# Admitted. S6a and Cx are 3GPP applications: each in its own
# Vendor-Specific-Application-Id under vendor 10415 and as a bare
# Auth-Application-Id. Rf is base accounting: Acct-Application-Id only.
expect 1 diameter.Result-Code 2001
expect 1 diameter.Auth-Application-Id 16777251,16777251,16777216,16777216
expect 1 diameter.Acct-Application-Id 3
# The first Vendor-Id is the node's own, the other two belong to the groups.
expect 1 diameter.Vendor-Id 0,10415,10415

# Refused: the peer offered Ro only. The answer still lists what is served.
expect 2 diameter.Result-Code 5010
expect 2 diameter.Auth-Application-Id 16777251,16777251,16777216,16777216
expect 2 diameter.Acct-Application-Id 3

# A relay: the Relay application id, outside any vendor group.
expect 3 diameter.Result-Code 2001
expect 3 diameter.Auth-Application-Id 4294967295
expect 3 diameter.Vendor-Id 0

tree="$(tshark -r "$PCAP" -V -O diameter 2>/dev/null)"

count() {
  local label="$1" pattern="$2" want="$3" got
  got="$(grep -cE "$pattern" <<<"$tree" || true)"
  if [[ "$got" != "$want" ]]; then
    echo "  FAIL $label: $got in the dissected tree, we meant $want" >&2
    status=1
    return
  fi
  echo "  ok   $label"
}

# Names read from Wireshark's dictionary rather than ours. tshark prints an
# AVP's value on its summary line and again in its body, so every count below
# is two per AVP.
count "S6a by name, twice in each of two answers" 'Auth-Application-Id: 3GPP S6a/S6d \(16777251\)' 8
count "Cx by name, twice in each of two answers" 'Auth-Application-Id: 3GPP Cx \(16777216\)' 8
count "Rf as base accounting in two answers" 'Acct-Application-Id: Diameter Base Accounting \(3\)' 4
count "Relay by name" 'Auth-Application-Id: Relay \(4294967295\)' 2
count "the refusal by name" 'Result-Code: DIAMETER_NO_COMMON_APPLICATION \(5010\)' 2
count "two vendor groups in each of two answers" 'AVP Code: 260 Vendor-Specific-Application-Id' 4

if grep -q "Unknown AVP" <<<"$tree"; then
  echo "  FAIL an AVP tshark does not recognise" >&2
  status=1
fi
if [[ -n "$(tshark -r "$PCAP" -Y '_ws.malformed || _ws.expert' 2>/dev/null)" ]]; then
  echo "  FAIL tshark flagged a CEA as malformed or raised expert info" >&2
  status=1
else
  echo "  ok   nothing malformed, no expert info"
fi

if [[ $status -ne 0 ]]; then
  echo "Diameter CEA validation FAILED" >&2
  exit 1
fi

echo "Diameter CEA validated against tshark's Diameter dissector"
