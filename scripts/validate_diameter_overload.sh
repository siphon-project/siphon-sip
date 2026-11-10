#!/usr/bin/env bash
#
# Validate the DOIC AVPs (RFC 7683) against Wireshark's Diameter dissector.
#
# The tests in src/diameter/overload.rs compare the encoding with bytes
# assembled by hand from the RFC. This has a third party read it: the
# OC-Supported-Features of a request, the answer of a reporting node with an
# OC-OLR, and an OC-OLR of a realm report with the extreme values, all read
# back by tshark's own dictionary, with no [Malformed] and no unknown AVP.
#
#   frame 1  request (DWR-sized base command 280) with OC-Supported-Features
#   frame 2  its answer with OC-Supported-Features and OC-OLR (30 %, host)
#   frame 3  an answer with a realm report, 100 %, 86400 s, a 64-bit sequence
#
# Needs tshark and text2pcap (wireshark-common).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

WORK="${TMPDIR:-/tmp}/siphon-diameter-overload-validation"
HEX="$WORK/overload.hex"
PCAP="$WORK/overload.pcap"

for tool in tshark text2pcap; do
  command -v "$tool" >/dev/null 2>&1 || { echo "$tool not found, install wireshark-common" >&2; exit 1; }
done

mkdir -p "$WORK"
rm -f "$HEX" "$PCAP"

SIPHON_DIAMETER_OVERLOAD_HEX_OUT="$HEX" \
  PYO3_PYTHON="${PYO3_PYTHON:-python3}" \
  cargo test --lib -- --exact \
  diameter::overload::tests::emit_doic_messages_for_external_dissection >/dev/null

[[ -s "$HEX" ]] || { echo "the encoder produced nothing" >&2; exit 1; }

text2pcap -q -T "3868,3868" "$HEX" "$PCAP"

status=0
field() {
  tshark -r "$PCAP" -Y "frame.number == $1" -T fields -E occurrence=a -E aggregator='|' -e "$2" 2>/dev/null | head -1
}
expect() {
  local got
  got="$(field "$1" "$2")"
  if [[ "$got" != "$3" ]]; then
    echo "  FAIL frame $1 $2: tshark read '$got', we meant '$3'" >&2
    status=1
    return
  fi
  echo "  ok   frame $1 $2 = $got"
}

if tshark -r "$PCAP" -V 2>/dev/null | grep -Eiq '\[malformed|unknown avp|expert info'; then
  echo "  FAIL tshark flags a malformed or unknown AVP" >&2
  tshark -r "$PCAP" -V 2>/dev/null | grep -Ei '\[malformed|unknown avp|expert info' >&2
  status=1
else
  echo "  ok   no [Malformed] and no unknown AVP in any frame"
fi

expect 1 diameter.OC-Feature-Vector "1"
expect 2 diameter.OC-Feature-Vector "1"
[[ -n "$(field 2 diameter.OC-Sequence-Number)" ]] || { echo "  FAIL frame 2 has no OC-Sequence-Number" >&2; status=1; }
expect 2 diameter.OC-Report-Type "0"
expect 2 diameter.OC-Reduction-Percentage "30"
expect 2 diameter.OC-Validity-Duration "30"
expect 3 diameter.OC-Sequence-Number "72623859790382856"
expect 3 diameter.OC-Report-Type "1"
expect 3 diameter.OC-Reduction-Percentage "100"
expect 3 diameter.OC-Validity-Duration "86400"

# No M and no V bit on any OC AVP (RFC 7683 section 7.1).
if tshark -r "$PCAP" -V -O diameter 2>/dev/null | awk '/AVP Code: 62[1-7] /{p=1;next} p&&/AVP Flags:/{print; p=0}' | grep -Eq 'Flags: 0x(4|8|c)'; then
  echo "  FAIL an OC AVP carries the M or V bit" >&2
  status=1
else
  echo "  ok   no OC AVP carries the M or V bit"
fi

exit "$status"
