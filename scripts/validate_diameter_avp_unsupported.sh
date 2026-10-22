#!/usr/bin/env bash
#
# Validate two answers a policy server builds against Wireshark's Diameter
# dissector:
#
#   frame 1  the DIAMETER_AVP_UNSUPPORTED (5001) answer that
#            `DiameterRequest.reject_unsupported_avps` builds for a Gx CCR
#            carrying unknown AVPs with the M bit (RFC 6733 sections 4.1,
#            7.1.5 and 7.5): Result-Code 5001, no E bit, one Failed-AVP
#            holding the top-level offender as received and the nested one
#            inside its QoS-Information
#   frame 2  an Rx AA-Answer carrying Acceptable-Service-Info, which TS
#            29.214 table 5.3.0.1 lists M,V under "Must"
#
# The unit tests in src/script/api/diameter_server.rs read the answers back
# with siphon's own decoder; tshark reads them with its own.
#
#   scripts/validate_diameter_avp_unsupported.sh
#
# Needs tshark and text2pcap (wireshark-common). CI runners have neither, so
# run it locally after touching src/diameter/unknown_avp.rs or the answer
# builders in src/script/api/diameter_server.rs.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# tshark is commonly AppArmor-confined to a short list of readable paths, and a
# checkout under $HOME is often not on it, so the capture lives under TMPDIR.
WORK="${TMPDIR:-/tmp}/siphon-diameter-avp-unsupported-validation"
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
SIPHON_DIAMETER_AVP_UNSUPPORTED_HEX_OUT="$HEX" \
  PYO3_PYTHON="${PYO3_PYTHON:-python3}" \
  cargo test --lib -- --exact \
  script::api::diameter_server::tests::emit_avp_unsupported_answers_for_external_dissection >/dev/null

if [[ ! -s "$HEX" ]]; then
  echo "the encoder produced nothing" >&2
  exit 1
fi

text2pcap -q -T "3868,3868" "$HEX" "$PCAP"

status=0

field() {
  tshark -r "$PCAP" -Y "frame.number == $1" -T fields -E occurrence=a -E aggregator='|' \
    -e "$2" 2>/dev/null | head -1
}

expect() {
  local frame="$1" name="$2" want="$3" got
  got="$(field "$frame" "$name")"
  if [[ "$got" != "$want" ]]; then
    echo "  FAIL frame $frame $name: tshark read '$got', we meant '$want'" >&2
    status=1
    return
  fi
  echo "  ok   frame $frame $name = $got"
}

# Each AVP header of a frame, in wire order, as "code flags depth": the depth
# is the indentation tshark nests a member under its group with.
headers() {
  tshark -r "$PCAP" -Y "frame.number == $1" -V -O diameter 2>/dev/null |
    awk '/AVP Code: / { depth = match($0, /[^ ]/); split($0, words, "AVP Code: "); split(words[2], code, " "); pending = code[1]; next }
      pending != "" && /AVP Flags:/ { sub(/^ +AVP Flags: /, ""); sub(/,.*/, ""); print pending, $0, depth; pending = "" }'
}

echo "5001 answer to a CCR with unknown M-bit AVPs"
expect 1 diameter.cmd.code 272
expect 1 diameter.flags.request False
expect 1 diameter.flags.error False
expect 1 diameter.Result-Code 5001
expect 1 diameter.Auth-Application-Id 16777238
avps="$(headers 1)"
failed="$(awk '$1 == 279' <<<"$avps")"
if [[ "$(wc -l <<<"$failed")" == 1 && "$(awk '{ print $2 }' <<<"$failed")" == 0x40 ]]; then
  echo "  ok   frame 1: one Failed-AVP, M set, no V"
else
  echo "  FAIL frame 1: Failed-AVP headers '$failed'" >&2
  status=1
fi
# Inside it, in order: 64000 (M,V) one level down, then QoS-Information (M,V)
# one level down holding 64002 (M,V) two levels down. The 64001 without the M
# bit is not there.
inside="$(awk 'seen { print $1, $2 } $1 == 279 { seen = 1 }' <<<"$avps" | tr '\n' ';')"
if [[ "$inside" == "64000 0xc0;1016 0xc0;64002 0xc0;" ]]; then
  echo "  ok   frame 1: Failed-AVP holds 64000, and 64002 inside QoS-Information, flags as received"
else
  echo "  FAIL frame 1: Failed-AVP holds '$inside'" >&2
  status=1
fi
depths="$(awk 'seen { print $3 } $1 == 279 { seen = 1 }' <<<"$avps" | tr '\n' ' ')"
read -r first group nested <<<"$depths"
if [[ "$first" == "$group" && "$nested" -gt "$group" ]]; then
  echo "  ok   frame 1: 64002 nested below QoS-Information"
else
  echo "  FAIL frame 1: nesting depths '$depths'" >&2
  status=1
fi

echo "Rx AA-Answer with Acceptable-Service-Info"
expect 2 diameter.cmd.code 265
expect 2 diameter.Result-Code 5003
expect 2 diameter.Max-Requested-Bandwidth-DL 64000
expect 2 diameter.Max-Requested-Bandwidth-UL 64000
acceptable="$(headers 2 | awk '$1 == 526 { print $2 }')"
if [[ "$acceptable" == 0xc0 ]]; then
  echo "  ok   frame 2: Acceptable-Service-Info flags 0xc0 (M,V must, TS 29.214 table 5.3.0.1)"
else
  echo "  FAIL frame 2: Acceptable-Service-Info flags '$acceptable', want 0xc0" >&2
  status=1
fi

# Frame 1 carries AVPs no dictionary defines on purpose, which tshark notes as
# expert info; neither frame may be malformed.
if [[ -n "$(tshark -r "$PCAP" -Y '_ws.malformed' 2>/dev/null)" ]]; then
  echo "  FAIL tshark flagged an answer as malformed" >&2
  status=1
else
  echo "  ok   nothing malformed"
fi
if [[ -n "$(tshark -r "$PCAP" -Y 'frame.number == 2 && _ws.expert' 2>/dev/null)" ]]; then
  echo "  FAIL tshark raised expert info on the AA-Answer" >&2
  status=1
fi

if [[ $status -ne 0 ]]; then
  echo "DIAMETER_AVP_UNSUPPORTED validation FAILED" >&2
  exit 1
fi
echo "the 5001 answer and Acceptable-Service-Info validated against tshark's Diameter dissector"
