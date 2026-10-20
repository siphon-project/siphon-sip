#!/usr/bin/env bash
#
# Validate the requests `diameter.originate` sends against Wireshark's
# Diameter dissector.
#
# The tests in src/script/api/diameter_originate.rs and
# src/diameter/originate.rs read the requests back with siphon's own codec,
# so they share whatever siphon gets wrong about the dictionary. This builds
# the requests from the AVP lists a script passes and asserts tshark, with
# its own dictionary, reads the command, application, flags, Session-Id and
# the required AVPs of each:
#
#   frame 1   Cx Registration-Termination-Request (TS 29.229 clause 6.1.9)
#   frame 2   Sh Push-Notification-Request        (TS 29.329 clause 6.1.7)
#   frame 3   Rx Abort-Session-Request            (TS 29.214 clause 5.6.7)
#   frame 4   Rx Re-Auth-Request                  (TS 29.214 clause 5.6.3)
#   frame 5   Gx Re-Auth-Request with a rule      (TS 29.212 clause 5.6.4)
#   frames 6-8 Gx CCR-I, CCR-U, CCR-T on one session (TS 29.212 clause 5.6.2)
#   frames 9-11 S6a CLR, IDR, DSR                 (TS 29.272 clauses 7.2.7, 7.2.9, 7.2.11)
#
#   scripts/validate_diameter_originate.sh
#
# Needs tshark and text2pcap (wireshark-common). CI runners have neither, so
# run it locally after touching src/diameter/originate.rs,
# src/script/api/diameter_originate.rs, the AVP construction in
# src/script/api/diameter_server.rs or the dictionary.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# tshark is commonly AppArmor-confined to a short list of readable paths, and a
# checkout under $HOME is often not on it, so the capture lives under TMPDIR.
WORK="${TMPDIR:-/tmp}/siphon-diameter-originate-validation"
HEX="$WORK/originate.hex"
PCAP="$WORK/originate.pcap"

for tool in tshark text2pcap; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "$tool not found, install wireshark-common" >&2
    exit 1
  fi
done

mkdir -p "$WORK"
rm -f "$HEX" "$PCAP"

echo "building the requests from a script's AVP lists"
SIPHON_DIAMETER_ORIGINATE_HEX_OUT="$HEX" \
  PYO3_PYTHON="${PYO3_PYTHON:-python3}" \
  cargo test --lib -- --exact \
  script::api::diameter_originate::tests::emit_originated_requests_for_external_dissection >/dev/null

if [[ ! -s "$HEX" ]]; then
  echo "the encoder produced nothing" >&2
  exit 1
fi

# 3868 is Diameter's registered port, so tshark's own dissector claims it.
text2pcap -q -T "3868,3868" "$HEX" "$PCAP"

status=0

field() {
  local frame="$1" name="$2"
  tshark -r "$PCAP" -Y "frame.number == $frame" -T fields -E occurrence=a -E aggregator='|' \
    -e "$name" 2>/dev/null | head -1
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

# The flags line of the first AVP with `code` in `frame`, as tshark prints it.
avp_flags() {
  local frame="$1" code="$2"
  tshark -r "$PCAP" -Y "frame.number == $frame" -V -O diameter 2>/dev/null |
    awk -v code="AVP Code: $code " 'index($0, code) { pending = 1; next }
      pending && /AVP Flags:/ { pending = 0; sub(/^ +/, ""); sub(/,.*/, ""); print; exit }'
}

expect_flags() {
  local frame="$1" code="$2" want="$3" got
  got="$(avp_flags "$frame" "$code")"
  if [[ "$got" != "AVP Flags: $want" ]]; then
    echo "  FAIL frame $frame AVP $code: '$got', want flags $want" >&2
    status=1
    return
  fi
  echo "  ok   frame $frame AVP $code flags $want"
}

# The envelope every request starts with: Session-Id first (RFC 6733 section
# 3), exactly one, then Origin-Host, Origin-Realm, Destination-Host when the
# request names one, Destination-Realm.
envelope() {
  local frame="$1" code="$2" application="$3" origin="$4" realm="$5" host="$6" destination="$7"
  expect "$frame" diameter.cmd.code "$code"
  expect "$frame" diameter.applicationId "$application"
  expect "$frame" diameter.flags.request True
  expect "$frame" diameter.flags.proxyable True
  expect "$frame" diameter.flags.error False
  expect "$frame" diameter.Origin-Host "$origin"
  expect "$frame" diameter.Origin-Realm "$realm"
  expect "$frame" diameter.Destination-Host "$host"
  expect "$frame" diameter.Destination-Realm "$destination"
  local sessions first
  sessions="$(field "$frame" diameter.Session-Id)"
  if [[ -z "$sessions" || "$sessions" == *"|"* ]]; then
    echo "  FAIL frame $frame: Session-Id '$sessions', want exactly one" >&2
    status=1
  fi
  first="$(field "$frame" diameter.avp.code | cut -d'|' -f1)"
  if [[ "$first" != "263" ]]; then
    echo "  FAIL frame $frame: first AVP $first, want Session-Id 263" >&2
    status=1
  fi
}

IMS="ims.mnc001.mcc001.3gppnetwork.org"
EPC="epc.mnc001.mcc001.3gppnetwork.org"
HSS="hss.$IMS"
PCRF="pcrf.$EPC"
PGW="pgw.$EPC"
IMPI="001010000000001@$IMS"
GX_SESSION="$PGW;1;1"
RX_SESSION="pcscf.$IMS;2;1"

echo "Cx RTR"
envelope 1 304 16777216 "$HSS" "$IMS" "scscf.$IMS" "$IMS"
expect 1 diameter.Vendor-Id 10415
expect 1 diameter.Auth-Application-Id 16777216
expect 1 diameter.Auth-Session-State 1
expect 1 diameter.User-Name "$IMPI"
expect 1 diameter.Public-Identity "sip:$IMPI|sip:alice@$IMS"
expect 1 diameter.Reason-Code 0
expect 1 diameter.Reason-Info "subscription withdrawn"
expect_flags 1 615 "0xc0"

echo "Sh PNR"
envelope 2 309 16777217 "$HSS" "$IMS" "as.$IMS" "$IMS"
expect 2 diameter.Auth-Application-Id 16777217
expect 2 diameter.Auth-Session-State 1
expect 2 diameter.Public-Identity "sip:alice@$IMS"
expect_flags 2 700 "0xc0"
expect_flags 2 702 "0xc0"
if [[ -z "$(field 2 diameter.Sh-User-Data)$(field 2 diameter.User-Data)" ]]; then
  echo "  FAIL frame 2: no User-Data" >&2
  status=1
fi

echo "Rx ASR"
envelope 3 274 16777236 "$PCRF" "$EPC" "pcscf.$IMS" "$IMS"
expect 3 diameter.Session-Id "$RX_SESSION"
expect 3 diameter.Auth-Application-Id 16777236
expect 3 diameter.Abort-Cause 0
expect 3 diameter.Auth-Session-State ""

echo "Rx RAR"
envelope 4 258 16777236 "$PCRF" "$EPC" "pcscf.$IMS" "$IMS"
expect 4 diameter.Session-Id "$RX_SESSION"
expect 4 diameter.Auth-Application-Id 16777236
expect 4 diameter.Re-Auth-Request-Type 0
expect 4 diameter.Specific-Action "2|4"
expect 4 diameter.Auth-Session-State ""

echo "Gx RAR with a rule installation"
envelope 5 258 16777238 "$PCRF" "$EPC" "$PGW" "$EPC"
expect 5 diameter.Session-Id "$GX_SESSION"
expect 5 diameter.Auth-Application-Id 16777238
expect 5 diameter.Re-Auth-Request-Type 0
expect 5 diameter.Event-Trigger "2|13"
expect 5 diameter.Charging-Rule-Name "$(printf '%s' ims-voice | od -An -tx1 | tr -d ' \n')|$(printf '%s' ims-signalling | od -An -tx1 | tr -d ' \n')"
expect 5 diameter.Flow-Description \
  "permit out 17 from 198.51.100.20 50000 to 198.51.100.7 40000|permit out 17 from 198.51.100.7 40000 to 198.51.100.20 50000"
expect 5 diameter.Flow-Direction "1|2"
expect 5 diameter.QoS-Class-Identifier 1
expect 5 diameter.Max-Requested-Bandwidth-UL 64000
expect 5 diameter.Guaranteed-Bitrate-DL 64000
expect 5 diameter.Priority-Level 2
expect 5 diameter.Pre-emption-Capability 0
expect 5 diameter.Pre-emption-Vulnerability 1
expect 5 diameter.Precedence "100|50"
expect_flags 5 1001 "0xc0"
expect_flags 5 1003 "0xc0"
expect_flags 5 1058 "0x80"
expect_flags 5 1080 "0x80"
# Wireshark's dictionary has these as M must; TS 29.212 table 5.3.1 (Rel-18)
# lists them V must, M must not, and the table is what is held here.
for code in 1034 1046 1047 1048; do
  expect_flags 5 "$code" "0x80"
done
expect_flags 5 1016 "0xc0"
expect_flags 5 1028 "0xc0"
# Two definitions inside the one Charging-Rule-Install, two flows inside the
# first: the nesting tshark sees, by indentation of the AVP code lines.
tree="$(tshark -r "$PCAP" -Y 'frame.number == 5' -V -O diameter 2>/dev/null)"
install_indent="$(grep -F 'AVP Code: 1001 ' <<<"$tree" | head -1 | sed -E 's/[^ ].*//' | wc -c)"
definition_indent="$(grep -F 'AVP Code: 1003 ' <<<"$tree" | sed -E 's/[^ ].*//' | awk '{ print length($0) + 1 }' | sort -u)"
flow_indent="$(grep -F 'AVP Code: 1058 ' <<<"$tree" | sed -E 's/[^ ].*//' | awk '{ print length($0) + 1 }' | sort -u)"
if [[ "$(grep -cF 'AVP Code: 1003 ' <<<"$tree")" == 2 && "$(grep -cF 'AVP Code: 1058 ' <<<"$tree")" == 2 &&
  "$definition_indent" -gt "$install_indent" && "$flow_indent" -gt "$definition_indent" ]]; then
  echo "  ok   frame 5: two Charging-Rule-Definitions in Charging-Rule-Install, two Flow-Information nested below"
else
  echo "  FAIL frame 5: the rule nesting tshark reads is not the one built" >&2
  status=1
fi

echo "Gx CCR-I, CCR-U, CCR-T on one session"
for check in "6 1 0" "7 2 1" "8 3 2"; do
  read -r frame request_type number <<<"$check"
  envelope "$frame" 272 16777238 "$PGW" "$EPC" "" "$EPC"
  expect "$frame" diameter.Session-Id "$GX_SESSION"
  expect "$frame" diameter.Auth-Application-Id 16777238
  expect "$frame" diameter.CC-Request-Type "$request_type"
  expect "$frame" diameter.CC-Request-Number "$number"
done
expect 6 diameter.Subscription-Id-Type "1|3"
expect 6 diameter.Subscription-Id-Data "001010000000001|001010000000001@nai.$EPC"
expect 6 diameter.IP-CAN-Type 5
expect 6 diameter.RAT-Type 1004
expect 6 diameter.Framed-IP-Address.IPv4 198.51.100.7
expect 6 diameter.Called-Station-Id ims
expect_flags 6 1032 "0x80"
expect 7 diameter.Event-Trigger 13
expect 8 diameter.Termination-Cause 1
# Each request its own identifiers.
ids="$(tshark -r "$PCAP" -Y 'frame.number >= 6 && frame.number <= 8' -T fields \
  -e diameter.hopbyhopid -e diameter.endtoendid 2>/dev/null | sort -u | wc -l)"
if [[ "$ids" == 3 ]]; then
  echo "  ok   CCR-I/U/T: three distinct hop-by-hop and end-to-end identifiers"
else
  echo "  FAIL CCR-I/U/T share identifiers" >&2
  status=1
fi

echo "S6a CLR, IDR, DSR"
for check in "9 317" "10 319" "11 320"; do
  read -r frame code <<<"$check"
  envelope "$frame" "$code" 16777251 "$HSS" "$IMS" "mme.$EPC" "$EPC"
  expect "$frame" diameter.Auth-Application-Id 16777251
  expect "$frame" diameter.Auth-Session-State 1
  expect "$frame" diameter.User-Name 001010000000001
done
expect 9 diameter.Cancellation-Type 2
expect 9 diameter.CLR-Flags 2
expect_flags 9 1638 "0x80"
expect 10 diameter.Subscriber-Status 0
expect 10 diameter.IDR-Flags 1
expect 11 diameter.DSR-Flags 8

if [[ -n "$(tshark -r "$PCAP" -Y '_ws.malformed || _ws.expert' 2>/dev/null)" ]]; then
  echo "  FAIL tshark flagged a request as malformed or raised expert info:" >&2
  tshark -r "$PCAP" -Y '_ws.malformed || _ws.expert' -T fields -e frame.number -e _ws.expert.message 2>/dev/null >&2
  status=1
else
  echo "  ok   nothing malformed, no expert info, no unknown AVP"
fi

if [[ $status -ne 0 ]]; then
  echo "diameter.originate validation FAILED" >&2
  exit 1
fi
echo "the requests diameter.originate sends validated against tshark's Diameter dissector"
