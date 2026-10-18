#!/usr/bin/env bash
#
# Validate the Ro session primitive's wire output against Wireshark's Diameter
# dissector.
#
# The unit tests in src/diameter/ro_session_tests.rs decode what a loopback OCS
# received with siphon's own dictionary, which shares whatever we misread of
# RFC 8506 / TS 32.299. This has tshark — its own dictionary, its own codec —
# decode the CCRs of two concurrent sessions (one charged to the caller, one to
# a forwarding user, the second externally metered) and the answers siphon
# gives to a RAR and an ASR, and asserts it reads back what we meant.
#
#   scripts/validate_ro_sessions.sh
#
# Needs tshark and text2pcap (wireshark-common). CI runners have neither, so
# run it locally after touching src/diameter/ro.rs or ro_service.rs.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# tshark is commonly AppArmor-confined to a short list of readable paths.
WORK="${TMPDIR:-/tmp}/siphon-ro-sessions-validation"
HEX="$WORK/ro_sessions.hex"
PCAP="$WORK/ro_sessions.pcap"

for tool in tshark text2pcap; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "$tool not found, install wireshark-common" >&2
    exit 1
  fi
done

mkdir -p "$WORK"
rm -f "$HEX" "$PCAP"

echo "running two Ro sessions against a loopback OCS"
SIPHON_RO_SESSIONS_HEX_OUT="$HEX" \
  PYO3_PYTHON="${PYO3_PYTHON:-python3}" \
  cargo test --lib diameter::ro_service::session_tests::emit_ro_sessions_for_external_dissection \
  -- --exact >/dev/null

if [[ ! -s "$HEX" ]]; then
  echo "the encoder produced nothing" >&2
  exit 1
fi

text2pcap -q -T "3868,3868" "$HEX" "$PCAP"

status=0
fields() {
  tshark -r "$PCAP" -T fields -E separator='|' -E occurrence=a "$@" 2>/dev/null
}

expect_eq() {
  local label="$1" want="$2" got="$3"
  if [[ "$got" != "$want" ]]; then
    echo "  FAIL $label: tshark read '$got', we meant '$want'" >&2
    status=1
  else
    echo "  ok   $label = $got"
  fi
}

# Frames, in order: CCR-I caller, CCR-I forwarder, CCR-U forwarder,
# CCR-T forwarder, CCR-T caller, CCR-I and CCR-T of a Proxy Function's
# session for a forwarded CS call (TS 32.276, MF), RAA, ASA.
expect_eq "commands" \
  "272,1|272,1|272,1|272,1|272,1|272,1|272,1|258,0|274,0" \
  "$(fields -e diameter.cmd.code -e diameter.flags.request \
      | sed 's/\t/,/; s/|/,/; s/True$/1/; s/False$/0/' | paste -sd'|')"
expect_eq "CC-Request-Type" "1|1|2|3|3|1|3||" \
  "$(fields -e diameter.CC-Request-Type | paste -sd'|')"
expect_eq "CC-Request-Number" "0|0|1|2|1|0|1||" \
  "$(fields -e diameter.CC-Request-Number | paste -sd'|')"
expect_eq "Subscription-Id-Type" "2|0|0|0|2|0,1|0,1||" \
  "$(fields -e diameter.Subscription-Id-Type | paste -sd'|')"
expect_eq "Subscription-Id-Data" \
  "sip:+15550100001@ims.example.net|15550100002|15550100002|15550100002|sip:+15550100001@ims.example.net|15550100004,001010000000004|15550100004,001010000000004||" \
  "$(fields -e diameter.Subscription-Id-Data | paste -sd'|')"
expect_eq "Role-Of-Node" "0|2|2|2|0|2|2||" \
  "$(fields -e diameter.Role-Of-Node | paste -sd'|')"
expect_eq "CC-Time (last of RSU, USU)" "30|30|12|8|0|30|30||" \
  "$(fields -e diameter.CC-Time | paste -sd'|' | sed 's/[^|]*,//g')"
expect_eq "Result-Code (RAA, ASA)" "|||||||2001|5002" \
  "$(fields -e diameter.Result-Code | paste -sd'|')"
expect_eq "Auth-Application-Id" "4|4|4|4|4|4|4||" \
  "$(fields -e diameter.Auth-Application-Id | paste -sd'|')"

# The two sessions are two Session-Ids; each keeps its own across its requests.
mapfile -t sessions < <(fields -e diameter.Session-Id)
if [[ "${sessions[0]}" != "${sessions[4]}" || "${sessions[1]}" != "${sessions[2]}" \
      || "${sessions[1]}" != "${sessions[3]}" || "${sessions[0]}" == "${sessions[1]}" ]]; then
  echo "  FAIL Session-Id: not one per session: ${sessions[*]}" >&2
  status=1
else
  echo "  ok   Session-Id: two sessions, each constant"
fi
if [[ "${sessions[7]}" != "${sessions[0]}" ]]; then
  echo "  FAIL RAA Session-Id ${sessions[7]} is not the session's ${sessions[0]}" >&2
  status=1
else
  echo "  ok   RAA carries the session's Session-Id"
fi

expect_eq "Service-Context-Id" \
  "32260@3gpp.org|32260@3gpp.org|32260@3gpp.org|32260@3gpp.org|32260@3gpp.org|32276@3gpp.org|32276@3gpp.org||" \
  "$(fields -e diameter.Service-Context-Id | paste -sd'|')"
expect_eq "Node-Functionality (Proxy Function on the CAMEL session)" \
  "6|6|6|6|6|16|16||" \
  "$(fields -e diameter.Node-Functionality | paste -sd'|')"
# VCS-Information members, frame 6 (the CAMEL CCR-I). The addresses are
# TBCD digits only (TS 32.299 7.2.111B, 7.2.242B).
vcs="$(tshark -r "$PCAP" -Y frame.number==6 -T fields -E occurrence=a -E separator='|' \
  -e diameter.MSC-Address -e diameter.Network-Call-Reference-Number \
  -e diameter.Teleservice -e diameter.VLR-Number 2>/dev/null)"
expect_eq "VCS-Information (MSC, NCRN, teleservice, VLR)" \
  "51551000f9|01020304|11|51551000f8" "$vcs"
# ISUP-Cause and Stop-Time are TERMINATION-only (TS 32.276 table 6.3.1.4.1):
# on frame 7, not on frame 6. Start-Time on both.
expect_eq "ISUP-Cause-Value (CAMEL CCR-I, CCR-T)" "|16" \
  "$(fields -Y 'frame.number==6 || frame.number==7' -e diameter.ISUP-Cause-Value | paste -sd'|')"
expect_eq "Stop-Time present (CAMEL CCR-I, CCR-T)" "0|1" \
  "$(fields -Y 'frame.number==6 || frame.number==7' -e diameter.Stop-Time | awk '{print (length($0)>0)}' | paste -sd'|')"
expect_eq "Start-Time present (CAMEL CCR-I, CCR-T)" "1|1" \
  "$(fields -Y 'frame.number==6 || frame.number==7' -e diameter.Start-Time | awk '{print (length($0)>0)}' | paste -sd'|')"
expect_eq "ISUP-Cause group (AVP 3416) on the CCR-T" "1" \
  "$(tshark -r "$PCAP" -Y 'frame.number==7 && diameter.avp.code==3416' 2>/dev/null | wc -l)"

tree="$(tshark -r "$PCAP" -V -O diameter 2>/dev/null)"
for broken in "Malformed" "Unknown AVP" "Undecoded"; do
  if grep -q "$broken" <<<"$tree"; then
    echo "  FAIL tshark reports '$broken' somewhere in the dissection" >&2
    grep -n "$broken" <<<"$tree" | head -5 >&2
    status=1
  fi
done

if [[ $status -eq 0 ]]; then
  echo "tshark agrees with the encoder"
fi
exit $status
