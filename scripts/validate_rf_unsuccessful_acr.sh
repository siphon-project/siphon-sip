#!/usr/bin/env bash
#
# Validate the Rf ACR-EVENT of an unsuccessful session set-up against
# Wireshark's Diameter dissector.
#
# A proxy's cancelled, busy and redirected calls are driven through the
# dispatcher against a loopback CDF, and the ACR octets it was sent are read
# back by tshark with its own dictionary: one EVENT_RECORD each, the INVITE
# as SIP-Method, originating P-CSCF, and the Cause-Code TS 32.299 V18.0.0
# clause 7.2.35 gives the final status (487 and 486 positive, 302 as -302).
#
#   scripts/validate_rf_unsuccessful_acr.sh
#
# Needs tshark and text2pcap (wireshark-common). CI runners have neither, so
# run it locally after touching the Rf emitters in src/dispatcher/charging/rf.rs
# or the Cause-Code mapping in src/diameter/rf.rs.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# tshark is commonly AppArmor-confined to a short list of readable paths, and a
# checkout under $HOME is often not on it, so the captures live under TMPDIR.
WORK="${TMPDIR:-/tmp}/siphon-rf-unsuccessful-validation"

for tool in tshark text2pcap; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "$tool not found, install wireshark-common" >&2
    exit 1
  fi
done

mkdir -p "$WORK"
rm -f "$WORK"/*.hex "$WORK"/*.pcap

echo "driving a cancelled, a busy and a redirected call through the proxy"
SIPHON_RF_FAILED_SETUP_HEX_DIR="$WORK" \
  PYO3_PYTHON="${PYO3_PYTHON:-python3}" \
  cargo test --all-features --lib \
  dispatcher::rf_unsuccessful_attempt_tests::emit_failed_setup_acrs_for_external_dissection \
  -- --exact >/dev/null

status=0

check() {
  local name="$1" cause="$2" hex="$WORK/$1.hex" pcap="$WORK/$1.pcap"
  if [[ ! -s "$hex" ]]; then
    echo "  FAIL $name: the dispatcher sent no ACR" >&2
    status=1
    return
  fi
  # 3868 is Diameter's registered port, so tshark's own dissector claims it.
  text2pcap -q -T "3868,3868" "$hex" "$pcap"
  echo "$name:"
  expect "$pcap" diameter.cmd.code 271
  expect "$pcap" diameter.applicationId 3
  expect "$pcap" diameter.Accounting-Record-Type 1
  expect "$pcap" diameter.3GPP-SIP-Method INVITE
  expect "$pcap" diameter.Role-Of-Node 0
  expect "$pcap" diameter.Node-Functionality 1
  expect "$pcap" diameter.Cause-Code "$cause"
  if [[ -n "$(tshark -r "$pcap" -Y '_ws.malformed || _ws.expert.severity >= warning' 2>/dev/null)" ]]; then
    echo "  FAIL $name: tshark flagged the ACR as malformed" >&2
    status=1
  fi
  if tshark -r "$pcap" -V -O diameter 2>/dev/null | grep -q "Unknown AVP"; then
    echo "  FAIL $name: an AVP tshark does not recognise" >&2
    status=1
  fi
}

expect() {
  local pcap="$1" field="$2" want="$3" got
  got="$(tshark -r "$pcap" -T fields -E occurrence=a -e "$field" 2>/dev/null | head -1)"
  if [[ "$got" != "$want" ]]; then
    echo "  FAIL $field: tshark read '$got', we meant '$want'" >&2
    status=1
    return
  fi
  echo "  ok   $field = $got"
}

check cancel_487 487
check busy_486 486
check redirect_302 -302

if [[ $status -ne 0 ]]; then
  echo "Rf unsuccessful set-up ACR validation FAILED" >&2
  exit 1
fi

echo "Rf unsuccessful set-up ACRs validated against tshark's Diameter dissector"
