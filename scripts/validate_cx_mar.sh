#!/usr/bin/env bash
#
# Validate the Cx Multimedia-Auth-Request of `auth.require_ims_digest` against
# Wireshark's Diameter dissector.
#
# The tests in src/script/api/auth/ims.rs read the MAR back with our own
# decoder, so they share whatever we misread of TS 29.229. This feeds the two
# MARs the S-CSCF path sends, for a first REGISTER and for a resynchronisation,
# to tshark, which decodes them with its own dictionary, and asserts it reads
# back the IMS-AKA scheme inside SIP-Auth-Data-Item.
#
#   scripts/validate_cx_mar.sh
#
# Needs tshark and text2pcap (wireshark-common). CI runners have neither, so
# run it locally after touching src/script/api/auth/ims.rs or
# DiameterClient::send_mar in src/diameter/mod.rs.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# tshark is commonly AppArmor-confined to a short list of readable paths, and a
# checkout under $HOME is often not on it, so the capture lives under TMPDIR.
WORK="${TMPDIR:-/tmp}/siphon-cx-mar-validation"
HEX="$WORK/cx_mar.hex"
PCAP="$WORK/cx_mar.pcap"

for tool in tshark text2pcap; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "$tool not found, install wireshark-common" >&2
    exit 1
  fi
done

mkdir -p "$WORK"
rm -f "$HEX" "$PCAP"

echo "encoding the MARs the way auth.require_ims_digest sends them"
SIPHON_CX_MAR_HEX_OUT="$HEX" \
  PYO3_PYTHON="${PYO3_PYTHON:-python3}" \
  cargo test --lib script::api::auth::ims::tests::emit_cx_mar_for_external_dissection -- --exact >/dev/null

if [[ ! -s "$HEX" ]]; then
  echo "the encoder produced nothing" >&2
  exit 1
fi

# 3868 is Diameter's registered port, so tshark's own dissector claims it.
text2pcap -q -T "3868,3868" "$HEX" "$PCAP"

status=0

# One line per MAR; occurrence=a joins repeated AVPs with ','.
expect() {
  local label="$1" field="$2" want="$3" got
  got="$(tshark -r "$PCAP" -T fields -E occurrence=a -e "$field" 2>/dev/null | paste -sd'|')"
  if [[ "$got" != "$want" ]]; then
    echo "  FAIL $label, $field: tshark read '$got', we meant '$want'" >&2
    status=1
    return
  fi
  echo "  ok   $label: $field = $got"
}

tree="$(tshark -r "$PCAP" -V -O diameter 2>/dev/null)"

count() {
  local label="$1" pattern="$2" want="$3" got
  got="$(grep -cF "$pattern" <<<"$tree" || true)"
  if [[ "$got" != "$want" ]]; then
    echo "  FAIL $label: $got of $want in the dissected tree" >&2
    status=1
    return
  fi
  echo "  ok   $label"
}

echo "reading them back with tshark"
expect "two requests" diameter.flags.request "True|True"
expect "both MAR" diameter.cmd.code "303|303"
expect "both Cx" diameter.applicationId "16777216|16777216"
expect "the public identity" diameter.Public-Identity \
  "sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org|sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org"
# Wireshark's dictionary prefixes the TS 29.229 AVPs with "3GPP-"; the bare
# names are the RFC 4740 ones, which have other codes.
expect "one vector asked for" diameter.3GPP-SIP-Number-Auth-Items "1|1"
# TS 29.229 clause 6.3.9: "Digest-AKAv1-MD5" is IMS-AKA, for the first request
# and for the resynchronisation alike.
expect "the IMS-AKA scheme" diameter.3GPP-SIP-Authentication-Scheme \
  "Digest-AKAv1-MD5|Digest-AKAv1-MD5"
# TS 29.228 table 6.3.2: Authorization Information only after a synchronisation
# failure, RAND (0x48 in the emitting test) followed by AUTS (0x44).
expect "RAND and AUTS on the resynchronisation only" diameter.3GPP-SIP-Authorization \
  "|484848484848484848484848484848484444444444444444444444444444"

count "a SIP-Auth-Data-Item in each" "AVP Code: 612 3GPP-SIP-Auth-Data-Item" 2
count "a SIP-Authentication-Scheme in each" \
  "AVP Code: 608 3GPP-SIP-Authentication-Scheme" 2
# The scheme is a child of the grouped item, not a top-level AVP: tshark
# indents a top-level AVP by four columns and a child of one by twelve.
nested="$(grep -cE '^ {12}3GPP-SIP-Authentication-Scheme: Digest-AKAv1-MD5$' <<<"$tree" || true)"
if [[ "$nested" == "2" ]]; then
  echo "  ok   the scheme is nested in SIP-Auth-Data-Item both times"
else
  echo "  FAIL the scheme was not found under SIP-Auth-Data-Item ($nested of 2)" >&2
  status=1
fi
# TS 29.229 table 6.3.1: M and V on both.
flagged="$(grep -A1 -E 'AVP Code: (608 3GPP-SIP-Authentication-Scheme|612 3GPP-SIP-Auth-Data-Item)' <<<"$tree" |
  grep -cF 'AVP Flags: 0xc0, Vendor-Specific: Set, Mandatory: Set' || true)"
if [[ "$flagged" == "4" ]]; then
  echo "  ok   item and scheme carry M+V"
else
  echo "  FAIL item and scheme flags: $flagged of 4 had M+V" >&2
  status=1
fi

if grep -q "Unknown AVP" <<<"$tree"; then
  echo "  FAIL an AVP tshark does not recognise" >&2
  status=1
fi
if [[ -n "$(tshark -r "$PCAP" -Y '_ws.malformed || _ws.expert' 2>/dev/null)" ]]; then
  echo "  FAIL tshark flagged a MAR as malformed or raised expert info" >&2
  status=1
else
  echo "  ok   nothing malformed, no expert info"
fi

if [[ $status -ne 0 ]]; then
  echo "Cx MAR validation FAILED" >&2
  exit 1
fi

echo "Cx MAR validated against tshark's Diameter dissector"
