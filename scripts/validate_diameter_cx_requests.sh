#!/usr/bin/env bash
#
# Validate the Cx requests this node sends against Wireshark's Diameter
# dissector.
#
# The tests in src/diameter/cx.rs pin octets we derived, so they share whatever
# we misread of TS 29.229. This feeds tshark a User-Authorization-Request and
# two Multimedia-Auth-Requests (a first one, and one after an IMS AKA
# synchronisation failure) and asserts tshark, with its own dictionary, reads
# back the User-Name and Server-Name the commands require and the scheme.
#
#   scripts/validate_diameter_cx_requests.sh
#
# Needs tshark and text2pcap (wireshark-common). CI runners have neither, so
# run it locally after touching the request builders in src/diameter/cx.rs.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# tshark is commonly AppArmor-confined to a short list of readable paths, and a
# checkout under $HOME is often not on it, so the capture lives under TMPDIR.
WORK="${TMPDIR:-/tmp}/siphon-diameter-cx-validation"
HEX="$WORK/requests.hex"
PCAP="$WORK/requests.pcap"

for tool in tshark text2pcap; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "$tool not found, install wireshark-common" >&2
    exit 1
  fi
done

mkdir -p "$WORK"
rm -f "$WORK"/*.hex "$PCAP"

echo "building the requests the way the client does"
SIPHON_CX_REQUESTS_HEX_DIR="$WORK" \
  PYO3_PYTHON="${PYO3_PYTHON:-python3}" \
  cargo test --lib diameter::cx::tests::emit_cx_requests_for_external_dissection -- --exact >/dev/null

for name in uar mar mar_resync; do
  if [[ ! -s "$WORK/$name.hex" ]]; then
    echo "the encoder produced no $name" >&2
    exit 1
  fi
done

# One packet per request: frame 1 the UAR, 2 the MAR, 3 the MAR after a
# synchronisation failure. 3868 is Diameter's registered port, so tshark's own
# dissector claims it.
cat "$WORK/uar.hex" "$WORK/mar.hex" "$WORK/mar_resync.hex" >"$HEX"
text2pcap -q -T "3868,3868" "$HEX" "$PCAP"

status=0

expect() {
  local frame="$1" field="$2" want="$3" got
  got="$(tshark -r "$PCAP" -Y "frame.number == $frame" -T fields -E occurrence=a -e "$field" 2>/dev/null | head -1)"
  if [[ "$got" != "$want" ]]; then
    echo "  FAIL frame $frame $field: tshark read '$got', we meant '$want'" >&2
    status=1
    return
  fi
  echo "  ok   frame $frame $field = $got"
}

PRIVATE_IDENTITY="001010000000001@ims.mnc001.mcc001.3gppnetwork.org"
PUBLIC_IDENTITY="sip:$PRIVATE_IDENTITY"
SCSCF_URI="sip:scscf.ims.mnc001.mcc001.3gppnetwork.org:6060"

echo "reading the UAR back with tshark"
expect 1 diameter.cmd.code 300
expect 1 diameter.flags.request True
expect 1 diameter.applicationId 16777216
expect 1 diameter.User-Name "$PRIVATE_IDENTITY"
expect 1 diameter.Public-Identity "$PUBLIC_IDENTITY"
expect 1 diameter.User-Authorization-Type 0

echo "reading the MAR back with tshark"
for frame in 2 3; do
  expect "$frame" diameter.cmd.code 303
  expect "$frame" diameter.flags.request True
  expect "$frame" diameter.applicationId 16777216
  expect "$frame" diameter.User-Name "$PRIVATE_IDENTITY"
  expect "$frame" diameter.Public-Identity "$PUBLIC_IDENTITY"
  expect "$frame" diameter.Server-Name "$SCSCF_URI"
  # Wireshark's dictionary prefixes the TS 29.229 AVPs with "3GPP-"; the bare
  # names are the RFC 4740 ones, which have other codes.
  expect "$frame" diameter.3GPP-SIP-Number-Auth-Items 1
  expect "$frame" diameter.3GPP-SIP-Authentication-Scheme Digest-AKAv1-MD5
done
# RAND then AUTS, 30 octets, only on the request after a synchronisation
# failure.
expect 2 diameter.3GPP-SIP-Authorization ""
expect 3 diameter.3GPP-SIP-Authorization "$(printf 'ab%.0s' $(seq 30))"

tree="$(tshark -r "$PCAP" -V -O diameter 2>/dev/null)"

# User-Name is a base AVP: the M bit and no vendor (RFC 6733 clause 4.5).
flags="$(grep -A1 -F "AVP Code: 1 User-Name" <<<"$tree" | grep -cF "AVP Flags: 0x40, Mandatory: Set" || true)"
if [[ "$flags" != "3" ]]; then
  echo "  FAIL User-Name flags: $flags of 3 requests carry it as M, no vendor" >&2
  status=1
else
  echo "  ok   User-Name is M with no vendor in all three"
fi
flags="$(grep -A1 -F "AVP Code: 602 Server-Name" <<<"$tree" | grep -cF "AVP Flags: 0xc0, Vendor-Specific: Set, Mandatory: Set" || true)"
if [[ "$flags" != "2" ]]; then
  echo "  FAIL Server-Name flags: $flags of 2 MARs carry it as V and M" >&2
  status=1
else
  echo "  ok   Server-Name is V and M in both MARs"
fi

if grep -q "Unknown AVP" <<<"$tree"; then
  echo "  FAIL an AVP tshark does not recognise" >&2
  status=1
fi
if [[ -n "$(tshark -r "$PCAP" -Y '_ws.malformed || _ws.expert' 2>/dev/null)" ]]; then
  echo "  FAIL tshark flagged a request as malformed or raised expert info" >&2
  status=1
else
  echo "  ok   nothing malformed, no expert info"
fi

if [[ $status -ne 0 ]]; then
  echo "Cx request validation FAILED" >&2
  exit 1
fi

echo "Cx requests validated against tshark's Diameter dissector"
