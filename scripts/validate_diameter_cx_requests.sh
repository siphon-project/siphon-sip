#!/usr/bin/env bash
#
# Validate the Cx requests this node sends against Wireshark's Diameter
# dissector.
#
# The tests in src/diameter/cx.rs pin octets we derived, so they share whatever
# we misread of TS 29.229. This feeds tshark a User-Authorization-Request, two
# Multimedia-Auth-Requests (a first one, and one after an IMS AKA
# synchronisation failure) and a Server-Assignment-Request, and asserts tshark,
# with its own dictionary, reads back the User-Name and Server-Name the
# commands require and the scheme. It then reads the answers the helpers for
# the HSS side build, for success carried as Result-Code, and the SIP Digest
# messages: Multimedia-Auth-Requests in the schemes "Unknown" and "SIP Digest",
# and two answers with SIP-Digest-Authenticate, one as the mock HSS of the
# tests encodes it and one built by a script through request.answer().
#
#   scripts/validate_diameter_cx_requests.sh
#
# Needs tshark and text2pcap (wireshark-common). CI runners have neither, so
# run it locally after touching the builders in src/diameter/cx.rs, the
# dictionary entries of the digest AVPs, or src/script/api/auth/sip_digest.rs.

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
  cargo test --lib -- --exact \
  diameter::cx::tests::emit_cx_requests_for_external_dissection \
  script::api::auth::sip_digest::tests::emit_sip_digest_maa_for_external_dissection \
  script::api::diameter_server::tests::emit_sip_digest_answer_for_external_dissection >/dev/null

for name in uar mar mar_resync sar saa lia maa rta mar_unknown mar_sip_digest \
  maa_sip_digest_mock maa_sip_digest_script; do
  if [[ ! -s "$WORK/$name.hex" ]]; then
    echo "the encoder produced no $name" >&2
    exit 1
  fi
done

# One packet per message: frame 1 the UAR, 2 the MAR, 3 the MAR after a
# synchronisation failure, 4 the SAR, then the answers SAA, LIA, MAA and RTA,
# 9 and 10 the MARs in the schemes "Unknown" and "SIP Digest", 11 and 12 the
# SIP Digest MAAs of the mock HSS and of a script.
# 3868 is Diameter's registered port, so tshark's own dissector claims it.
cat "$WORK/uar.hex" "$WORK/mar.hex" "$WORK/mar_resync.hex" "$WORK/sar.hex" \
  "$WORK/saa.hex" "$WORK/lia.hex" "$WORK/maa.hex" "$WORK/rta.hex" \
  "$WORK/mar_unknown.hex" "$WORK/mar_sip_digest.hex" \
  "$WORK/maa_sip_digest_mock.hex" "$WORK/maa_sip_digest_script.hex" >"$HEX"
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

echo "reading the SAR back with tshark"
expect 4 diameter.cmd.code 301
expect 4 diameter.flags.request True
# TS 29.228 Table 6.1.2.1: present whenever the S-CSCF has it.
expect 4 diameter.User-Name "$PRIVATE_IDENTITY"
expect 4 diameter.Public-Identity "$PUBLIC_IDENTITY"
expect 4 diameter.Server-Name "$SCSCF_URI"
expect 4 diameter.Server-Assignment-Type 1
expect 4 diameter.User-Data-Already-Available 0

# TS 29.228 clauses 6.1.2.1, 6.1.4.1 and 6.3.1: "The Result-Code shall be set
# to DIAMETER_SUCCESS". TS 29.229 clause 6.2 keeps Experimental-Result for the
# codes it defines, where 2001 is DIAMETER_FIRST_REGISTRATION.
echo "reading the SAA, LIA, MAA and RTA of the answer helpers back with tshark"
for answer in "5 301" "6 302" "7 303" "8 304"; do
  read -r frame code <<<"$answer"
  expect "$frame" diameter.cmd.code "$code"
  expect "$frame" diameter.flags.request False
  expect "$frame" diameter.Result-Code 2001
  expect "$frame" diameter.Experimental-Result-Code ""
done
# TS 29.228 Table 6.3.4: both identities in a successful MAA.
expect 7 diameter.User-Name "dave@ims.example.com"
expect 7 diameter.Public-Identity "sip:dave@ims.example.com"
expect 7 diameter.3GPP-SIP-Authentication-Scheme Digest-AKAv1-MD5

# TS 29.229 clause 6.3.9: "Unknown" for an Authorization header without
# integrity-protected, "SIP Digest" for a protected REGISTER.
echo "reading the SIP Digest MARs back with tshark"
for request in "9 Unknown" "10 SIP Digest"; do
  frame="${request%% *}"
  expect "$frame" diameter.cmd.code 303
  expect "$frame" diameter.flags.request True
  expect "$frame" diameter.User-Name "$PRIVATE_IDENTITY"
  expect "$frame" diameter.Server-Name "$SCSCF_URI"
  expect "$frame" diameter.3GPP-SIP-Authentication-Scheme "${request#* }"
done

# TS 29.229 clause 6.3.36 and table 6.3.0.1: SIP-Digest-Authenticate is 635 of
# the 3GPP vendor, its digest attributes the RFC 5090 ones with no vendor.
echo "reading the SIP Digest MAAs back with tshark"
MOCK_HA1="$(printf '%s' "$PRIVATE_IDENTITY:digest.example.org:a password for 001010000000001" |
  md5sum | cut -d' ' -f1)"
for answer in "11 $MOCK_HA1" "12 3d78807defe7de2157e2b0b6573a855f"; do
  frame="${answer%% *}"
  expect "$frame" diameter.cmd.code 303
  expect "$frame" diameter.flags.request False
  expect "$frame" diameter.Result-Code 2001
  expect "$frame" diameter.3GPP-SIP-Authentication-Scheme "SIP Digest"
  expect "$frame" diameter.Digest-Realm digest.example.org
  expect "$frame" diameter.Digest-Algorithm MD5
  expect "$frame" diameter.Digest-Qop auth
  expect "$frame" diameter.Digest-HA1 "${answer#* }"
  digest_tree="$(tshark -r "$PCAP" -Y "frame.number == $frame" -V -O diameter 2>/dev/null)"
  for avp in "635 SIP-Digest-Authenticate" "104 Digest-Realm" "110 Digest-Qop" \
    "111 Digest-Algorithm" "121 Digest-HA1" "662 " "663 "; do
    if [[ "$(grep -cF "AVP Code: $avp" <<<"$digest_tree" || true)" != "1" ]]; then
      echo "  FAIL frame $frame: not exactly one AVP Code: $avp" >&2
      status=1
    fi
  done
  # Three levels down: SIP-Auth-Data-Item, SIP-Digest-Authenticate, member.
  nested="$(grep -cE '^ {20}Digest-(Realm|Algorithm|Qop|HA1): ' <<<"$digest_tree" || true)"
  if [[ "$nested" == "4" ]]; then
    echo "  ok   frame $frame: 635, 104, 110, 111, 121, 662 and 663 once each, the four digest attributes nested in SIP-Digest-Authenticate"
  else
    echo "  FAIL frame $frame: $nested of 4 digest attributes under SIP-Digest-Authenticate" >&2
    status=1
  fi
done

tree="$(tshark -r "$PCAP" -V -O diameter 2>/dev/null)"

# User-Name is a base AVP: the M bit and no vendor (RFC 6733 clause 4.5).
flags="$(grep -A1 -F "AVP Code: 1 User-Name" <<<"$tree" | grep -cF "AVP Flags: 0x40, Mandatory: Set" || true)"
if [[ "$flags" != "9" ]]; then
  echo "  FAIL User-Name flags: $flags of 9 messages carry it as M, no vendor" >&2
  status=1
else
  echo "  ok   User-Name is M with no vendor in the six requests and the three MAAs"
fi
flags="$(grep -A1 -F "AVP Code: 602 Server-Name" <<<"$tree" | grep -cF "AVP Flags: 0xc0, Vendor-Specific: Set, Mandatory: Set" || true)"
if [[ "$flags" != "6" ]]; then
  echo "  FAIL Server-Name flags: $flags of 6 messages carry it as V and M" >&2
  status=1
else
  echo "  ok   Server-Name is V and M in the four MARs, the SAR and the LIA"
fi

# Wireshark's dictionary may predate Alternate-Digest-Algorithm (662) and
# Alternate-Digest-HA1 (663) of TS 29.229 clauses 6.3.72 and 6.3.73. It then
# lists them by code under the 3GPP vendor and raises "undecoded" expert info
# for the two answers that carry them. Anything else it does not know fails.
if grep -F "Unknown AVP" <<<"$tree" | grep -qvE 'Unknown AVP 66[23] \(vendor=3GPP\)'; then
  echo "  FAIL an AVP tshark does not recognise" >&2
  status=1
fi
if [[ -n "$(tshark -r "$PCAP" -Y '_ws.malformed || (_ws.expert && frame.number < 11)' 2>/dev/null)" ]]; then
  echo "  FAIL tshark flagged a message as malformed or raised expert info" >&2
  status=1
else
  echo "  ok   nothing malformed, no expert info but for AVPs 662 and 663"
fi

if [[ $status -ne 0 ]]; then
  echo "Cx validation FAILED" >&2
  exit 1
fi

echo "Cx requests and answers validated against tshark's Diameter dissector"
