#!/usr/bin/env bash
#
# Validate the GBA messages (Zh and Zn, TS 29.109) against Wireshark's Diameter
# dissector.
#
# The tests in src/diameter/gba.rs and src/script/api/diameter_gba.rs compare
# what this node sends with messages written out by hand from the ABNF. This
# feeds tshark, which has its own dictionary, three sets of octets:
#
#   - the capabilities exchange of a node with a `zh` and a `zn` route,
#   - what a peer received from `diameter.zh_mar`, from
#     `diameter.send_request("Multimedia-Auth-Request", "Zh", ...)` with a
#     SIP-Auth-Data-Item given as a dict, and from `diameter.zn_bir`,
#   - the Bootstrapping-Info-Answers a script's `@diameter.on_request("Zn:BIR")`
#     handler built,
#
# and then the hand-written messages themselves, so that what their comments
# claim is checked by the same independent decoder.
#
#   scripts/validate_diameter_gba.sh
#
# Needs tshark and text2pcap (wireshark-common). CI runners have neither, so
# run it locally after touching src/diameter/gba.rs, the GBA entries of
# src/diameter/dictionary.rs, or the AVP builders the script API uses.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# tshark is commonly AppArmor-confined to a short list of readable paths, and a
# checkout under $HOME is often not on it, so the capture lives under TMPDIR.
WORK="${TMPDIR:-/tmp}/siphon-diameter-gba-validation"
HEX="$WORK/gba.all"
PCAP="$WORK/gba.pcap"

for tool in tshark text2pcap; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "$tool not found, install wireshark-common" >&2
    exit 1
  fi
done

# One packet per message, in this order.
FRAMES=(cer cea zh_mar zh_mar_resync zh_mar_generic zn_bir zn_bia zn_bia_unknown
  written_zh_maa written_zh_maa_unknown written_zn_bir written_zn_bia
  written_zn_bia_invalid)

mkdir -p "$WORK"
for name in "${FRAMES[@]}"; do
  : >"$WORK/$name.hex"
done

echo "building the messages the way a script does"
SIPHON_GBA_HEX_DIR="$WORK" \
  PYO3_PYTHON="${PYO3_PYTHON:-python3}" \
  cargo test --lib script::api::diameter_gba::tests::emit_gba_messages_for_external_dissection -- --exact >/dev/null

: >"$HEX"
for name in "${FRAMES[@]}"; do
  if [[ ! -s "$WORK/$name.hex" ]]; then
    echo "no $name was produced" >&2
    exit 1
  fi
  cat "$WORK/$name.hex" >>"$HEX"
done

# 3868 is Diameter's registered port, so tshark's own dissector claims it.
text2pcap -q -T "3868,3868" "$HEX" "$PCAP"

status=0

# The value of `field` in frame `number`; repeated AVPs are joined with ','.
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

# The header of every message: command, direction and application.
header() {
  local frame="$1" command="$2" request="$3" application="$4"
  expect "$frame" diameter.cmd.code "$command"
  expect "$frame" diameter.flags.request "$request"
  expect "$frame" diameter.applicationId "$application"
}

IMPI="001010000000001@ims.mnc001.mcc001.3gppnetwork.org"
RAND="101112131415161718191a1b1c1d1e1f"
AUTS="a0a1a2a3a4a5a6a7a8a9aaabacad"
B_TID_HEX="45424553457851564668635947526f624842306548773d3d406273662e6d6e633030312e6d63633030312e7075622e336770706e6574776f726b2e6f7267"
# naf.example.com followed by the Ua security protocol identifier 01 00 01 13 01.
NAF_ID_HEX="6e61662e6578616d706c652e636f6d0100011301"
KS_EXT_NAF="606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
KS_INT_NAF="808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"

echo "the capabilities exchange"
# RFC 6733 clause 6.11: each 3GPP application inside its own
# Vendor-Specific-Application-Id with Vendor-Id 10415. The first Vendor-Id of
# the message is the node's own.
for frame in 1 2; do
  expect "$frame" diameter.cmd.code 257
  expect "$frame" diameter.Vendor-Id 0,10415,10415
  expect "$frame" diameter.Auth-Application-Id 16777221,16777221,16777220,16777220
done
expect 1 diameter.flags.request True
expect 2 diameter.flags.request False

echo "Zh: the Multimedia-Auth-Request of diameter.zh_mar"
header 3 303 True 16777221
expect 3 diameter.User-Name "$IMPI"
expect 3 diameter.Auth-Application-Id 16777221
# Session-Id, Vendor-Specific-Application-Id with its two members,
# Auth-Session-State, Origin-Host, Origin-Realm, Destination-Realm, User-Name:
# the ABNF of TS 29.109 clause 4.2, and no SIP-Auth-Data-Item for IMS AKA.
expect 3 diameter.avp.code 263,260,266,258,277,264,296,283,1
expect 3 diameter.avp.flags 0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40

echo "Zh: after a synchronisation failure, with the GUSS timestamp"
header 4 303 True 16777221
expect 4 diameter.avp.code 263,260,266,258,277,264,296,283,1,612,608,610,409
# SIP-Auth-Data-Item and its members carry V and M; GUSS-Timestamp carries V
# and not M (TS 29.109 Table 6.1).
expect 4 diameter.avp.flags 0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0xc0,0xc0,0xc0,0x80
expect 4 diameter.avp.vendorId 10415,10415,10415,10415
expect 4 diameter.3GPP-SIP-Authentication-Scheme Digest-AKAv1-MD5
# RAND || AUTS, 30 octets (TS 29.229 clause 6.3.11).
expect 4 diameter.3GPP-SIP-Authorization "$RAND$AUTS"
expect 4 diameter.GUSS-Timestamp 2026-01-01T00:00:00.000000000Z

echo "Zh: the same request from diameter.send_request with a dict"
header 5 303 True 16777221
expect 5 diameter.User-Name "$IMPI"
expect 5 diameter.avp.vendorId 10415,10415,10415,10415
expect 5 diameter.3GPP-SIP-Authentication-Scheme Digest-AKAv1-MD5
expect 5 diameter.3GPP-SIP-Authorization "$RAND$AUTS"
expect 5 diameter.GUSS-Timestamp 2026-01-01T00:00:00.000000000Z
expect 5 diameter.Auth-Application-Id 16777221

echo "Zn: the Bootstrapping-Info-Request of diameter.zn_bir"
header 6 310 True 16777220
expect 6 diameter.avp.code 263,260,266,258,277,264,296,283,403,403,401,402,407
expect 6 diameter.avp.flags 0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0xc0,0xc0,0xc0,0xc0,0xc0
expect 6 diameter.avp.vendorId 10415,10415,10415,10415,10415
expect 6 diameter.Auth-Application-Id 16777220
expect 6 diameter.GAA-Service-Identifier 31,34
expect 6 diameter.Transaction-Identifier "$B_TID_HEX"
# Wireshark's dictionary still calls AVP 402 NAF-Hostname; TS 29.109 clause
# 6.3.1.3 names it NAF-Id.
expect 6 diameter.NAF-Hostname "$NAF_ID_HEX"
expect 6 diameter.GBA_U-Awareness-Indicator 1

echo "Zn: the Bootstrapping-Info-Answer a script's handler built"
header 7 310 False 16777220
expect 7 diameter.Result-Code 2001
expect 7 diameter.User-Name "$IMPI"
expect 7 diameter.ME-Key-Material "$KS_EXT_NAF"
expect 7 diameter.UICC-Key-Material "$KS_INT_NAF"
expect 7 diameter.Key-ExpiryTime 2026-01-01T01:00:00.000000000Z
expect 7 diameter.BootstrapInfoCreationTime 2026-01-01T00:00:00.000000000Z
expect 7 diameter.GBA-Type 0
expect 7 diameter.Auth-Application-Id 16777220
# Six GBA AVPs, each with V and M.
expect 7 diameter.avp.vendorId 10415,10415,10415,10415,10415,10415
expect 7 diameter.avp.flags 0x40,0x40,0x40,0x40,0x40,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0x40,0x40,0x40,0x40

echo "Zn: the refusal of an unknown B-TID"
header 8 310 False 16777220
expect 8 diameter.flags.error False
# TS 29.109 clause 6.2: inside an Experimental-Result, and no Result-Code.
expect 8 diameter.Experimental-Result-Code 5403
expect 8 diameter.Result-Code ""
expect 8 diameter.Vendor-Id 10415,10415

echo "the hand-written messages the tests read"
header 9 303 False 16777221
expect 9 diameter.Result-Code 2001
expect 9 diameter.3GPP-SIP-Item-Number 1
expect 9 diameter.avp.code 263,260,266,258,268,277,264,296,1,612,613,608,609,610,625,626,400
header 10 303 False 16777221
expect 10 diameter.Experimental-Result-Code 5401
expect 10 diameter.Result-Code ""
header 11 310 True 16777220
expect 11 diameter.avp.code 263,260,266,258,277,264,296,283,403,403,401,402,407
expect 11 diameter.Transaction-Identifier "$B_TID_HEX"
expect 11 diameter.NAF-Hostname "$NAF_ID_HEX"
header 12 310 False 16777220
expect 12 diameter.avp.code 263,260,266,258,268,277,264,296,1,405,406,404,408,400,410
expect 12 diameter.Key-ExpiryTime 2026-01-01T01:00:00.000000000Z
header 13 310 False 16777220
expect 13 diameter.Experimental-Result-Code 5403

tree="$(tshark -r "$PCAP" -V -O diameter 2>/dev/null)"

count() {
  local label="$1" pattern="$2" want="$3" got
  got="$(grep -cF "$pattern" <<<"$tree" || true)"
  if [[ "$got" != "$want" ]]; then
    echo "  FAIL $label: $got in the dissected tree, we meant $want" >&2
    status=1
    return
  fi
  echo "  ok   $label"
}

echo "names read from Wireshark's dictionary"
# The header names the application once per message: three requests and two
# written answers on Zh, two requests and four answers on Zn.
count "Zh by name in every Zh message" "ApplicationId: 3GPP Zh (16777221)" 5
count "Zn by name in every Zn message" "ApplicationId: 3GPP Zn (16777220)" 6
count "GBA-UserSecSettings in three answers" "AVP Code: 400 GBA-UserSecSettings" 3
count "Transaction-Identifier in two requests" "AVP Code: 401 Transaction-Identifier" 2
count "Key-ExpiryTime in two answers" "AVP Code: 404 Key-ExpiryTime" 2
count "ME-Key-Material in two answers" "AVP Code: 405 ME-Key-Material" 2
count "UICC-Key-Material in two answers" "AVP Code: 406 UICC-Key-Material" 2
count "GBA_U-Awareness-Indicator in two requests" "AVP Code: 407 GBA_U-Awareness-Indicator" 2
count "BootstrapInfoCreationTime in two answers" "AVP Code: 408 BootstrapInfoCreationTime" 2
count "GUSS-Timestamp in two requests" "AVP Code: 409 GUSS-Timestamp" 2
count "GBA-Type in two answers" "AVP Code: 410 GBA-Type" 2
count "SIP-Auth-Data-Item in two requests and one answer" "AVP Code: 612 3GPP-SIP-Auth-Data-Item" 3

if grep -q "Unknown AVP" <<<"$tree"; then
  echo "  FAIL an AVP tshark does not recognise" >&2
  status=1
fi
if [[ -n "$(tshark -r "$PCAP" -Y '_ws.malformed || _ws.expert' 2>/dev/null)" ]]; then
  echo "  FAIL tshark flagged a message as malformed or raised expert info" >&2
  status=1
else
  echo "  ok   nothing malformed, no expert info"
fi

if [[ $status -ne 0 ]]; then
  echo "Diameter GBA validation FAILED" >&2
  exit 1
fi

echo "Diameter GBA messages validated against tshark's Diameter dissector"
