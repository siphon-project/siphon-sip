#!/usr/bin/env bash
#
# Capture X2 and X3 on the wire and read them back with a third-party dissector.
#
# scripts/validate_x2_pdu.sh checks one PDU the encoder produced, in isolation.
# This one places a warranted SIPp call through the interop estate, packet-
# captures the delivery interface with tcpdump, and hands the capture to the
# third-party x2x3PduDissector plus Wireshark's own SIP and RTP dissectors.
# Nothing in the verification path is ours.
#
#   scripts/validate_li_capture.sh
#
# What it asserts:
#
#   * **Counts.** Every PDU on the wire dissects, X2 as type 1 and X3 as type 2,
#     and the totals match what the mediation function says it received.
#   * **SIP signalling inside X2.** Wireshark's SIP dissector parses every X2
#     payload and finds the INVITE, the 200, the ACK and the BYE. An off-by-one
#     in the header length would leave it parsing nothing.
#   * **RTP inside X3**, with contiguous sequence numbers — the check that says
#     the packet count is right rather than merely plausible — and one X3 record
#     per RTP packet the engine actually relayed, counted from a separate
#     capture taken in the engine's own network namespace.
#
# The delivery interface is fronted by a TLS-terminating tap (see
# docker-compose.li-capture.yaml): the engine's X3 is TLS-only and ECDHE, so the
# production hop cannot be decrypted after the fact. The outer hop stays exactly
# what production is, mutual TLS included; the capture is taken one hop later.
#
# Needs tshark and text2pcap (wireshark-common).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

LI_DIR="sipp/li"
COMPOSE=(-f "$LI_DIR/docker-compose.li.yaml" -f "$LI_DIR/docker-compose.li-capture.yaml")
CAPTURE_DIR="$LI_DIR/captures"

# tshark is commonly AppArmor-confined to a short list of readable paths, and a
# checkout under $HOME is not on it — it reports a permission error on the
# capture that has nothing to do with file modes. Everything it reads lives
# somewhere it is allowed to.
WORK="${TMPDIR:-/tmp}/siphon-li-capture"
DISSECTOR="$WORK/x2x3PduDissector.lua"

# Where the tap listens, and what the destination is provisioned as.
TAP_HOST="172.29.0.50"
TAP_PORT=42069
# The plaintext hop the capture is taken on.
INNER_PORT=42070

for tool in tshark text2pcap docker; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "$tool not found" >&2
    exit 1
  fi
done

mkdir -p "$WORK" "$CAPTURE_DIR"
rm -f "$CAPTURE_DIR"/*.pcap

if [[ ! -f "$DISSECTOR" ]]; then
  echo "fetching the third-party dissector"
  curl -fsSL \
    https://raw.githubusercontent.com/hyavari/x2x3PduDissector/main/x2x3PduDissector.lua \
    -o "$DISSECTOR"
fi

cleanup() {
  docker compose "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "=== building ==="
docker compose "${COMPOSE[@]}" build network-element li-x1-test >/dev/null

echo "=== bringing the estate up, with the tap and the captures ==="
docker compose "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
docker compose "${COMPOSE[@]}" up -d \
  init-admf-certs init-ne-certs init-keystores \
  siphon-rtp siphon-rtp-ready network-element simulator li-uas \
  x3-tap capture-x2x3 capture-rtp

# tcpdump needs a moment to open the device, or the first packets are missed.
sleep 3

echo "=== placing one intercepted call ==="
# The destination is provisioned at the tap rather than at the mediation
# function, so both interfaces arrive through it.
docker compose "${COMPOSE[@]}" run --rm \
  -e MDF_HOST="$TAP_HOST" \
  -e X2X3_PORT="$TAP_PORT" \
  li-x1-test

echo "=== stopping the captures ==="
# SIGINT rather than SIGKILL, so tcpdump flushes and closes the file.
docker kill --signal=INT li-capture-x2x3 li-capture-rtp >/dev/null 2>&1 || true
sleep 2
docker compose "${COMPOSE[@]}" stop capture-x2x3 capture-rtp >/dev/null 2>&1 || true

cp "$CAPTURE_DIR/x2x3.pcap" "$WORK/x2x3.pcap"
cp "$CAPTURE_DIR/rtp.pcap" "$WORK/rtp.pcap"

status=0
fail() {
  echo "  FAIL $*" >&2
  status=1
}
pass() {
  echo "  ok   $*"
}

dissect() {
  tshark -q -r "$WORK/x2x3.pcap" \
    -X "lua_script:$DISSECTOR" \
    -d "tcp.port==$INNER_PORT,x2x3" \
    "$@" 2>/dev/null
}

echo
echo "=== what the capture holds ==="
total_frames="$(tshark -q -r "$WORK/x2x3.pcap" -T fields -e frame.number 2>/dev/null | grep -c . || true)"
echo "  $total_frames frames on the delivery interface"
if [[ "$total_frames" -eq 0 ]]; then
  fail "the capture is empty — nothing was delivered, or tcpdump saw nothing"
  exit 1
fi

x2_on_wire="$(dissect -T fields -e x2x3.pduType | tr ',' '\n' | grep -c '^1$' || true)"
x3_on_wire="$(dissect -T fields -e x2x3.pduType | tr ',' '\n' | grep -c '^2$' || true)"
echo "  X2 PDUs dissected off the wire: $x2_on_wire"
echo "  X3 PDUs dissected off the wire: $x3_on_wire"

[[ "$x2_on_wire" -gt 0 ]] || fail "no X2 PDU was dissected from the capture"
[[ "$x3_on_wire" -gt 0 ]] || fail "no X3 PDU was dissected from the capture"
if [[ $status -ne 0 ]]; then
  exit 1
fi

echo
echo "=== X2: the signalling inside ==="

formats="$(dissect -T fields -e x2x3.payloadFormat | tr ',' '\n' | sort -u | grep -v '^$' | tr '\n' ' ')"
if [[ " $formats " != *" 9 "* ]]; then
  fail "no X2 record on the wire carried payload format 9 (SIP); saw '$formats'"
else
  pass "X2 records carry payload format 9 (SIP)"
fi

# Wireshark's own SIP dissector, handed the payload by the X2X3 dissector. If
# the header length were wrong by one octet this would parse nothing at all.
methods="$(dissect -T fields -e sip.Method | tr ',' '\n' | tr -d '\r' | sort -u | grep -v '^$' | tr '\n' ' ')"
statuses="$(dissect -T fields -e sip.Status-Code | tr ',' '\n' | tr -d '\r' | sort -u | grep -v '^$' | tr '\n' ' ')"
sip_frames="$(dissect -Y sip -T fields -e frame.number | grep -c . || true)"

echo "  SIP methods:  $methods"
echo "  SIP statuses: $statuses"
echo "  frames Wireshark read SIP in: $sip_frames"

if [[ "$sip_frames" -eq 0 ]]; then
  fail "Wireshark's SIP dissector read nothing inside the X2 records"
else
  pass "Wireshark's SIP dissector reads the X2 payloads"
fi

for method in INVITE ACK BYE; do
  if [[ " $methods " != *" $method "* ]]; then
    fail "no $method among the captured X2 records"
  else
    pass "X2 carries the $method"
  fi
done

if [[ " $statuses " != *" 200 "* ]]; then
  fail "no 200 response among the captured X2 records"
else
  pass "X2 carries the 200 response"
fi

echo
echo "=== X3: the content inside ==="

if [[ " $formats " != *" 8 "* ]]; then
  fail "no X3 record on the wire carried payload format 8 (RTP); saw '$formats'"
else
  pass "X3 records carry payload format 8 (RTP)"
fi

# The RTP the engine actually relayed, captured in its own namespace. One
# content record per relayed packet is what X3 means.
#
# The engine both receives and sends each packet, so the capture holds it twice
# in the relay direction; the intercepted copy is one per packet in the
# direction the warrant covers. Counting the caller's stream by its source port
# keeps the comparison honest.
rtp_total="$(tshark -q -r "$WORK/rtp.pcap" -T fields -e frame.number 2>/dev/null | grep -c . || true)"
echo "  RTP frames captured in the engine's namespace: $rtp_total"
if [[ "$rtp_total" -eq 0 ]]; then
  fail "no RTP was captured, so the content records cannot be copies of anything"
fi

python3 "$REPO_ROOT/scripts/li_capture_check.py" \
  --capture "$WORK/x2x3.pcap" \
  --dissector "$DISSECTOR" \
  --port "$INNER_PORT" \
  --rtp-capture "$WORK/rtp.pcap" || status=1

echo
if [[ $status -ne 0 ]]; then
  echo "LI capture validation FAILED" >&2
  exit 1
fi
echo "LI capture validated: X2 and X3 read off the wire by a third-party dissector"
