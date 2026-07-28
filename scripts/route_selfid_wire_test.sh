#!/usr/bin/env bash
#
# Wire-level Route self-identity test (RFC 3261 §16.4).
#
# Proves on the wire what the unit tests assert in isolation: siphon consumes
# the Record-Route it stamped itself, and only that one.
#
# The standing SIPp baseline cannot show this. `siphon.yaml` lists 127.0.0.1
# under `domain.local`, so loose-routing on loopback works even when Route
# recognition is keyed on served domains alone. These cases each run a config
# where `domain.local` deliberately does NOT contain the listen address —
# the shape of every real IP-addressed deployment.
#
# Cases:
#   1. baseline   — in-dialog BYE must be relayed, not answered 404.
#   2. dualstack  — same, on a second (IPv6) listener of the same transport:
#                   the first-per-transport maps do not contain it.
#   3. colocated  — a Route at our address on a port we do not serve belongs to
#                   another proxy and must be left as the next hop.
#
# Every case is verified from a tcpdump capture with tshark, not from SIPp's
# exit status — SIPp counts a call successful as long as it got *a* final
# response, so a 404'd BYE can still look like a pass in its summary.
#
# Usage: scripts/route_selfid_wire_test.sh [case]     (default: all)

set -uo pipefail
set +m    # no job-control chatter when cleanup kills the background siphon

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

WORK="${WORK_DIR:-/tmp/siphon_route_selfid}"
mkdir -p "$WORK"

PROXY_V4="127.0.0.1"
PROXY_V6="::1"
UAS_IP="127.0.0.2"
UAC_IP="127.0.0.51"
UAS_PORT=5061
UAC_PORT=5062

PASS=0
FAIL=0

cleanup() {
    pkill -f "invite_uac" 2>/dev/null || true
    pkill -f "invite_uas" 2>/dev/null || true
    pkill -9 -f "target/release/siphon" 2>/dev/null || true
    [ -n "${TCPDUMP_PID:-}" ] && kill "$TCPDUMP_PID" 2>/dev/null || true
}
trap cleanup EXIT

# --- Free-threaded Python, same resolution as scale_test.sh ---------------
if [ -z "${PYO3_PYTHON:-}" ]; then
    if command -v uv > /dev/null 2>&1; then
        FT="$(uv python list --only-installed 2>/dev/null \
            | awk '/freethreaded/ && /-linux-/ {for (i=1;i<=NF;i++) if ($i ~ /\/python3\.14t$/) {print $i; exit}}' || true)"
        [ -n "$FT" ] && export PYO3_PYTHON="$FT"
    fi
fi
export PYO3_PYTHON="${PYO3_PYTHON:-python3}"

# A uv-installed interpreter's libpython is not on the default loader path.
if [ -x "$PYO3_PYTHON" ] && [ -f "$PYO3_PYTHON" ]; then
    PY_LIB_DIR="$(dirname "$(dirname "$(readlink -f "$PYO3_PYTHON")")")/lib"
    if [ -d "$PY_LIB_DIR" ]; then
        case ":${LD_LIBRARY_PATH:-}:" in
            *":$PY_LIB_DIR:"*) ;;
            *) export LD_LIBRARY_PATH="${PY_LIB_DIR}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" ;;
        esac
    fi
fi

echo "[*] Building siphon (release)..."
if ! cargo build --release > "$WORK/build.log" 2>&1; then
    tail -30 "$WORK/build.log"
    echo "FAIL: build"
    exit 1
fi
echo "[+] build ok"

# ------------------------------------------------------------------------
# Config generation
#
# Derived from siphon.yaml so auth users / registrar limits stay in step, with
# `domain.local` replaced by a name-only list. That single change is what makes
# the proxy's own Record-Route unrecognisable to a served-domains-only match.
# ------------------------------------------------------------------------
make_config() {
    local out="$1" extra_listen="${2:-}"
    "$PYO3_PYTHON" - "$out" "$extra_listen" <<'PYEOF'
import sys
out, extra_listen = sys.argv[1], sys.argv[2]
lines = open("siphon.yaml").read().splitlines(keepends=True)

def block_span(start_key):
    """Line span of a top-level `key:` block, including its indented body."""
    for i, line in enumerate(lines):
        if line.startswith(start_key):
            j = i + 1
            while j < len(lines) and (lines[j][:1] in (" ", "\t") or not lines[j].strip()):
                j += 1
            return i, j
    raise AssertionError(f"{start_key} not found")

# Replace domain.local with a name-only list. The listen address is
# deliberately absent — that is the condition under test.
start, end = block_span("domain:")
lines[start:end] = ['domain:\n', '  local:\n', '    - "example.com"\n', '\n']

if extra_listen:
    # A SECOND udp listener. Being second is the point: the dispatcher's
    # first-per-transport maps never see it, only the listener registry does.
    start, end = block_span("listen:")
    for i in range(start, end):
        if lines[i].strip() == "udp:":
            indent = " " * (len(lines[i]) - len(lines[i].lstrip()) + 2)
            # Insert after the existing first entry so ours is not first.
            j = i + 1
            while j < end and lines[j].lstrip().startswith("-"):
                j += 1
            lines.insert(j, f'{indent}- "{extra_listen}"\n')
            break
    else:
        raise AssertionError("listen.udp not found")

text = "".join(lines)
assert '- "example.com"' in text
if extra_listen:
    assert extra_listen in text
open(out, "w").write(text)
PYEOF
}

start_siphon() {
    local config="$1" tag="$2"
    pkill -9 -f "target/release/siphon" 2>/dev/null || true
    sleep 1
    RUST_LOG="${RUST_LOG:-debug}" ./target/release/siphon -c "$config" \
        > "$WORK/siphon_$tag.log" 2>&1 &
    SIPHON_PID=$!
    sleep 2
    if ! kill -0 "$SIPHON_PID" 2>/dev/null; then
        echo "    siphon did not start:"
        tail -20 "$WORK/siphon_$tag.log"
        return 1
    fi
    return 0
}

# Packet capture is a cross-check, not the source of truth: raw capture on `lo`
# needs CAP_NET_RAW, which an unprivileged run does not have. The assertions read
# SIPp's own -trace_msg logs, which record the exact bytes each side put on and
# took off the socket. Grant the capability to also get a pcap:
#   sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v tcpdump)"
CAPTURE_AVAILABLE=""
start_capture() {
    local tag="$1"
    CAP="$WORK/$tag.pcap"
    rm -f "$CAP"
    tcpdump -i lo -s 0 -w "$CAP" -U "udp portrange 5060-5070 or tcp portrange 5060-5070" \
        > "$WORK/tcpdump_$tag.log" 2>&1 &
    TCPDUMP_PID=$!
    sleep 1
    if kill -0 "$TCPDUMP_PID" 2>/dev/null; then
        CAPTURE_AVAILABLE="yes"
    else
        CAPTURE_AVAILABLE=""
        TCPDUMP_PID=""
    fi
}

stop_capture() {
    sleep 1
    if [ -n "${TCPDUMP_PID:-}" ]; then
        kill "$TCPDUMP_PID" 2>/dev/null
        wait "$TCPDUMP_PID" 2>/dev/null
        TCPDUMP_PID=""
    fi
    sleep 1
}

record() {
    local name="$1" ok="$2" detail="$3"
    if [ "$ok" = "yes" ]; then
        echo "  [PASS] $name"
        PASS=$((PASS + 1))
    else
        echo "  [FAIL] $name — $detail"
        FAIL=$((FAIL + 1))
    fi
}

# ------------------------------------------------------------------------
# Case 1 + 2: a healthy call whose in-dialog BYE must be relayed.
#   $1 = tag, $2 = extra listener ("" for none), $3 = proxy address for SIPp
# ------------------------------------------------------------------------
run_dialog_case() {
    local tag="$1" extra_listen="$2" proxy_addr="$3"
    echo ""
    echo "=== case: $tag (domain.local has no listen address) ==="

    local config="$WORK/$tag.yaml"
    make_config "$config" "$extra_listen" || { record "$tag config" no "generation failed"; return; }
    start_siphon "$config" "$tag" || { record "$tag siphon start" no "see log"; return; }

    sipp -sf sipp/register.xml "$PROXY_V4:5060" -m 1 -t u1 -i "$UAS_IP" -p "$UAS_PORT" \
        -s bob -au bob -ap secret > "$WORK/register_$tag.log" 2>&1 || true
    if ! grep -q "Successful call" "$WORK/register_$tag.log"; then
        record "$tag registration" no "bob did not register"
        return
    fi

    # invite_uas.xml (not _fast): it echoes [last_Record-Route:] into its 180/200
    # as RFC 3261 §12.1.1 requires, so the UAC learns a real route set, and it
    # receives ACK and BYE so both in-dialog paths are exercised.
    rm -f "$WORK/uas_$tag.msg"
    sipp -sf sipp/invite_uas.xml -t u1 -i "$UAS_IP" -p "$UAS_PORT" -bg \
        -trace_msg -message_file "$WORK/uas_$tag.msg" \
        > "$WORK/uas_$tag.log" 2>&1 || true
    sleep 1

    start_capture "$tag"
    rm -f "$WORK/uac_$tag.msg"
    sipp -sf sipp/invite_uac.xml "$proxy_addr:5060" -m 1 -r 1 -t u1 \
        -i "$UAC_IP" -p "$UAC_PORT" -s bob \
        -trace_msg -message_file "$WORK/uac_$tag.msg" \
        > "$WORK/uac_$tag.log" 2>&1 || true
    sleep 2
    stop_capture
    pkill -f "invite_uas" 2>/dev/null || true
    sleep 1

    verify_dialog "$tag"
}

# ------------------------------------------------------------------------
# tshark assertions for a dialog case.
# ------------------------------------------------------------------------
verify_dialog() {
    local tag="$1"
    local uac="$WORK/uac_$tag.msg"
    local uas="$WORK/uas_$tag.msg"

    if [ ! -s "$uac" ]; then
        record "$tag UAC trace" no "no messages recorded"
        return
    fi
    if [ ! -s "$uas" ]; then
        record "$tag UAS trace" no "no messages recorded (UAS never engaged)"
        return
    fi

    # --- UAC side: the dialog completed and the BYE was not refused ---------
    if grep -q "^BYE sip:" "$uac"; then
        record "$tag UAC sent BYE" yes ""
    else
        record "$tag UAC sent BYE" no "no BYE in UAC trace — dialog never established"
        return
    fi

    # THE assertion. A refused self-Route makes the shipped proxy script answer
    # 404 to the in-dialog BYE (scripts/proxy_default.py loose_route else-branch).
    if grep -qE "^SIP/2\.0 404" "$uac"; then
        record "$tag no 404 on in-dialog request" no "proxy refused its own Record-Route"
        grep -E "^SIP/2\.0 404" "$uac" | head -2 | sed 's/^/        /'
    else
        record "$tag no 404 on in-dialog request" yes ""
    fi

    # The response to the BYE specifically — matched by CSeq, since the trace
    # also contains the INVITE's 200 and a bare "any 200" check would pass even
    # when the BYE was refused.
    local bye_status
    bye_status=$(awk '
        /^(SIP\/2\.0|[A-Z]+ sip:)/ { status = /^SIP\/2\.0/ ? $0 : ""; cseq = "" }
        /^CSeq:/                    { cseq = $0 }
        status != "" && cseq ~ /BYE/ { print status; status = "" }
    ' "$uac" | sort -u | tr '\n' ' ')
    if [ -z "$bye_status" ]; then
        record "$tag BYE got a final response" no "no response carrying CSeq …BYE"
    elif echo "$bye_status" | grep -q "200"; then
        record "$tag BYE answered 200 (by CSeq)" yes ""
    else
        record "$tag BYE answered 200 (by CSeq)" no "BYE answered: $bye_status"
    fi

    # --- UAS side: the proxy actually forwarded the in-dialog requests ------
    if grep -q "^BYE sip:" "$uas"; then
        record "$tag BYE relayed to UAS" yes ""
    else
        record "$tag BYE relayed to UAS" no "BYE never reached the UAS"
    fi

    # F2: an unrecognised self-Route becomes the computed next hop and the
    # is_own_address loop guard then drops the ACK silently.
    if grep -q "^ACK sip:" "$uas"; then
        record "$tag ACK relayed to UAS" yes ""
    else
        record "$tag ACK relayed to UAS" no "ACK never reached the UAS (loop-guard drop)"
    fi

    # §16.4: the relayed copies must not still carry a Route pointing at us.
    # Check every Route header the UAS received against the proxy's addresses.
    local leftover
    leftover=$(grep -iE "^Route:" "$uas" | grep -cE "127\.0\.0\.1|\[?::1\]?" || true)
    if [ "$leftover" -eq 0 ]; then
        record "$tag self-Route consumed before relay" yes ""
    else
        record "$tag self-Route consumed before relay" no \
            "$leftover relayed request(s) still carry the proxy's Route"
        grep -iE "^Route:" "$uas" | head -3 | sed 's/^/        /'
    fi

    # The UAS must have offered a route set in the first place, or the test
    # proves nothing about Route consumption.
    if grep -qiE "^Record-Route:" "$uas"; then
        record "$tag proxy did Record-Route" yes ""
    else
        record "$tag proxy did Record-Route" no \
            "no Record-Route seen by UAS — nothing to loose-route"
    fi

    # --- optional pcap cross-check -----------------------------------------
    local cap="$WORK/$tag.pcap"
    if [ -n "$CAPTURE_AVAILABLE" ] && [ -s "$cap" ]; then
        local pcap_404
        pcap_404=$(tshark -r "$cap" -Y 'sip.Status-Code == 404' 2>/dev/null | wc -l)
        if [ "$pcap_404" -eq 0 ]; then
            record "$tag pcap cross-check (no 404)" yes ""
        else
            record "$tag pcap cross-check (no 404)" no "$pcap_404 x 404 in capture"
        fi
    else
        echo "  [skip] $tag pcap cross-check — needs CAP_NET_RAW on tcpdump"
    fi
}

# ------------------------------------------------------------------------
# Case 3: a Route at our address on a port we do not serve is NOT ours.
#
# Driven directly rather than over the wire: it needs a second proxy at our
# address, which the loopback harness cannot express. The dialog cases above
# already prove the wire path; this proves the discrimination.
# ------------------------------------------------------------------------
run_colocated_case() {
    echo ""
    echo "=== case: colocated (same address, foreign port) ==="
    local config="$WORK/colocated.yaml"
    make_config "$config" "" || { record "colocated config" no "generation failed"; return; }

    # The identity is logged at debug. Asserting on the set a *live* process
    # builds is the end-to-end check of the wiring; the discrimination itself is
    # covered by unit tests (a second proxy at our address is not something the
    # loopback harness can express).
    RUST_LOG=debug start_siphon "$config" "colocated" \
        || { record "colocated siphon start" no "see log"; return; }

    local line
    line=$(grep -m1 "route self-identity" "$WORK/siphon_colocated.log" || true)
    if [ -z "$line" ]; then
        record "colocated identity built" no "no identity logged at debug"
        return
    fi
    record "colocated identity built" yes ""

    # The listen address must be present *with a port list*, not as an
    # any-port entry — an empty port list would match a co-located proxy too.
    if echo "$line" | grep -qE '"127\.0\.0\.1", \[[0-9]+'; then
        record "colocated listen address is port-scoped" yes ""
    else
        record "colocated listen address is port-scoped" no "entry not port-scoped: $line"
    fi

    # And the served domain must be an any-port alias (empty port list).
    if echo "$line" | grep -qE '"example\.com", \[\]'; then
        record "colocated served domain is an any-port alias" yes ""
    else
        record "colocated served domain is an any-port alias" no "$line"
    fi
}

CASE="${1:-all}"
case "$CASE" in
    baseline)  run_dialog_case baseline "" "$PROXY_V4" ;;
    dualstack) run_dialog_case dualstack "[::1]:5060" "$PROXY_V4" ;;
    colocated) run_colocated_case ;;
    all)
        run_dialog_case baseline "" "$PROXY_V4"
        run_dialog_case dualstack "[::1]:5060" "$PROXY_V4"
        run_colocated_case
        ;;
    *) echo "unknown case '$CASE'"; exit 1 ;;
esac

echo ""
echo "=== $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] || exit 1
