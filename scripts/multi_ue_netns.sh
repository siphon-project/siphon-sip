#!/usr/bin/env bash
# Manual acceptance harness for one process registering many IMS UEs, each
# from its own address (registrant `local_addr`). Needs root (network
# namespaces, xfrm). Not run in CI.
#
# Topology:
#
#   netns $CORE_NS                                 netns $UE_NS
#   P-CSCF 198.51.100.1  (examples/ims_pcscf.py)   siphon 198.51.100.2
#   S-CSCF 198.51.100.3  (ims_scscf_aka_lab.py)    (examples/ims_multi_ue.py)
#          veth-core 198.51.100.1/24 <----------> veth-ue 198.51.100.2/24
#   route 203.0.113.0/24 via 198.51.100.2          dummy: N x 203.0.113.x/32
#
# The UE side registers N UEs, one per /32, through the P-CSCF to an S-CSCF
# doing local Milenage AKA. The home domain resolves through per-netns hosts
# files (/etc/netns/<ns>/hosts, bind-mounted by `ip netns exec`): to the
# P-CSCF in the UE namespace, to the S-CSCF in the core namespace.
#
# Checks:
#   1. every UE reaches `registered`
#   2. 4 x N xfrm states in the UE namespace
#   3. N distinct contact hosts at the S-CSCF (GET /admin/registrations)
#   4. refreshes spread over refresh_window (from the script's event lines),
#      sent over each UE's SA set: still 4 x N xfrm states after them (a
#      protected refresh the S-CSCF accepts installs no new set)
#   5. the /32s are replaced by a shifted set and the address file rewritten:
#      every UE re-registers from its new address, no restart
#   6. optional (CALL_TEST=1, needs sipp): one call from UE 1 to UE 2 through
#      the P-CSCF, bridged to a sipp UAS standing in for the tester
#   7. make-before-break (OVERLAP_TEST=1, the default): the S-CSCF re-challenges
#      UE 1's next protected refresh, so it holds an old and a new SA set on
#      one protected server port. During that overlap a datagram is sent from
#      the P-CSCF's protected client port over the OLD set (its outbound policy
#      pointed at the old SPI for the one packet); the UE kernel must decrypt it
#      on the old inbound SA with no XfrmInTmplMismatch
#   8. shutdown: SIGTERM to the UE process; once it exits, 0 xfrm states and 0
#      xfrm policies left in the UE namespace
# and prints the UE process's fd count and RSS.
#
# Usage:
#   sudo -E N=20 scripts/multi_ue_netns.sh
#
# Environment:
#   N              UEs, default 20
#   ADDR_BASE      first host octet of the UE /32s, default 10
#   ADDR_SHIFT     added to every host octet for the move step, default 100
#   INTERVAL       requested registration interval in seconds, default 120
#   SIPHON_BIN     siphon binary, default ${CARGO_TARGET_DIR:-<repo>/target}/release/siphon
#   SCRATCH        work directory (configs, logs), default
#                  <repo>/../scratch/registrant-multi-ue/netns
#   CORE_NS/UE_NS  namespace names, default core / ue (refused if they exist)
#   REGISTER_TIMEOUT seconds to wait for all UEs registered, default 120
#   CALL_TEST      1 to run the optional call step
#   OVERLAP_TEST   0 to skip the make-before-break step, default 1
#   STOP_TIMEOUT   seconds to wait for the UE process to exit, default 60
#   KEEP           1 to leave namespaces and processes up on exit
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
N="${N:-20}"
ADDR_BASE="${ADDR_BASE:-10}"
ADDR_SHIFT="${ADDR_SHIFT:-100}"
INTERVAL="${INTERVAL:-120}"
SIPHON_BIN="${SIPHON_BIN:-${CARGO_TARGET_DIR:-$REPO/target}/release/siphon}"
SCRATCH="${SCRATCH:-$REPO/../scratch/registrant-multi-ue/netns}"
CORE_NS="${CORE_NS:-core}"
UE_NS="${UE_NS:-ue}"
REGISTER_TIMEOUT="${REGISTER_TIMEOUT:-120}"
CALL_TEST="${CALL_TEST:-0}"
OVERLAP_TEST="${OVERLAP_TEST:-1}"
STOP_TIMEOUT="${STOP_TIMEOUT:-60}"
KEEP="${KEEP:-0}"

HOME_DOMAIN="ims.mnc01.mcc001.3gppnetwork.org"
CORE_IP="198.51.100.1"
UE_IP="198.51.100.2"
SCSCF_IP="198.51.100.3"
SCSCF_ADMIN="$SCSCF_IP:9091"
TESTER_PORT=5070
UAC_PORT=5080
DUMMY_DEV="mue0"
# TS 35.208 Test Set 1. Every UE shares one key: this is a lab.
USIM_K="465b5ce8b199b49faa5f0a2ee238a6bc"
USIM_OP="cdc202d5123e20f62b6d676ac72cb318"

PIDS=()

log() { printf '[%s] %s\n' "$(date +%T)" "$*"; }
fail() { log "FAIL: $*"; exit 1; }

imsi() { printf '0010100000%05d' "$1"; }
ue_addr() { printf '203.0.113.%d' "$(( ADDR_BASE + $1 - 1 + $2 ))"; }

cleanup() {
    local status=$?
    if [[ "$KEEP" == "1" ]]; then
        log "KEEP=1: leaving $CORE_NS / $UE_NS and processes up"
        exit "$status"
    fi
    local pid
    for pid in ${PIDS[@]+"${PIDS[@]}"}; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    ip netns del "$UE_NS" 2>/dev/null || true
    ip netns del "$CORE_NS" 2>/dev/null || true
    rm -rf "/etc/netns/$UE_NS" "/etc/netns/$CORE_NS"
    exit "$status"
}

preflight() {
    [[ "$(id -u)" -eq 0 ]] || fail "needs root"
    [[ -x "$SIPHON_BIN" ]] || fail "no siphon binary at $SIPHON_BIN (set SIPHON_BIN)"
    command -v python3 >/dev/null || fail "python3 not found"
    command -v curl >/dev/null || fail "curl not found"
    (( N >= 2 )) || fail "N must be at least 2"
    (( ADDR_BASE + N - 1 + ADDR_SHIFT <= 254 )) || fail "ADDR_BASE + N + ADDR_SHIFT exceeds the /24"
    (( N <= 99999 )) || fail "N too large for the IMSI range"
    local namespace existing
    existing="$(ip netns list)"
    for namespace in "$CORE_NS" "$UE_NS"; do
        if grep -qw -- "$namespace" <<<"$existing"; then
            fail "netns $namespace already exists; set CORE_NS/UE_NS"
        fi
        [[ ! -e "/etc/netns/$namespace" ]] || fail "/etc/netns/$namespace already exists"
    done
}

build_network() {
    log "creating netns $CORE_NS and $UE_NS"
    ip netns add "$CORE_NS"
    ip netns add "$UE_NS"
    ip link add veth-core type veth peer name veth-ue
    ip link set veth-core netns "$CORE_NS"
    ip link set veth-ue netns "$UE_NS"

    ip -n "$CORE_NS" link set lo up
    ip -n "$CORE_NS" addr add "$CORE_IP/24" dev veth-core
    ip -n "$CORE_NS" addr add "$SCSCF_IP/32" dev veth-core
    ip -n "$CORE_NS" link set veth-core up
    ip -n "$CORE_NS" route add 203.0.113.0/24 via "$UE_IP"

    ip -n "$UE_NS" link set lo up
    ip -n "$UE_NS" addr add "$UE_IP/24" dev veth-ue
    ip -n "$UE_NS" link set veth-ue up
    ip -n "$UE_NS" link add "$DUMMY_DEV" type dummy
    ip -n "$UE_NS" link set "$DUMMY_DEV" up
    assign_addresses 0

    # The home domain resolves to the next hop on each side.
    mkdir -p "/etc/netns/$UE_NS" "/etc/netns/$CORE_NS"
    printf '127.0.0.1 localhost\n%s %s\n' "$CORE_IP" "$HOME_DOMAIN" >"/etc/netns/$UE_NS/hosts"
    printf '127.0.0.1 localhost\n%s %s\n' "$SCSCF_IP" "$HOME_DOMAIN" >"/etc/netns/$CORE_NS/hosts"
}

# Put the UE /32s (shifted by $1) on the dummy interface, replacing any.
assign_addresses() {
    local offset="$1" index
    ip -n "$UE_NS" addr flush dev "$DUMMY_DEV"
    for (( index = 1; index <= N; index++ )); do
        ip -n "$UE_NS" addr add "$(ue_addr "$index" "$offset")/32" dev "$DUMMY_DEV"
    done
}

# The UE list the script polls, with addresses shifted by $1. Written to a
# temporary file and renamed, so the script never reads half a file.
write_ue_csv() {
    local offset="$1" index id
    {
        echo "impu,impi,k,op,opc,imei,address"
        for (( index = 1; index <= N; index++ )); do
            id="$(imsi "$index")"
            printf 'sip:%s@%s,%s@%s,%s,%s,,01234567-%06d-0,%s\n' \
                "$id" "$HOME_DOMAIN" "$id" "$HOME_DOMAIN" "$USIM_K" "$USIM_OP" \
                "$index" "$(ue_addr "$index" "$offset")"
        done
    } >"$SCRATCH/ues.csv.tmp"
    mv "$SCRATCH/ues.csv.tmp" "$SCRATCH/ues.csv"
}

write_core_configs() {
    local index
    cat >"$SCRATCH/pcscf.yaml" <<EOF
listen:
  udp:
    - "$CORE_IP:5060"
    - "$CORE_IP:5064"
    - "$CORE_IP:5066"
advertised_address: "$CORE_IP"
domain:
  local:
    - "$CORE_IP"
script:
  path: "$REPO/examples/ims_pcscf.py"
  reload: auto
registrar:
  backend: memory
  default_expires: 600000
  max_expires: 600000
ipsec:
  pcscf_port_c: 5064
  pcscf_port_s: 5066
  backend: netlink
  path_host: "$CORE_IP:5060"
# ims_pcscf.py keeps its Path tokens in these caches. Nothing listens on the
# Redis URL inside the namespace; the local LRU in front of it is what serves.
cache:
  - name: "qos_sessions"
    url: "redis://127.0.0.1:6379"
    local_ttl_secs: 600
  - name: "path_tokens"
    url: "redis://127.0.0.1:6379"
    local_ttl_secs: 600
log:
  level: info
EOF

    {
        cat <<EOF
listen:
  udp:
    - "$SCSCF_IP:5060"
advertised_address: "$SCSCF_IP"
domain:
  local:
    - "$HOME_DOMAIN"
    - "ims.test"
    - "$SCSCF_IP"
script:
  path: "$REPO/examples/ims_scscf_aka_lab.py"
  reload: auto
registrar:
  backend: memory
  default_expires: 600000
  max_expires: 600000
admin:
  listen: "$SCSCF_ADMIN"
log:
  level: info
auth:
  realm: "ims.test"
  backend: static
  aka_credentials:
EOF
        for (( index = 1; index <= N; index++ )); do
            printf '    "%s":\n      k: "%s"\n      op: "%s"\n      amf: "8000"\n' \
                "$(imsi "$index")" "$USIM_K" "$USIM_OP"
        done
    } >"$SCRATCH/scscf.yaml"
}

start_siphon() {
    local namespace="$1" name="$2" config="$3"
    shift 3
    # The extra arguments are VAR=value pairs for the process environment.
    ip netns exec "$namespace" env "$@" "$SIPHON_BIN" --config "$config" \
        >"$SCRATCH/$name.log" 2>&1 &
    PIDS+=("$!")
    log "started $name (pid $!) in $namespace, log $SCRATCH/$name.log"
}

# Print a field of the UE script's status file through python3, or "" when
# the file is not there yet. $1: a Python expression over `status`.
status_query() {
    python3 - "$SCRATCH/status.json" "$1" <<'EOF' 2>/dev/null || true
import json, sys
try:
    with open(sys.argv[1]) as handle:
        status = json.load(handle)
except (OSError, ValueError):
    sys.exit(0)
print(eval(sys.argv[2], {"status": status}))
EOF
}

# Wait until every UE is registered, from the addresses shifted by $1.
wait_registered() {
    local offset="$1" deadline registered="" expected index
    expected="$(for (( index = 1; index <= N; index++ )); do ue_addr "$index" "$offset"; echo; done | sort | tr '\n' ' ')"
    deadline=$(( SECONDS + REGISTER_TIMEOUT ))
    while (( SECONDS < deadline )); do
        registered="$(status_query "sum(1 for e in status['entries'] if e['state'] == 'registered' and e['local_addr'] in '''$expected'''.split())")"
        if [[ "$registered" == "$N" ]]; then
            log "all $N UEs registered from the expected addresses"
            return 0
        fi
        sleep 2
    done
    log "counts: $(status_query "status['counts']")"
    fail "only ${registered:-0}/$N registered from the expected addresses after ${REGISTER_TIMEOUT}s"
}

check_xfrm() {
    local states
    states="$(ip netns exec "$UE_NS" ip xfrm state | grep -c '^src' || true)"
    log "xfrm states in $UE_NS: $states (expected $(( 4 * N )))"
    [[ "$states" -eq $(( 4 * N )) ]] || fail "expected $(( 4 * N )) xfrm states, found $states"
}

# Distinct contact hosts at the S-CSCF that are in the address set shifted
# by $1.
check_contacts() {
    local offset="$1" body distinct expected index
    expected="$(for (( index = 1; index <= N; index++ )); do ue_addr "$index" "$offset"; echo; done | tr '\n' ' ')"
    body="$(ip netns exec "$CORE_NS" curl -sf "http://$SCSCF_ADMIN/admin/registrations")" \
        || fail "GET /admin/registrations on the S-CSCF failed"
    distinct="$(printf '%s' "$body" | python3 -c '
import json, re, sys
wanted = set(sys.argv[1].split())
hosts = set()
for entry in json.load(sys.stdin):
    match = re.match(r"sips?:(?:[^@]*@)?\[?([^];:>]+)", entry["uri"])
    if match and match.group(1) in wanted:
        hosts.add(match.group(1))
print(len(hosts))
' "$expected")"
    log "distinct UE contact hosts at the S-CSCF: $distinct (expected $N)"
    [[ "$distinct" -eq "$N" ]] || fail "expected $N distinct contact hosts at the S-CSCF, found $distinct"
}

# Wait for one refresh per UE and report where in the window they landed.
check_refresh_spread() {
    local deadline=$(( SECONDS + INTERVAL * 6 / 10 + 60 )) refreshed=0 result count low high
    log "waiting for one refresh per UE (window [0.4, 0.6] of ${INTERVAL}s)"
    while (( SECONDS < deadline )); do
        refreshed="$(grep -o 'multi-ue event=refreshed aor=[^ ]*' "$SCRATCH/ue.log" | sort -u | wc -l || true)"
        (( refreshed >= N )) && break
        sleep 5
    done
    (( refreshed >= N )) || fail "only $refreshed/$N UEs refreshed"
    result="$(python3 - "$SCRATCH/ue.log" "$INTERVAL" <<'EOF'
import re, sys
interval = float(sys.argv[2])
registered, refreshed = {}, {}
pattern = re.compile(r"multi-ue event=(registered|refreshed) aor=(\S+) t=([0-9.]+)")
with open(sys.argv[1], errors="replace") as handle:
    for line in handle:
        match = pattern.search(line)
        if not match:
            continue
        event, aor, stamp = match.group(1), match.group(2), float(match.group(3))
        if event == "registered":
            registered.setdefault(aor, stamp)
        elif aor in registered:
            refreshed.setdefault(aor, stamp)
fractions = sorted((refreshed[aor] - registered[aor]) / interval
                   for aor in refreshed if aor in registered)
if not fractions:
    print("none")
else:
    print(f"{len(fractions)} {fractions[0]:.3f} {fractions[-1]:.3f}")
EOF
)"
    [[ "$result" != "none" ]] || fail "no registered/refreshed pairs in the UE log"
    read -r count low high <<<"$result"
    log "first refresh of $count UEs at ${low}..${high} of the interval"
    # The draw is uniform in [0.4, 0.6]; a 200 ms tick and the challenge-free
    # round trip sit well inside the slack.
    python3 -c "import sys; low, high = float(sys.argv[1]), float(sys.argv[2]); sys.exit(0 if low >= 0.38 and high <= 0.65 and high - low >= 0.03 else 1)" \
        "$low" "$high" || fail "refreshes at ${low}..${high}: not spread over [0.4, 0.6]"
}

report_process() {
    local pid="$1" fds rss
    fds="$(find "/proc/$pid/fd" -mindepth 1 -maxdepth 1 | wc -l)"
    rss="$(awk '/^VmRSS/ {print $2, $3}' "/proc/$pid/status")"
    log "UE process $pid: $fds fds (3 per UE plus the base set), RSS $rss"
}

call_test() {
    command -v sipp >/dev/null || { log "CALL_TEST: sipp not found, skipped"; return 0; }
    local caller callee
    caller="$(imsi 1)"
    callee="$(imsi 2)"
    cat >"$SCRATCH/uac.xml" <<EOF
<?xml version="1.0" encoding="ISO-8859-1" ?>
<scenario name="multi-ue tester call">
  <send retrans="500">
    <![CDATA[
      INVITE sip:$callee@[remote_ip]:[remote_port] SIP/2.0
      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
      From: <sip:$caller@[local_ip]:[local_port]>;tag=[pid]SIPpTag00[call_number]
      To: <sip:$callee@[remote_ip]:[remote_port]>
      Call-ID: [call_id]
      CSeq: 1 INVITE
      Contact: <sip:$caller@[local_ip]:[local_port]>
      Max-Forwards: 70
      Content-Type: application/sdp
      Content-Length: [len]

      v=0
      o=- 1 1 IN IP4 [local_ip]
      s=-
      c=IN IP4 [local_ip]
      t=0 0
      m=audio 40000 RTP/AVP 0
      a=rtpmap:0 PCMU/8000
    ]]>
  </send>
  <recv response="100" optional="true"/>
  <recv response="180" optional="true"/>
  <recv response="183" optional="true"/>
  <recv response="200" rtd="true"/>
  <send>
    <![CDATA[
      ACK sip:$callee@[remote_ip]:[remote_port] SIP/2.0
      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
      From: <sip:$caller@[local_ip]:[local_port]>;tag=[pid]SIPpTag00[call_number]
      To: <sip:$callee@[remote_ip]:[remote_port]>[peer_tag_param]
      Call-ID: [call_id]
      CSeq: 1 ACK
      Max-Forwards: 70
      Content-Length: 0

    ]]>
  </send>
  <pause milliseconds="1000"/>
  <send retrans="500">
    <![CDATA[
      BYE sip:$callee@[remote_ip]:[remote_port] SIP/2.0
      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
      From: <sip:$caller@[local_ip]:[local_port]>;tag=[pid]SIPpTag00[call_number]
      To: <sip:$callee@[remote_ip]:[remote_port]>[peer_tag_param]
      Call-ID: [call_id]
      CSeq: 2 BYE
      Max-Forwards: 70
      Content-Length: 0

    ]]>
  </send>
  <recv response="200"/>
</scenario>
EOF
    log "CALL_TEST: $caller -> $callee through the P-CSCF, bridged to a sipp UAS"
    ip netns exec "$UE_NS" sipp -sn uas -i "$UE_IP" -p "$TESTER_PORT" -m 1 \
        -trace_err -error_file "$SCRATCH/uas_errors.log" >"$SCRATCH/uas.log" 2>&1 &
    local uas_pid=$!
    PIDS+=("$uas_pid")
    sleep 1
    if ip netns exec "$UE_NS" sipp "$UE_IP:5060" -sf "$SCRATCH/uac.xml" \
        -i "$UE_IP" -p "$UAC_PORT" -m 1 -timeout 40s \
        -trace_err -error_file "$SCRATCH/uac_errors.log" >"$SCRATCH/uac.log" 2>&1; then
        log "CALL_TEST: call completed"
    else
        fail "CALL_TEST: call failed, see $SCRATCH/uac_errors.log and $SCRATCH/ue.log"
    fi
}

# The SPIs of the inbound states in the UE namespace whose selector is
# P-CSCF:5064 -> $1:6101 (SA #3 of each set the UE holds there), one per line.
ue_server_spis() {
    ip netns exec "$UE_NS" ip xfrm state list dst "$1" proto esp | python3 -c '
import re, sys
spi = None
for line in sys.stdin:
    if line.startswith("src "):
        spi = None
    match = re.search(r"proto esp spi (0x[0-9a-f]+)", line)
    if match:
        spi = match.group(1)
    if spi and re.search(r"sel src \S+ dst \S+ .*sport 5064 dport 6101", line):
        print(spi)
'
}

xfrm_stat() {
    ip netns exec "$UE_NS" awk -v name="$1" '$1 == name {print $2}' /proc/net/xfrm_stat
}

# Packets the UE namespace decrypted on the inbound state with SPI $2 to $1.
state_packets() {
    ip netns exec "$UE_NS" ip -s xfrm state get src "$CORE_IP" dst "$1" proto esp spi "$2" \
        | awk '/lifetime current:/ {getline; if (match($0, /[0-9]+\(packets\)/)) print substr($0, RSTART, RLENGTH - 9); exit}'
}

check_overlap() {
    local ue deadline spis old new before_mismatch after_mismatch before after
    ue="$(ue_addr 1 "$ADDR_SHIFT")"
    old="$(ue_server_spis "$ue" | head -n 1)"
    [[ -n "$old" ]] || fail "OVERLAP: no inbound SA #3 for $ue"
    log "OVERLAP: re-challenging protected refreshes; waiting for UE 1 ($ue) to hold two sets"
    touch "$SCRATCH/rechallenge"
    deadline=$(( SECONDS + INTERVAL ))
    spis=""
    while (( SECONDS < deadline )); do
        spis="$(ue_server_spis "$ue")"
        [[ "$(wc -l <<<"$spis")" -ge 2 ]] && break
        sleep 1
    done
    rm -f "$SCRATCH/rechallenge"
    [[ "$(wc -l <<<"$spis")" -ge 2 ]] || fail "OVERLAP: UE 1 never held two sets"
    new="$(grep -v -x -- "$old" <<<"$spis" | head -n 1)"
    log "OVERLAP: old SA #3 spi $old, new $new"

    before_mismatch="$(xfrm_stat XfrmInTmplMismatch)"
    before="$(state_packets "$ue" "$old")"
    # One datagram from the P-CSCF's protected client port over the old set:
    # its outbound policy points at the old SPI for this packet only.
    ip netns exec "$CORE_NS" ip xfrm policy update src "$CORE_IP/32" dst "$ue/32" \
        proto any sport 5064 dport 6101 dir out \
        tmpl src "$CORE_IP" dst "$ue" proto esp spi "$old" mode transport
    ip netns exec "$CORE_NS" python3 -c '
import socket, sys
probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
probe.bind((sys.argv[1], 5064))
probe.sendto(b"OPTIONS sip:overlap-probe SIP/2.0\r\nContent-Length: 0\r\n\r\n", (sys.argv[2], 6101))
' "$CORE_IP" "$ue"
    ip netns exec "$CORE_NS" ip xfrm policy update src "$CORE_IP/32" dst "$ue/32" \
        proto any sport 5064 dport 6101 dir out \
        tmpl src "$CORE_IP" dst "$ue" proto esp spi "$new" mode transport
    sleep 1
    after="$(state_packets "$ue" "$old")"
    after_mismatch="$(xfrm_stat XfrmInTmplMismatch)"
    log "OVERLAP: old SA #3 packets $before -> $after, XfrmInTmplMismatch $before_mismatch -> $after_mismatch"
    (( after > before )) || fail "OVERLAP: the old set did not receive the probe"
    [[ "$after_mismatch" == "$before_mismatch" ]] \
        || fail "OVERLAP: the UE dropped a packet on the old set (template mismatch)"
}

check_shutdown_cleanup() {
    local pid="$1" deadline states policies
    log "SHUTDOWN: SIGTERM to the UE process $pid"
    kill -TERM "$pid"
    deadline=$(( SECONDS + STOP_TIMEOUT ))
    while kill -0 "$pid" 2>/dev/null && (( SECONDS < deadline )); do
        sleep 1
    done
    if kill -0 "$pid" 2>/dev/null; then
        fail "SHUTDOWN: the UE process did not exit within ${STOP_TIMEOUT}s"
    fi
    states="$(ip netns exec "$UE_NS" ip xfrm state | grep -c '^src' || true)"
    policies="$(ip netns exec "$UE_NS" ip xfrm policy | grep -c '^src' || true)"
    log "SHUTDOWN: xfrm states $states, policies $policies left in $UE_NS (expected 0 and 0)"
    [[ "$states" -eq 0 && "$policies" -eq 0 ]] \
        || fail "SHUTDOWN: the UE left security associations in the kernel"
}

main() {
    preflight
    mkdir -p "$SCRATCH"
    rm -f "$SCRATCH"/*.log "$SCRATCH/status.json" "$SCRATCH/rechallenge"
    trap cleanup EXIT
    trap 'exit 130' INT TERM

    build_network
    write_core_configs
    write_ue_csv 0

    start_siphon "$CORE_NS" scscf "$SCRATCH/scscf.yaml" \
        "AKA_LAB_RECHALLENGE_FILE=$SCRATCH/rechallenge"
    start_siphon "$CORE_NS" pcscf "$SCRATCH/pcscf.yaml"
    sleep 2
    # The UE side runs the shipped example config from the repo root, so its
    # relative script path resolves.
    cd "$REPO"
    start_siphon "$UE_NS" ue "$REPO/examples/ims_multi_ue.yaml" \
        "PROCESS_IP=$UE_IP" \
        "IMS_HOME=$HOME_DOMAIN" \
        "PCSCF=sip:$HOME_DOMAIN:5060" \
        "TESTER=sip:tester@$UE_IP:$TESTER_PORT" \
        "MULTI_UE_CSV=$SCRATCH/ues.csv" \
        "MULTI_UE_STATUS=$SCRATCH/status.json" \
        "MULTI_UE_INTERVAL=$INTERVAL"
    local ue_pid="${PIDS[-1]}"

    wait_registered 0
    check_xfrm
    check_contacts 0
    report_process "$ue_pid"
    check_refresh_spread
    check_xfrm

    log "moving every UE: /32s shifted by $ADDR_SHIFT, address file rewritten"
    assign_addresses "$ADDR_SHIFT"
    write_ue_csv "$ADDR_SHIFT"
    wait_registered "$ADDR_SHIFT"
    kill -0 "$ue_pid" 2>/dev/null || fail "the UE process exited"
    check_xfrm
    check_contacts "$ADDR_SHIFT"
    report_process "$ue_pid"

    if [[ "$CALL_TEST" == "1" ]]; then
        call_test
    fi
    if [[ "$OVERLAP_TEST" == "1" ]]; then
        check_overlap
    fi
    check_shutdown_cleanup "$ue_pid"
    log "PASS"
}

main "$@"
