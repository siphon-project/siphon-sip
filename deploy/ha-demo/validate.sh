#!/usr/bin/env bash
#
# HA-demo validation: prove the "front LB + 2 backends + shared Redis" pattern
# works, and that the one durability claim the docs make is real — a backend
# recovers its full registrar from Redis on restart.
#
# This runs the siphon BINARY directly on the host (no Docker image build), with a
# throwaway Redis in a container. It is fully isolated (own ports, own Redis,
# own temp dir) so it can't collide with the project's perf/mem-leak harness.
#
# Requirements: a built `siphon` binary (redis-backend feature), `docker`, `curl`,
# `python3`.
#
#   SIPHON_BIN=/path/to/siphon ./validate.sh
#
# Exit 0 = all assertions passed.

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIPHON_BIN="${SIPHON_BIN:-$DIR/../../target/release/siphon}"

# Isolated ports / names so nothing collides with anything else on the box.
REDIS_NAME="siphon-hademo-redis"
REDIS_PORT=6399
FE_PORT=6060;  FE_METRICS=9100; FE_ADMIN=9110
BE1_PORT=6061; BE1_METRICS=9101; BE1_ADMIN=9111
BE2_PORT=6062; BE2_METRICS=9102; BE2_ADMIN=9112

WORK="$(mktemp -d)"
PIDS=()
PASS=0; FAIL=0

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
info()  { printf '\033[36m• %s\033[0m\n' "$*"; }

cleanup() {
  set +e
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
  docker rm -f "$REDIS_NAME" >/dev/null 2>&1
  rm -rf "$WORK"
}
trap cleanup EXIT

assert() { # assert "<label>" <actual> <expected-or-predicate>
  local label="$1" actual="$2" expect="$3"
  if [[ "$expect" == "not404" ]]; then
    if [[ "$actual" != "404" && "$actual" != "000" ]]; then
      green "  PASS  $label (got $actual)"; PASS=$((PASS+1)); return
    fi
  elif [[ "$actual" == "$expect" ]]; then
    green "  PASS  $label (got $actual)"; PASS=$((PASS+1)); return
  fi
  red "  FAIL  $label (got '$actual', expected '$expect')"; FAIL=$((FAIL+1))
}

sip() { python3 "$DIR/sipcli.py" "$@"; }
rcli() { docker exec "$REDIS_NAME" redis-cli "$@"; }

wait_metrics() { # wait until /metrics on $1 returns 200
  local port="$1" i
  for i in $(seq 1 30); do
    if [[ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/metrics" 2>/dev/null)" == "200" ]]; then
      return 0
    fi
    sleep 0.5
  done
  red "node on metrics port $port never became ready"; return 1
}

LAST_PID=""
start_node() { # start_node <logfile> <configfile> <KEY=VAL>...
  local log="$1" cfg="$2"; shift 2
  env "$@" PYO3_PYTHON="${PYO3_PYTHON:-python3}" "$SIPHON_BIN" --config "$cfg" >"$log" 2>&1 &
  LAST_PID="$!"
  PIDS+=("$LAST_PID")
}

# --- preflight ----------------------------------------------------------------
[[ -x "$SIPHON_BIN" ]] || { red "siphon binary not found/executable at $SIPHON_BIN (set SIPHON_BIN)"; exit 2; }
command -v docker >/dev/null || { red "docker is required"; exit 2; }
command -v curl   >/dev/null || { red "curl is required"; exit 2; }

info "siphon binary: $SIPHON_BIN"
info "work dir: $WORK"

# --- redis --------------------------------------------------------------------
info "starting throwaway Redis on 127.0.0.1:$REDIS_PORT"
docker rm -f "$REDIS_NAME" >/dev/null 2>&1 || true
docker run -d --rm --name "$REDIS_NAME" -p "127.0.0.1:$REDIS_PORT:6379" \
  redis:7-alpine redis-server --save "" --appendonly no >/dev/null
for i in $(seq 1 30); do rcli ping >/dev/null 2>&1 && break; sleep 0.5; done

REDIS_ENV=(REDIS_HOST=127.0.0.1 REDIS_PORT="$REDIS_PORT")

# --- backends + frontend ------------------------------------------------------
info "starting backend1 (SIP $BE1_PORT, metrics $BE1_METRICS, admin $BE1_ADMIN)"
start_node "$WORK/backend1.log" "$DIR/siphon-backend.yaml" \
  INSTANCE_ID=backend1 SIP_PORT="$BE1_PORT" METRICS_PORT="$BE1_METRICS" ADMIN_PORT="$BE1_ADMIN" \
  SCRIPT_PATH="$DIR/proxy.py" "${REDIS_ENV[@]}"
BE1_PID="$LAST_PID"

info "starting backend2 (SIP $BE2_PORT, metrics $BE2_METRICS, admin $BE2_ADMIN)"
start_node "$WORK/backend2.log" "$DIR/siphon-backend.yaml" \
  INSTANCE_ID=backend2 SIP_PORT="$BE2_PORT" METRICS_PORT="$BE2_METRICS" ADMIN_PORT="$BE2_ADMIN" \
  SCRIPT_PATH="$DIR/proxy.py" "${REDIS_ENV[@]}"

info "starting frontend LB (SIP $FE_PORT, metrics $FE_METRICS, admin $FE_ADMIN)"
start_node "$WORK/frontend.log" "$DIR/siphon-frontend.yaml" \
  INSTANCE_ID=frontend SIP_PORT="$FE_PORT" METRICS_PORT="$FE_METRICS" ADMIN_PORT="$FE_ADMIN" \
  SCRIPT_PATH="$DIR/lb.py" \
  BACKEND1_URI="sip:127.0.0.1:$BE1_PORT" BACKEND1_ADDR="127.0.0.1:$BE1_PORT" \
  BACKEND2_URI="sip:127.0.0.1:$BE2_PORT" BACKEND2_ADDR="127.0.0.1:$BE2_PORT"

wait_metrics "$BE1_METRICS"; wait_metrics "$BE2_METRICS"; wait_metrics "$FE_METRICS"
green "all three nodes up"

echo
info "PHASE 0 — admin API probes"
httpcode() { curl -s -o /dev/null -w '%{http_code}' "$1" 2>/dev/null; }
assert "GET /admin/health (liveness) -> 200" "$(httpcode http://127.0.0.1:$BE1_ADMIN/admin/health)" 200
assert "GET /admin/ready (readiness) -> 200" "$(httpcode http://127.0.0.1:$BE1_ADMIN/admin/ready)"  200

echo
info "PHASE A — front LB + DNS-SRV-style spread + node-local registrar"
# Register through the LB; the LB hashes the AoR to one backend, which saves it.
assert "REGISTER alice via LB -> 200"        "$(sip register 127.0.0.1 $FE_PORT alice 127.0.0.1 7777)" 200
# Terminating INVITE through the LB hashes alice to the SAME backend -> lookup hit.
assert "INVITE alice via LB -> not 404"      "$(sip invite   127.0.0.1 $FE_PORT alice)"                not404

echo
info "PHASE B — Redis durability + restart recovery (the one claim worth proving)"
# Talk DIRECTLY to backend1 so we know exactly which node holds the binding.
assert "REGISTER bob on backend1 -> 200"     "$(sip register 127.0.0.1 $BE1_PORT bob 127.0.0.1 7778)"  200
assert "INVITE bob on backend1 -> not 404"   "$(sip invite   127.0.0.1 $BE1_PORT bob)"                 not404
# Honest limitation: backend2 never saw bob's REGISTER (no live cross-node sync).
assert "INVITE bob on backend2 -> 404"       "$(sip invite   127.0.0.1 $BE2_PORT bob)"                 404
# Persistence is in Redis, independent of the siphon process.
assert "bob's binding present in Redis"      "$(rcli KEYS 'siphon:reg:*' | grep -c bob || true)"       1

info "killing backend1 (simulating a node failure / restart)"
kill "$BE1_PID" 2>/dev/null || true
sleep 1
info "restarting backend1 — it must reload the snapshot from Redis"
start_node "$WORK/backend1.restart.log" "$DIR/siphon-backend.yaml" \
  INSTANCE_ID=backend1 SIP_PORT="$BE1_PORT" METRICS_PORT="$BE1_METRICS" ADMIN_PORT="$BE1_ADMIN" \
  SCRIPT_PATH="$DIR/proxy.py" "${REDIS_ENV[@]}"
wait_metrics "$BE1_METRICS"

# The boot log proves the snapshot was loaded.
restored=""
for i in $(seq 1 20); do
  if grep -q "restored contacts from Redis backend" "$WORK/backend1.restart.log" 2>/dev/null; then
    restored="yes"; break
  fi
  sleep 0.5
done
assert "backend1 logged snapshot restore"    "${restored:-no}"                                         yes
# And the recovered node answers for bob WITHOUT bob re-registering.
assert "INVITE bob on restarted backend1 -> not 404" "$(sip invite 127.0.0.1 $BE1_PORT bob)"           not404

# --- summary ------------------------------------------------------------------
echo
if [[ "$FAIL" -eq 0 ]]; then
  green "==== ALL $PASS ASSERTIONS PASSED ===="
  green "LB+SRV pattern works; Redis-backed registrar survives a node restart."
  exit 0
else
  red "==== $FAIL FAILED, $PASS passed ===="
  red "backend1 restart log: $WORK/backend1.restart.log (kept until process exit)"
  exit 1
fi
