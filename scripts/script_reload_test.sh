#!/usr/bin/env bash
# script_reload_test.sh — what reloads a script, and what does not (real binary).
#
# Three properties, none of which a unit test can reach, because all three are
# about signal delivery and inotify against a running process:
#
#   1. `reload: sighup` reloads on SIGHUP. It used to reload on nothing at all:
#      the mode disabled the watcher and no SIGHUP handler existed anywhere, so
#      `kill -HUP` terminated siphon on the default disposition and a
#      deployment that picked the mode to control *when* module state is wiped
#      got a script frozen at boot.
#   2. Under `reload: sighup`, writing a watched file still does not reload —
#      that is the whole of what the mode buys.
#   3. Under `reload: auto`, editing a sibling `.py` the script never imports
#      does NOT reload it, while editing one it does import DOES. Two siphon
#      processes sharing a script directory used to reload each other, and a
#      reload re-executes the script in a fresh namespace, so the process that
#      had not changed lost its module-level state.
#
# Runs the real binary against loopback — no docker, no SIPp.
#
# Requires: python3, a built siphon. Usage: scripts/script_reload_test.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT" || exit 2

BINARY="${SIPHON_BIN:-$REPO_ROOT/target/release/siphon}"
WORK="$(mktemp -d -t siphon-reload-XXXXXX)"
LOG="$WORK/siphon.log"
SIPHON_PID=""

cleanup() {
  [[ -n "$SIPHON_PID" ]] && kill -9 "$SIPHON_PID" >/dev/null 2>&1
  rm -rf "$WORK"
}
trap cleanup EXIT

if [[ ! -x "$BINARY" ]]; then
  if [[ -n "${SIPHON_BIN:-}" ]]; then
    echo "error: SIPHON_BIN=$SIPHON_BIN is not an executable" >&2
    exit 2
  fi
  echo "=== building siphon (no binary at $BINARY) ==="
  if ! PYO3_PYTHON="${PYO3_PYTHON:-python3}" cargo build --release --bin siphon; then
    echo "error: build failed" >&2
    exit 2
  fi
fi

# The script under test, the helper it imports, and a sibling it never does —
# the second process's script, as far as this one is concerned.
cat > "$WORK/helper.py" <<'PY'
VALUE = "v1"
PY
cat > "$WORK/stranger.py" <<'PY'
VALUE = "unrelated"
PY
cat > "$WORK/main.py" <<'PY'
from siphon import proxy
import helper


@proxy.on_request("OPTIONS")
def options(request):
    request.reply(200, "OK")
PY

# A port nothing else on the box is on: this never receives traffic, the
# reload count is read from the log.
cat > "$WORK/siphon.yaml" <<YAML
listen:
  udp:
    - "127.0.0.1:15098"
domain:
  local:
    - "reload.test"
script:
  path: "$WORK/main.py"
  reload: RELOAD_MODE
log:
  level: info
  format: pretty
YAML

# How many times siphon has said it reloaded, since boot.
reload_count() {
  grep -c "reloading script" "$LOG" 2>/dev/null || true
}

start_siphon() {
  local mode="$1"
  sed "s/RELOAD_MODE/$mode/" "$WORK/siphon.yaml" > "$WORK/siphon.active.yaml"
  PYO3_PYTHON="${PYO3_PYTHON:-python3}" "$BINARY" --config "$WORK/siphon.active.yaml" \
    >"$LOG" 2>&1 &
  SIPHON_PID=$!

  # Wait for the script to be compiled and the listener bound, rather than
  # sleeping a fixed amount: startup compiles Python, which is neither instant
  # nor constant.
  for _ in $(seq 1 100); do
    if grep -q "ready" "$LOG" 2>/dev/null; then
      return 0
    fi
    if ! kill -0 "$SIPHON_PID" 2>/dev/null; then
      echo "FAIL: siphon exited during startup"
      cat "$LOG"
      return 1
    fi
    sleep 0.1
  done
  echo "FAIL: siphon did not come up"
  cat "$LOG"
  return 1
}

stop_siphon() {
  [[ -n "$SIPHON_PID" ]] || return 0
  kill -TERM "$SIPHON_PID" >/dev/null 2>&1
  wait "$SIPHON_PID" 2>/dev/null
  SIPHON_PID=""
}

# Give the watcher its coalescing window (250 ms) plus slack before counting.
settle() { sleep 1.5; }

fail() {
  echo "FAIL: $1"
  echo "--- siphon log ---"
  tail -30 "$LOG"
  stop_siphon
  exit 1
}

# ── 1 + 2: reload: sighup ────────────────────────────────────────────────────
echo "=== reload: sighup — SIGHUP reloads, a file write does not ==="
start_siphon sighup || exit 1

before="$(reload_count)"
echo 'VALUE = "v2"' > "$WORK/helper.py"
touch "$WORK/main.py"
settle
if [[ "$(reload_count)" != "$before" ]]; then
  fail "reload: sighup reloaded on a file write (that is what the mode turns off)"
fi
echo "ok: a file write did not reload"

kill -HUP "$SIPHON_PID" || fail "could not signal siphon"
settle
if ! kill -0 "$SIPHON_PID" 2>/dev/null; then
  fail "SIGHUP terminated siphon instead of reloading it"
fi
if [[ "$(reload_count)" -lt 1 ]]; then
  fail "SIGHUP did not reload the script"
fi
echo "ok: SIGHUP reloaded the script, and siphon is still running"
stop_siphon

# ── 3: reload: auto, and whose file changed ──────────────────────────────────
echo
echo "=== reload: auto — an imported helper reloads, a sibling does not ==="
echo 'VALUE = "v1"' > "$WORK/helper.py"
start_siphon auto || exit 1

before="$(reload_count)"
echo 'VALUE = "still unrelated"' > "$WORK/stranger.py"
settle
if [[ "$(reload_count)" != "$before" ]]; then
  fail "a sibling .py the script never imports reloaded it — that is another process's deploy"
fi
echo "ok: a sibling the script never imports did not reload it"

echo 'VALUE = "v2"' > "$WORK/helper.py"
settle
if [[ "$(reload_count)" -le "$before" ]]; then
  fail "editing an imported helper did not reload the script"
fi
echo "ok: editing an imported helper reloaded the script"

# A burst is one reload, not one per write.
before="$(reload_count)"
for value in a b c; do
  echo "VALUE = \"$value\"" > "$WORK/helper.py"
done
settle
after="$(reload_count)"
if (( after - before != 1 )); then
  fail "three writes inside the coalescing window caused $((after - before)) reloads, expected 1"
fi
echo "ok: three writes in one burst caused one reload"
stop_siphon

echo
echo "PASS: reload scope and SIGHUP behave"
