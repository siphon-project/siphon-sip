// Logs — the node's own log stream, live.
//
// The point is that an operator debugging a call does not have to leave the
// dashboard for journalctl. Filtering is sent to the server rather than applied
// here: a busy node emits far more than a browser should be asked to receive
// and discard.

import { $, html, text, esc } from "../lib/dom.js";
import * as api from "../lib/api.js";
import { openEventStream } from "../lib/stream.js";

// Bounded for the same reason the server's queue is: an unbounded list in a tab
// left open overnight is a memory leak with a nice font.
const MAX_LINES = 5000;

let handle = null;
let paused = false;
let follow = true;
let lines = [];
let unavailable = null;
let statusState = "idle";
// Whether the retained-warning backfill has been applied for the *current*
// filter. Without this, the 4s view refresh re-seeded the whole unfiltered ring
// every tick — so a filter appeared to do nothing: the list was cleared, then
// immediately refilled with everything.
let seeded = false;

const LEVEL_CLASS = {
  ERROR: "crit",
  WARN: "warn",
  INFO: "up",
  DEBUG: "info",
  TRACE: "info",
};

/** The filter the controls currently describe. */
function currentFilter() {
  return {
    level: $("log-level") ? $("log-level").value : "",
    contains: $("log-filter") ? $("log-filter").value.trim() : "",
    callId: $("log-callid") ? $("log-callid").value.trim() : "",
  };
}

function currentQuery() {
  const filter = currentFilter();
  const params = new URLSearchParams();
  if (filter.level) params.set("level", filter.level);
  if (filter.contains) params.set("contains", filter.contains);
  if (filter.callId) params.set("call_id", filter.callId);
  const query = params.toString();
  return "/admin/logs/stream" + (query ? "?" + query : "");
}

// Severity as a rank, most severe first — the same ordering the server applies,
// so the backfill and the live stream agree about what a filter admits.
const LEVEL_RANK = { ERROR: 0, WARN: 1, INFO: 2, DEBUG: 3, TRACE: 4 };
const rankOf = (level) => (level in LEVEL_RANK ? LEVEL_RANK[level] : 4);

/**
 * Whether a record satisfies the active filter.
 *
 * The live stream is filtered server-side, but `/admin/logs` returns the whole
 * retained ring, so the backfill has to be filtered here or it contradicts the
 * stream it is prepended to.
 */
function matchesFilter(record, filter) {
  if (filter.level && rankOf(record.level) > rankOf(filter.level.toUpperCase())) return false;
  if (filter.callId && record.call_id !== filter.callId) return false;
  if (filter.contains) {
    const needle = filter.contains.toLowerCase();
    const hit =
      (record.message || "").toLowerCase().includes(needle) ||
      (record.target || "").toLowerCase().includes(needle) ||
      (record.fields || []).some(([, value]) => String(value).toLowerCase().includes(needle));
    if (!hit) return false;
  }
  return true;
}

function renderStatus() {
  const element = $("log-status");
  if (!element) return;
  const label =
    unavailable ||
    (paused
      ? "paused"
      : statusState === "live"
        ? "live"
        : statusState === "reconnecting"
          ? "reconnecting…"
          : statusState === "locked"
            ? "locked — unlock first"
            : "idle");
  const tone =
    unavailable || statusState === "locked"
      ? "warn"
      : paused
        ? "info"
        : statusState === "live"
          ? "up"
          : "info";
  element.className = "spill " + tone;
  element.textContent = label;
}

function rowFor(record) {
  const stamp = new Date(record.timestamp_ms).toISOString().slice(11, 23);
  const level = record.level || "INFO";
  const fields = (record.fields || [])
    .map(([name, value]) => esc(name) + "=" + esc(value))
    .join(" ");
  return (
    '<tr class="logline">' +
    '<td class="q">' +
    esc(stamp) +
    "</td>" +
    '<td><span class="spill ' +
    (LEVEL_CLASS[level] || "info") +
    '">' +
    esc(level) +
    "</span></td>" +
    '<td class="contact">' +
    esc(record.target || "") +
    "</td>" +
    '<td class="aor">' +
    esc(record.message || "") +
    (record.call_id
      ? ' <span class="q">call_id=' + esc(record.call_id) + "</span>"
      : "") +
    (fields ? ' <span class="q">' + fields + "</span>" : "") +
    "</td>" +
    "</tr>"
  );
}

function repaint() {
  const body = $("log-lines");
  if (!body) return;
  if (!lines.length) {
    body.innerHTML =
      '<tr><td colspan="4" class="empty">' +
      (unavailable ? esc(unavailable) : "waiting for log output…") +
      "</td></tr>";
    return;
  }
  body.innerHTML = lines.map(rowFor).join("");
  if (follow) {
    const scroller = $("log-scroll");
    if (scroller) scroller.scrollTop = scroller.scrollHeight;
  }
  text("log-count", lines.length);
}

function append(record) {
  if (paused) return;
  // The stream is already filtered server-side; this guards the one case it
  // cannot cover — records still arriving from a stream opened under the
  // previous filter, while the replacement connects.
  if (!matchesFilter(record, currentFilter())) return;
  lines.push(record);
  if (lines.length > MAX_LINES) lines.splice(0, lines.length - MAX_LINES);
  repaint();
}

function stop() {
  if (handle) {
    handle.close();
    handle = null;
  }
}

function start() {
  stop();
  if (unavailable) {
    renderStatus();
    return;
  }
  handle = openEventStream(currentQuery(), {
    onMessage(payload) {
      try {
        append(JSON.parse(payload));
      } catch (error) {
        // A truncated frame is not worth tearing the stream down for.
      }
    },
    onEvent(name, payload) {
      if (name !== "dropped") return;
      // Show the gap in line, where it happened, rather than as a counter
      // somewhere else: a tail that silently skips a burst is worse than one
      // that admits it.
      append({
        timestamp_ms: Date.now(),
        level: "WARN",
        target: "siphon.dashboard",
        message: payload + " lines dropped — this view could not keep up",
      });
    },
    onStatus(state) {
      statusState = state;
      renderStatus();
    },
  });
}

/** Called by app.js when this view becomes visible / is refreshed. */
export async function load() {
  // The retained WARN+ ring gives immediate context before the stream produces
  // its first line — on a quiet node that would otherwise be a blank panel.
  //
  // Guarded by `seeded` rather than by an empty list: this runs on the 4s view
  // refresh, and keying off `lines.length` meant every filter change was undone
  // one tick later by a fresh unfiltered backfill.
  if (!seeded && !unavailable) {
    try {
      const seed = await api.logs();
      const filter = currentFilter();
      seeded = true;
      lines = (seed.records || [])
        .filter((record) => matchesFilter(record, filter))
        .slice(-MAX_LINES);
      repaint();
    } catch (error) {
      if (error instanceof api.Unauthorized) {
        unavailable = "log access is protected — unlock first";
      } else {
        unavailable =
          "log tail is not enabled on this node — set admin.log_tail.enabled";
      }
      repaint();
      renderStatus();
      return;
    }
  }
  if (!handle) start();
  renderStatus();
}

export function bind() {
  const rebind = () => {
    lines = [];
    seeded = false;
    repaint();
    start();
    // Re-apply the retained backfill under the new filter, so narrowing to a
    // call-id shows the warnings already collected for it rather than waiting
    // for the next one to happen.
    load();
  };
  ["log-level", "log-filter", "log-callid"].forEach((id) => {
    const element = $(id);
    if (!element) return;
    // Re-subscribing on every keystroke would reconnect the stream per
    // character; wait for the field to settle.
    let timer = null;
    const handler = () => {
      clearTimeout(timer);
      timer = setTimeout(rebind, 350);
    };
    element.addEventListener(element.tagName === "SELECT" ? "change" : "input", handler);
  });

  const pause = $("log-pause");
  if (pause) {
    pause.addEventListener("click", () => {
      paused = !paused;
      pause.textContent = paused ? "▶" : "⏸";
      pause.title = paused ? "Resume" : "Pause";
      renderStatus();
    });
  }

  const clear = $("log-clear");
  if (clear) {
    clear.addEventListener("click", () => {
      lines = [];
      // Clear means clear: without this the next refresh tick would helpfully
      // put the whole retained ring back.
      seeded = true;
      repaint();
    });
  }

  const followBox = $("log-follow");
  if (followBox) {
    followBox.addEventListener("change", () => {
      follow = followBox.checked;
    });
  }
}

/** Release the stream when the view is closed; `load()` reopens it. */
export function suspend() {
  stop();
  statusState = "idle";
  renderStatus();
}

/** Open the view already filtered to one call. */
export function focusCall(callId) {
  const field = $("log-callid");
  if (!field) return;
  field.value = callId;
  lines = [];
  seeded = false;
  repaint();
  start();
  load();
}

export function markup() {
  return `
    <div class="sectlabel">Live log</div>
    <section class="card">
      <div class="panelhead">
        <span class="t">Tail</span>
        <span class="count-pill"><b id="log-count">0</b> lines</span>
        <span class="spill info" id="log-status">idle</span>
      </div>
      <div class="toolbar">
        <select id="log-level" class="search">
          <option value="">all levels</option>
          <option value="error">error</option>
          <option value="warn">warn and above</option>
          <option value="info">info and above</option>
          <option value="debug">debug and above</option>
        </select>
        <span class="search"><input id="log-filter" type="text" placeholder="filter text" /></span>
        <span class="search"><input id="log-callid" type="text" placeholder="call-id" /></span>
        <span class="grow"></span>
        <label class="q"><input type="checkbox" id="log-follow" checked /> follow</label>
        <button class="iconbtn" id="log-pause" title="Pause">⏸</button>
        <button class="iconbtn" id="log-clear" title="Clear">⌫</button>
      </div>
      <div class="tblscroll logscroll" id="log-scroll">
        <table class="tbl">
          <thead>
            <tr><th>Time</th><th>Level</th><th>Target</th><th>Message</th></tr>
          </thead>
          <tbody id="log-lines">
            <tr><td colspan="4" class="empty">waiting for log output…</td></tr>
          </tbody>
        </table>
      </div>
      <div class="panelbody q">
        Shows what this node's configured <code>log.level</code> admits — tailing
        debug needs the node running at debug. Call-id filtering matches the log
        sites that attach one; Python <code>log.*</code> output carries no fields.
      </div>
    </section>
  `;
}
