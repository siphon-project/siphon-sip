// Calls — active B2BUA calls.
//
// This is the view Prometheus fundamentally cannot provide: per-call state
// keyed on a Call-ID. It previously showed five columns and no duration, which
// left the two questions an operator actually asks ("how long has this been up"
// and "why did that branch fail") unanswerable.

import { $, html, text, esc, table, transportChip } from "../lib/dom.js";
import { count, elapsed, isAbsent } from "../lib/format.js";
import { fact } from "../lib/widgets.js";
import * as api from "../lib/api.js";
import { openDrawer } from "../drawer.js";

let cache = [];
let query = "";

const STATE_COLORS = {
  calling: "var(--cyan)",
  ringing: "var(--warn)",
  answered: "var(--up)",
  terminated: "var(--faint)",
};

function stateChip(state) {
  const color = STATE_COLORS[state] || "var(--muted)";
  return '<span class="spill" style="color:' + color + ";border-color:" + color + '">' + esc(state) + "</span>";
}

/**
 * Branch outcomes as chips. A fork that lost three of four branches can say why
 * each lost — the failure code is carried per branch and was previously dropped
 * on the floor.
 */
function branchChips(branches) {
  if (!branches || !branches.length) return '<span class="q">—</span>';
  return branches
    .map((branch) => {
      const failed = branch.status === "failed";
      const cls = branch.winner ? "up" : failed ? "down" : branch.status === "ringing" ? "warn" : "";
      const label = failed && branch.code ? branch.status + " " + branch.code : branch.status;
      return '<span class="spill ' + cls + '" title="' + esc(branch.target || "") + '">' + esc(label) + "</span> ";
    })
    .join("");
}

function row(call) {
  // Talk time once answered, ring time before that — conflating them hides
  // whether a call is stuck ringing or genuinely long.
  const answered = !isAbsent(call.talk_secs);
  const durationCell = answered
    ? '<span title="talking">' + esc(elapsed(call.talk_secs)) + "</span>"
    : '<span class="q" title="ringing">' + esc(elapsed(call.ringing_secs)) + "</span>";

  const flags = [];
  if (call.originated) flags.push('<span class="spill info" title="siphon placed this call">out</span>');
  if (call.recording) flags.push('<span class="spill warn" title="recording / intercept requested">rec</span>');
  if (call.transfer) {
    flags.push(
      '<span class="spill warn" title="' + esc(call.transfer.refer_to || "") + '">xfer</span>',
    );
  }
  if (call.control_app) {
    flags.push('<span class="spill info" title="controlled by ' + esc(call.control_app) + '">app</span>');
  }
  if (call.route_attempts && call.route_attempts.length) {
    flags.push('<span class="spill" title="least-cost routing">lcr ' + call.route_attempts.length + "</span>");
  }

  return (
    '<tr class="rowlink" data-call="' +
    esc(call.id) +
    '"><td class="aor">' +
    esc(call.call_id) +
    "</td><td>" +
    stateChip(call.state) +
    '</td><td class="num">' +
    durationCell +
    '</td><td class="contact">' +
    esc(call.a_party || "—") +
    " " +
    transportChip(call.a_transport) +
    '</td><td class="contact">' +
    esc(call.b_party || "—") +
    "</td><td>" +
    branchChips(call.branches) +
    "</td><td>" +
    (flags.join(" ") || '<span class="q">—</span>') +
    "</td></tr>"
  );
}

function detail(call) {
  const rows = [
    fact("call-id", call.call_id),
    fact("internal id", call.id),
    fact("state", call.state),
    fact("direction", call.originated ? "originated by siphon" : "inbound"),
    fact("ringing for", elapsed(call.ringing_secs)),
    fact("talking for", isAbsent(call.talk_secs) ? "not answered" : elapsed(call.talk_secs)),
    fact("A-party", call.a_party || "—"),
    fact("A transport", (call.a_transport || "—") + " " + (call.a_remote_addr || "")),
    fact("B-party", call.b_party || "—"),
    fact("B-legs", call.b_legs),
    fact("controlled by", call.control_app || "—"),
    fact("recording", call.recording ? "requested" : "no"),
    // Cost is an estimate from the routing API's rate — "not rated" rather than
    // a zero when no carrier rate is in play.
    fact(
      "carrier",
      call.rating ? call.rating.carrier + " (" + (call.rating.currency || "?") + ")" : "not rated",
    ),
    fact(
      "cost so far",
      call.rating && call.rating.cost !== null && call.rating.cost !== undefined
        ? "~" + call.rating.cost.toFixed(4) + " " + (call.rating.currency || "")
        : "—",
    ),
  ];

  let body = '<div class="facts">' + rows.join("") + "</div>";

  if (call.session_timer) {
    body +=
      '<div class="subhead" style="margin-top:14px">Session timer (RFC 4028)</div><div class="facts">' +
      fact("session-expires", call.session_timer.expires + "s") +
      fact("refresher", call.session_timer.refresher) +
      fact("last refresh", elapsed(call.session_timer.last_refresh_secs) + " ago") +
      "</div>";
  }

  if (call.transfer) {
    body +=
      '<div class="subhead" style="margin-top:14px">Transfer (RFC 3515)</div><div class="facts">' +
      fact("state", call.transfer.state) +
      fact("refer-to", call.transfer.refer_to || "—") +
      fact("replaces", call.transfer.replaces_call_id || "blind transfer") +
      "</div>";
  }

  if (call.branches && call.branches.length) {
    body +=
      '<div class="subhead" style="margin-top:14px">Branches</div>' +
      table(
        ["Target", "Status", "Transport", "Address"],
        call.branches.map(
          (branch) =>
            "<tr><td>" +
            esc(branch.target || "—") +
            (branch.winner ? ' <span class="spill up">won</span>' : "") +
            "</td><td>" +
            esc(branch.status + (branch.code ? " " + branch.code : "")) +
            "</td><td>" +
            transportChip(branch.transport) +
            '</td><td class="contact">' +
            esc(branch.remote_addr || "—") +
            "</td></tr>",
        ),
        "no branches",
      );
  }

  if (call.route_attempts && call.route_attempts.length) {
    body +=
      '<div class="subhead" style="margin-top:14px">Carrier attempts (LCR)</div>' +
      table(
        ["Carrier", "Result", "Elapsed"],
        call.route_attempts.map(
          (attempt) =>
            "<tr><td>" +
            esc(attempt.carrier) +
            "</td><td>" +
            // `dialed: false` means siphon never got the INVITE onto the wire,
            // so the status is siphon's own verdict and not the carrier's.
            (attempt.dialed
              ? esc(attempt.status)
              : '<span class="spill warn" title="siphon never dialled this carrier — local gateway or DNS problem, not a carrier fault">' +
                esc(attempt.status) +
                " local</span>") +
            '</td><td class="num">' +
            esc(attempt.elapsed_ms) +
            " ms</td></tr>",
        ),
        "no attempts",
      );
  }

  return body;
}

export async function load() {
  try {
    cache = await api.calls();
  } catch (error) {
    html(
      "call-rows",
      '<tr><td colspan="7" class="empty">' +
        (error instanceof api.Unauthorized
          ? "read access is protected — unlock with an admin token"
          : "failed to load") +
        "</td></tr>",
    );
    return;
  }
  draw();
}

function draw() {
  const filtered = cache.filter(
    (call) =>
      !query ||
      [call.call_id, call.a_party, call.b_party, call.state, call.control_app]
        .join(" ")
        .toLowerCase()
        .includes(query),
  );
  text("call-count", filtered.length);
  text("nav-calls", cache.length || "");
  html(
    "call-rows",
    filtered.length
      ? filtered.map(row).join("")
      : '<tr><td colspan="7" class="empty">no active B2BUA calls</td></tr>',
  );
}

/**
 * Render the captured SIP exchange for one call as a ladder.
 *
 * Drawn from the capture ring rather than reconstructed from state, so what is
 * shown is what actually crossed the wire — including the retransmissions and
 * the branch that failed, which a reconstruction would smooth over.
 */
function ladderMarkup(captured) {
  if (!captured || !captured.messages || !captured.messages.length) {
    return '<div class="empty">nothing captured for this call</div>';
  }
  const first = captured.messages[0].timestamp_ms;
  const rows = captured.messages
    .map((message, index) => {
      const offset = ((message.timestamp_ms - first) / 1000).toFixed(3);
      const inbound = message.direction === "in";
      const arrow = inbound ? "&#8594;" : "&#8592;";
      return (
        '<tr class="rowlink" data-msg="' + index + '">' +
        '<td class="q">+' + esc(offset) + "s</td>" +
        '<td class="' + (inbound ? "aor" : "contact") + '" title="' + esc(message.peer) + '">' +
        arrow + " " + esc(message.transport) + "</td>" +
        '<td class="aor">' + esc(message.start_line) + "</td>" +
        '<td class="num q">' + esc(message.bytes) + "</td>" +
        "</tr>" +
        '<tr class="msgraw" id="msgraw-' + index + '" hidden><td colspan="4">' +
        "<pre>" + esc(message.raw) + "</pre></td></tr>"
      );
    })
    .join("");
  return (
    '<div class="subhead" style="margin-top:14px">Signalling (' +
    captured.messages.length +
    " messages)</div>" +
    table(["Offset", "Dir", "Message", { label: "Bytes" }], [rows], "nothing captured")
  );
}

/** Fetch and append the ladder after the drawer is already showing. */
async function appendLadder(callId) {
  let captured = null;
  try {
    captured = await api.get("/admin/capture/" + encodeURIComponent(callId));
  } catch (error) {
    const container = $("call-ladder");
    if (container) {
      container.innerHTML =
        '<div class="empty">' +
        (error instanceof api.Unauthorized
          ? "capture is protected — unlock first"
          : "message capture is not enabled on this node") +
        "</div>";
    }
    return;
  }
  const container = $("call-ladder");
  if (container) container.innerHTML = ladderMarkup(captured);
}

export function bind() {
  $("call-q").addEventListener("input", (event) => {
    query = event.target.value.toLowerCase().trim();
    draw();
  });
  $("call-refresh").addEventListener("click", load);
  $("call-rows").addEventListener("click", (event) => {
    const tr = event.target.closest("[data-call]");
    if (!tr) return;
    const call = cache.find((entry) => entry.id === tr.getAttribute("data-call"));
    if (!call) return;
    openDrawer(
      "Call " + call.call_id,
      detail(call) + '<div id="call-ladder"><div class="empty">loading signalling…</div></div>',
    );
    appendLadder(call.call_id);
  });

  // Expanding one message shows the raw text it was rendered from.
  document.addEventListener("click", (event) => {
    const row = event.target.closest("[data-msg]");
    if (!row) return;
    const raw = $("msgraw-" + row.getAttribute("data-msg"));
    if (raw) raw.hidden = !raw.hidden;
  });
}

export function markup() {
  return `
    <div class="toolbar">
      <label class="search">
        <svg viewBox="0 0 24 24" stroke-width="1.8"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4-4"/></svg>
        <input id="call-q" placeholder="Filter call-id, party, state…" autocomplete="off">
      </label>
      <span class="grow"></span>
      <span class="count-pill"><b id="call-count">0</b> shown</span>
      <button class="iconbtn" id="call-refresh" title="Refresh">
        <svg viewBox="0 0 24 24" stroke-width="1.8"><path d="M20 11a8 8 0 10-2 5.3M20 5v6h-6"/></svg>
      </button>
    </div>
    <div class="card"><div class="tblscroll"><table class="tbl">
      <thead><tr>
        <th>Call-ID</th><th>State</th><th class="num">Duration</th>
        <th>Caller</th><th>Callee</th><th>Branches</th><th>Flags</th>
      </tr></thead>
      <tbody id="call-rows"><tr><td colspan="7" class="empty">loading…</td></tr></tbody>
    </table></div></div>
    <div class="sectlabel">Click a row for legs, branches, transfer and carrier detail</div>
  `;
}
