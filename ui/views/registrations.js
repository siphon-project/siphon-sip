// Registrations — the registrar's live bindings.
//
// Adds the fields that answer "why can't I reach this subscriber": the
// transport and source the REGISTER arrived on, whether the contact is behind
// NAT, which node accepted it, and whether it is still pending an IMS SAR.

import { $, html, text, esc, transportChip } from "../lib/dom.js";
import { count, elapsed, isAbsent } from "../lib/format.js";
import { fact } from "../lib/widgets.js";
import * as api from "../lib/api.js";
import { openDrawer } from "../drawer.js";

let cache = [];
let query = "";
let unlocked = false;

export function setUnlocked(value) {
  unlocked = value;
}

function expiryColor(seconds) {
  return seconds > 300 ? "var(--up)" : seconds > 120 ? "var(--warn)" : "var(--crit)";
}

function expiryCell(contact) {
  const remaining = contact.expires_remaining || 0;
  // Scale the bar against the binding's own granted lifetime, not a fixed
  // constant — a 120 s registration was previously drawn as permanently
  // near-empty against a hardcoded 600 s.
  const granted = contact.expires_secs || 600;
  const percent = Math.max(4, Math.min(100, Math.round((remaining / granted) * 100)));
  return (
    '<span class="exp"><span class="bar"><i style="width:' +
    percent +
    "%;background:" +
    expiryColor(remaining) +
    '"></i></span>' +
    remaining +
    "s</span>"
  );
}

function row(contact, withAction) {
  const flags = [];
  if (contact.nated) flags.push('<span class="spill warn" title="contact URI differs from the REGISTER source">nat</span>');
  if (contact.pending) flags.push('<span class="spill warn" title="awaiting Cx SAR confirmation">pending</span>');
  if (contact.path_depth > 0) flags.push('<span class="spill info" title="RFC 3327 Path set">path ' + contact.path_depth + "</span>");
  if (contact.is_local === false) {
    flags.push('<span class="spill" title="accepted by another siphon instance">' + esc(contact.node || "remote") + "</span>");
  }

  return (
    '<tr class="rowlink" data-aor="' +
    esc(contact.aor) +
    '"><td class="aor">' +
    esc(contact.aor) +
    '</td><td class="contact">' +
    esc(contact.uri) +
    "</td><td>" +
    transportChip(contact.transport) +
    '</td><td class="contact">' +
    esc(contact.source_addr || "—") +
    '</td><td class="q">' +
    (contact.q != null ? contact.q : "") +
    "</td><td>" +
    expiryCell(contact) +
    "</td><td>" +
    (flags.join(" ") || '<span class="q">—</span>') +
    "</td>" +
    (withAction
      ? '<td><button class="rowbtn' +
        (unlocked ? " armed" : "") +
        '" data-unreg="' +
        esc(contact.aor) +
        '">unreg</button></td>'
      : "") +
    "</tr>"
  );
}

function detail(contact) {
  return (
    '<div class="facts">' +
    fact("aor", contact.aor) +
    fact("contact", contact.uri) +
    fact("transport", contact.transport || "—") +
    fact("source", contact.source_addr || "—") +
    fact("behind nat", contact.nated ? "yes" : "no") +
    fact("expires in", elapsed(contact.expires_remaining)) +
    fact("granted for", contact.expires_secs + "s") +
    fact("q-value", contact.q) +
    fact("instance-id", contact.instance_id || "—") +
    fact("reg-id", isAbsent(contact.reg_id) ? "—" : contact.reg_id) +
    fact("path depth", contact.path_depth) +
    fact("ims pending", contact.pending ? "yes" : "no") +
    fact("accepted by", contact.node || "—") +
    fact("local binding", contact.is_local ? "yes" : "no") +
    fact("call-id", contact.call_id) +
    fact("cseq", contact.cseq) +
    "</div>"
  );
}

export async function load() {
  try {
    cache = await api.registrations();
  } catch (error) {
    html(
      "reg-rows",
      '<tr><td colspan="8" class="empty">' +
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
    (contact) =>
      !query || [contact.aor, contact.uri, contact.source_addr].join(" ").toLowerCase().includes(query),
  );
  text("reg-count", filtered.length);
  text("nav-regs", cache.length || "");
  html(
    "reg-rows",
    filtered.length
      ? filtered.map((contact) => row(contact, true)).join("")
      : '<tr><td colspan="8" class="empty">no registrations</td></tr>',
  );
}

/** The five most recent bindings, for the overview preview. */
export function preview() {
  return cache.slice(0, 5);
}

export function bind(onAction) {
  $("reg-q").addEventListener("input", (event) => {
    query = event.target.value.toLowerCase().trim();
    draw();
  });
  $("reg-refresh").addEventListener("click", load);
  $("reg-rows").addEventListener("click", (event) => {
    const button = event.target.closest("[data-unreg]");
    if (button) {
      event.stopPropagation();
      onAction(button.getAttribute("data-unreg"));
      return;
    }
    const tr = event.target.closest("[data-aor]");
    if (!tr) return;
    const contact = cache.find((entry) => entry.aor === tr.getAttribute("data-aor"));
    if (contact) openDrawer(contact.aor, detail(contact));
  });
}

export function refreshArmed() {
  document.querySelectorAll("#reg-rows .rowbtn").forEach((button) => button.classList.toggle("armed", unlocked));
}

export function markup() {
  return `
    <div class="toolbar">
      <label class="search">
        <svg viewBox="0 0 24 24" stroke-width="1.8"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4-4"/></svg>
        <input id="reg-q" placeholder="Filter AoR, contact or source…" autocomplete="off">
      </label>
      <span class="grow"></span>
      <span class="count-pill"><b id="reg-count">0</b> shown</span>
      <button class="iconbtn" id="reg-refresh" title="Refresh">
        <svg viewBox="0 0 24 24" stroke-width="1.8"><path d="M20 11a8 8 0 10-2 5.3M20 5v6h-6"/></svg>
      </button>
    </div>
    <div class="card"><div class="tblscroll"><table class="tbl">
      <thead><tr>
        <th>AoR</th><th>Contact</th><th>Transport</th><th>Source</th>
        <th>Q</th><th>Expires</th><th>Flags</th><th></th>
      </tr></thead>
      <tbody id="reg-rows"><tr><td colspan="8" class="empty">loading…</td></tr></tbody>
    </table></div></div>
  `;
}
