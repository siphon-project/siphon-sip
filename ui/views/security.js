// Security — what was rejected, and why.
//
// Adds the two counters that were live on real nodes and invisible here:
// handshake failures (a TLS/WS peer that never got as far as SIP) and
// connections refused by the per-source ceilings, broken down by reason.

import { $, html, text, esc } from "../lib/dom.js";
import { count } from "../lib/format.js";
import { barList, tile } from "../lib/widgets.js";
import * as api from "../lib/api.js";

let unlocked = false;

export function setUnlocked(value) {
  unlocked = value;
}

export function render(snapshot) {
  const counters = snapshot.counters || {};
  const security = snapshot.security || {};

  html(
    "sec-kpis",
    [
      tile("Banned now", count(security.banned_ips), "auto-ban active"),
      tile("Auth failures", count(counters.auth_failures_total), "no credentials offered"),
      tile("Credential fails", count(counters.credential_failures_total), "bad digest response"),
      tile("Scanner blocked", count(counters.scanner_blocked_total), "bad UA / probe"),
      tile("Rate limited", count(counters.rate_limited_total), "per-source window"),
      tile("Malformed", count(counters.malformed_messages_total), "sanity-check fail"),
    ].join(""),
  );

  html(
    "sec-transport",
    [
      // A peer failing the TLS/WS handshake never reaches the SIP layer, so it
      // appears in none of the counters above.
      '<div class="metaline"><span>Handshake failures</span><b style="color:' +
        ((security.handshake_failures || 0) > 0 ? "var(--warn)" : "var(--text)") +
        '">' +
        count(security.handshake_failures) +
        "</b></div>",
      '<div class="metaline"><span>Handshakes in flight</span><b>' +
        count((snapshot.sip || {}).handshakes_in_flight) +
        "</b></div>",
      '<div class="metaline"><span>Requests without branch</span><b>' +
        count(security.requests_without_branch) +
        "</b></div>",
      '<div class="metaline"><span>UDP at buffer limit</span><b>' +
        count(security.udp_at_buffer_limit) +
        "</b></div>",
      '<div class="metaline"><span>Auth backend errors</span><b>' +
        count(security.auth_backend_errors) +
        "</b></div>",
      '<div class="metaline"><span>Script handler errors</span><b style="color:' +
        ((counters.script_errors_total || 0) > 0 ? "var(--warn)" : "var(--text)") +
        '">' +
        count(counters.script_errors_total) +
        "</b></div>",
    ].join(""),
  );

  html(
    "sec-refused",
    barList(security.connections_refused, {
      color: "var(--crit)",
      empty: "no connections refused",
    }),
  );

  const firewallDropped = security.firewall_commands_dropped || 0;
  const firewallFailed = security.firewall_command_failures || 0;
  html(
    "sec-firewall",
    firewallDropped + firewallFailed === 0
      ? '<div class="empty">kernel firewall healthy</div>'
      : '<div class="metaline"><span>Commands dropped</span><b style="color:var(--warn)">' +
          count(firewallDropped) +
          '</b></div><div class="metaline"><span>Command failures</span><b style="color:var(--crit)">' +
          count(firewallFailed) +
          "</b></div>",
  );
}

export async function load() {
  let entries;
  try {
    entries = await api.bans();
  } catch (error) {
    html(
      "ban-rows",
      '<tr><td colspan="3" class="empty">' +
        (error instanceof api.Unauthorized ? "read access is protected — unlock first" : "failed to load") +
        "</td></tr>",
    );
    return;
  }
  text("ban-count", entries.length);
  text("nav-bans", entries.length || "");
  html(
    "ban-rows",
    entries.length
      ? entries
          .map((ban) => {
            const remaining = ban.expires_remaining || 0;
            return (
              '<tr><td class="aor">' +
              esc(ban.ip) +
              '</td><td><span class="exp"><span class="bar"><i style="width:' +
              Math.min(100, Math.round((remaining / 900) * 100)) +
              '%;background:var(--warn)"></i></span>' +
              Math.floor(remaining / 60) +
              "m " +
              (remaining % 60) +
              's</span></td><td><button class="rowbtn' +
              (unlocked ? " armed" : "") +
              '" data-lift="' +
              esc(ban.ip) +
              '">lift</button></td></tr>'
            );
          })
          .join("")
      : '<tr><td colspan="3" class="empty">no active bans</td></tr>',
  );
}

export function bind(onLift) {
  $("ban-rows").addEventListener("click", (event) => {
    const button = event.target.closest("[data-lift]");
    if (button) onLift(button.getAttribute("data-lift"));
  });
}

export function markup() {
  return `
    <div class="sectlabel">Rejected at the SIP layer · since restart</div>
    <section class="kpis" id="sec-kpis"></section>

    <section class="grid2">
      <div class="card">
        <div class="panelhead"><span class="t">Active bans</span><span class="count-pill"><b id="ban-count">0</b> sources</span></div>
        <div class="tblscroll"><table class="tbl">
          <thead><tr><th>Source IP</th><th>Expires</th><th></th></tr></thead>
          <tbody id="ban-rows"><tr><td colspan="3" class="empty">loading…</td></tr></tbody>
        </table></div>
      </div>
      <div class="card">
        <div class="panelhead"><span class="t">Transport &amp; script</span><span class="count-pill">below SIP</span></div>
        <div class="panelbody" id="sec-transport"></div>
      </div>
    </section>

    <section class="grid2">
      <div class="card">
        <div class="panelhead"><span class="t">Connections refused</span><span class="count-pill">by reason</span></div>
        <div class="panelbody" id="sec-refused"></div>
      </div>
      <div class="card">
        <div class="panelhead"><span class="t">Kernel firewall</span></div>
        <div class="panelbody" id="sec-firewall"></div>
      </div>
    </section>
  `;
}
