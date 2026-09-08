// Cost — what the traffic on this node is costing, from the LCR carrier rates.
//
// An estimate, and labelled as one everywhere it appears. The carrier's own
// rating is authoritative and will differ (connection fees, mid-call rate
// changes, their rounding). This is for trending, for spotting a carrier that
// is quietly ten times its neighbour, and for noticing a burn rate that should
// not be that high at 3am — never for billing.

import { html, text, esc, table, notConfigured } from "../lib/dom.js";
import { isAbsent } from "../lib/format.js";
import { metaLine } from "../lib/widgets.js";
import * as api from "../lib/api.js";

/** Currency amounts, at the precision wholesale rates actually carry. */
function money(value, currency) {
  if (value === null || value === undefined) return "—";
  const digits = Math.abs(value) < 1 ? 4 : 2;
  return value.toFixed(digits) + (currency ? " " + currency : "");
}

export function render(snapshot) {
  const spend = snapshot.spend;

  if (isAbsent(spend)) {
    // No B2BUA on this node: rating rides on the LCR route a B2BUA call
    // carries, and a proxy makes no carrier decision to price.
    html(
      "cost-body",
      notConfigured("Call rating", "b2bua") +
        '<div class="panelbody q">Rating follows the carrier chosen by least-cost routing, ' +
        "which is a B2BUA path — a proxy forwards the dialog and picks no carrier.</div>",
    );
    html("cost-carriers", "");
    return;
  }

  const perMinute = spend.per_minute || {};
  const currencies = Object.keys(perMinute).sort();

  html(
    "cost-body",
    currencies.length
      ? currencies
          .map((currency) =>
            metaLine("Burn rate", money(perMinute[currency], currency) + " / min", {
              color: "var(--warn)",
            }),
          )
          .join("")
      : metaLine("Burn rate", "no rated calls in progress", { color: "var(--faint)" }),
  );

  // One row per carrier+currency. Never a single total: adding EUR to USD
  // produces a number that means nothing.
  const rows = (spend.cost_total || [])
    .slice()
    .sort((a, b) => (b.value || 0) - (a.value || 0))
    .map(
      (row) =>
        '<tr><td class="aor">' +
        esc(row.carrier || "—") +
        '</td><td class="q">' +
        esc(row.currency || "—") +
        '</td><td class="num">' +
        esc(money(row.value, row.currency)) +
        "</td></tr>",
    );

  html(
    "cost-carriers",
    table(["Carrier", "Currency", { label: "Spend since boot" }], rows, "no calls rated yet"),
  );
  text("cost-count", rows.length);
}

export async function load() {
  // The per-call breakdown comes from the same list the Calls view reads.
  let calls;
  try {
    calls = await api.calls();
  } catch (error) {
    html(
      "cost-calls",
      '<div class="empty">' +
        (error instanceof api.Unauthorized ? "read access is protected — unlock first" : "failed to load") +
        "</div>",
    );
    return;
  }

  const rated = calls.filter((call) => call.rating);
  html(
    "cost-calls",
    table(
      ["Call-ID", "Carrier", "Rate", "Billed", { label: "Cost" }],
      rated.map(
        (call) =>
          '<tr><td class="contact">' +
          esc(call.call_id) +
          '</td><td class="aor">' +
          esc(call.rating.carrier || "—") +
          '</td><td class="q">' +
          esc(money(call.rating.rate_per_minute, call.rating.currency)) +
          "/min</td>" +
          '<td class="q">' +
          (call.rating.billed_secs === null || call.rating.billed_secs === undefined
            ? "not answered"
            : esc(call.rating.billed_secs) + "s") +
          '</td><td class="num">' +
          esc(money(call.rating.cost, call.rating.currency)) +
          "</td></tr>",
      ),
      calls.length ? "no call in progress carries a carrier rate" : "no calls in progress",
    ),
  );
}

export function markup() {
  return `
    <div class="sectlabel">Cost</div>
    <section class="grid2">
      <div class="card">
        <div class="panelhead"><span class="t">Right now</span></div>
        <div class="panelbody" id="cost-body"></div>
      </div>
      <div class="card">
        <div class="panelhead">
          <span class="t">Per carrier</span>
          <span class="count-pill"><b id="cost-count">0</b> rated</span>
        </div>
        <div id="cost-carriers"></div>
      </div>
    </section>

    <div class="sectlabel">Calls in progress</div>
    <section class="card">
      <div id="cost-calls"></div>
      <div class="panelbody q">
        Estimated from the rate the routing API returned for the carrier that won,
        applying its billing increment and minimum duration. The carrier's own
        rating is authoritative and will differ — this is for trending and alarms,
        not for billing.
      </div>
    </section>
  `;
}
