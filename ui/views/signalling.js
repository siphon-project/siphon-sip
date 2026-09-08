// Signalling — Diameter and the SIP transport layer.
//
// Diameter previously showed one number ("1 peer connected") while per-command
// totals, per-error-kind totals and latency histograms sat unread in the
// registry. Command codes name the interface, so the breakdown is also the
// answer to "is my Cx working but my Rf not".

import { $, html, esc } from "../lib/dom.js";
import { notConfigured } from "../lib/dom.js";
import { count, isAbsent, sum } from "../lib/format.js";
import { barList, metaLine } from "../lib/widgets.js";

/**
 * Diameter command code → the 3GPP reference point it belongs to.
 *
 * Grouping by interface is what an operator reasons about: "Cx is fine, Ro is
 * failing" rather than a flat list of three-letter command names.
 */
const COMMAND_INTERFACE = {
  UAR: "Cx", UAA: "Cx", SAR: "Cx", SAA: "Cx", LIR: "Cx", LIA: "Cx", MAR: "Cx", MAA: "Cx",
  AAR: "Rx", AAA: "Rx", STR: "Rx", STA: "Rx", RAR: "Rx", RAA: "Rx", ASR: "Rx", ASA: "Rx",
  ACR: "Rf", ACA: "Rf",
  CCR: "Ro", CCA: "Ro",
  UDR: "Sh", UDA: "Sh", PUR: "Sh", PUA: "Sh", SNR: "Sh", SNA: "Sh", PNR: "Sh", PNA: "Sh",
  AIR: "S6a", AIA: "S6a", ULR: "S6a", ULA: "S6a", CLR: "S6a", CLA: "S6a",
  CER: "base", CEA: "base", DWR: "base", DWA: "base", DPR: "base", DPA: "base",
};

function byInterface(commands) {
  const grouped = {};
  Object.entries(commands || {}).forEach(([command, value]) => {
    const iface = COMMAND_INTERFACE[command] || "other";
    grouped[iface] = (grouped[iface] || 0) + value;
  });
  return grouped;
}

export function render(snapshot) {
  const diameter = snapshot.diameter;
  const sip = snapshot.sip || {};

  // The two per-command cards only mean anything alongside a configured
  // Diameter stack, so they are hidden rather than left as empty boxes — an
  // empty card reads as "no data", which is a different claim.
  const dependent = [$("sig-commands-card"), $("sig-errors-card")];
  dependent.forEach((card) => card && (card.hidden = isAbsent(diameter)));

  if (isAbsent(diameter)) {
    html("sig-diameter", notConfigured("Diameter", "diameter"));
  } else {
    const peers = diameter.peers_connected || 0;
    const commands = diameter.requests_by_command || {};
    // The watchdog (RFC 6733 DWR/DWA) failing is the early warning that a peer
    // is about to drop, well before peers_connected moves.
    const watchdog = diameter.watchdog_failures || 0;
    html(
      "sig-diameter",
      [
        metaLine("Peers connected", peers, { color: peers > 0 ? "var(--up)" : "var(--crit)" }),
        metaLine("Requests total", count(sum(commands))),
        metaLine("Errors total", count(sum(diameter.errors_by_kind)), {
          color: sum(diameter.errors_by_kind) > 0 ? "var(--warn)" : undefined,
        }),
        metaLine("Watchdog failures", count(watchdog), { color: watchdog > 0 ? "var(--warn)" : undefined }),
        '<div class="subhead" style="margin-top:12px">By reference point</div>',
        barList(byInterface(commands), { color: "var(--cyan)", empty: "no Diameter traffic yet" }),
      ].join(""),
    );
    html("sig-commands", barList(commands, { color: "var(--indigo)", empty: "no commands yet" }));
    html(
      "sig-errors",
      barList(diameter.errors_by_kind, { color: "var(--crit)", empty: "no Diameter errors" }),
    );
  }

  // SIP transport. UDP is stated as not-applicable rather than shown as zero.
  const connections = sip.connections || {};
  const rows = Object.entries(connections)
    .sort()
    .map(([transport, value]) =>
      metaLine(transport.toUpperCase(), count(value) + " connections"),
    );
  rows.push(metaLine("UDP", "connectionless", { color: "var(--faint)" }));
  rows.push(metaLine("Stream connections (total)", count(sip.stream_connections)));
  rows.push(metaLine("Handshakes in flight", count(sip.handshakes_in_flight)));
  rows.push(metaLine("UAC requests pending", count(sip.uac_pending)));
  rows.push(metaLine("SUBSCRIBE dialogs", count(sip.subscribe_dialogs)));
  rows.push(metaLine("CDR sessions in flight", count(sip.cdr_sessions)));
  html("sig-transport", rows.join(""));

  // Charging — Rf and Ro are Diameter reference points (TS 32.299), so they sit
  // with Diameter rather than with the 5GC or with access security.
  const sessions = snapshot.sessions || {};
  html(
    "sig-charging",
    [
      isAbsent(sessions.rf)
        ? metaLine("Rf — offline (ACR/ACA)", "not configured", { color: "var(--faint)" })
        : metaLine("Rf — offline (ACR/ACA)", count(sessions.rf) + " sessions"),
      isAbsent(sessions.ro)
        ? metaLine("Ro — online (CCR/CCA)", "not configured", { color: "var(--faint)" })
        : metaLine("Ro — online (CCR/CCA)", count(sessions.ro) + " sessions"),
    ].join(""),
  );

  // 5GC service-based interfaces. Nothing to do with the Gm access security
  // below it — HTTP/2 JSON to the PCF, not IPsec ESP to the UE.
  html(
    "sig-sbi",
    isAbsent(snapshot.sbi)
      ? notConfigured("5GC SBI", "sbi")
      : [
          metaLine("Npcf app sessions (N5)", count(snapshot.sbi.npcf_sessions_active)),
          metaLine("Policy authorization", "TS 29.514", { color: "var(--faint)" }),
        ].join(""),
  );

  // Gm access security — IPsec sec-agree to the UE (TS 33.203 / RFC 3329 over
  // SIP). A 4G IMS P-CSCF has this and no SBI at all, which is why the two are
  // no longer rendered in one card.
  html(
    "sig-access",
    isAbsent(snapshot.ipsec)
      ? notConfigured("IPsec sec-agree (Gm)", "ipsec")
      : [
          metaLine("IPsec SA pairs", count(snapshot.ipsec.sa_pairs)),
          metaLine("Mechanism", "ipsec-3gpp (TS 33.203)", { color: "var(--faint)" }),
        ].join(""),
  );

  html(
    "sig-li",
    isAbsent(sessions.li_remembered)
      ? notConfigured("Lawful intercept", "lawful_intercept")
      : [
          metaLine("Remembered sessions", count(sessions.li_remembered)),
          metaLine("Interfaces", "ETSI X1 / X2 / X3", { color: "var(--faint)" }),
        ].join(""),
  );
}

export function markup() {
  return `
    <div class="sectlabel">Diameter · 3GPP reference points</div>
    <!-- One flowing grid rather than fixed rows: the two per-command cards are
         hidden when Diameter is absent, and the rest close up behind them
         instead of leaving holes. -->
    <section class="cardgrid">
      <div class="card">
        <div class="panelhead"><span class="t">Diameter</span><span class="count-pill">Cx / Rx / Rf / Ro / Sh</span></div>
        <div class="panelbody" id="sig-diameter"></div>
      </div>
      <div class="card" id="sig-commands-card">
        <div class="panelhead"><span class="t">By command</span><span class="count-pill">requests</span></div>
        <div class="panelbody" id="sig-commands"></div>
      </div>
      <div class="card" id="sig-errors-card">
        <div class="panelhead"><span class="t">Diameter errors</span><span class="count-pill">by kind</span></div>
        <div class="panelbody" id="sig-errors"></div>
      </div>
      <div class="card">
        <div class="panelhead"><span class="t">Charging</span><span class="count-pill">Rf / Ro · TS 32.299</span></div>
        <div class="panelbody" id="sig-charging"></div>
      </div>
    </section>

    <!-- Deliberately separate sections. These are different reference points
         with different transports and different peers; the previous dashboard
         put IPsec SA pairs inside a "5GC · SBI" card, which is wrong on a 5G
         node and doubly wrong on a 4G IMS P-CSCF that has no SBI at all. -->
    <div class="sectlabel">5G core · service-based interfaces</div>
    <section class="cardgrid">
      <div class="card">
        <div class="panelhead"><span class="t">SBI</span><span class="count-pill">N5 / Npcf · HTTP2</span></div>
        <div class="panelbody" id="sig-sbi"></div>
      </div>
      <div class="card">
        <div class="panelhead"><span class="t">Access security</span><span class="count-pill">Gm · TS 33.203</span></div>
        <div class="panelbody" id="sig-access"></div>
      </div>
    </section>

    <div class="sectlabel">SIP transport &amp; interception</div>
    <section class="cardgrid">
      <div class="card">
        <div class="panelhead"><span class="t">Transport layer</span></div>
        <div class="panelbody" id="sig-transport"></div>
      </div>
      <div class="card">
        <div class="panelhead"><span class="t">Lawful intercept</span><span class="count-pill">ETSI TS 103 221</span></div>
        <div class="panelbody" id="sig-li"></div>
      </div>
    </section>
  `;
}
