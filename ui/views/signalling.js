// Signalling — Diameter and the SIP transport layer.
//
// Diameter previously showed one number ("1 peer connected") while per-command
// totals, per-error-kind totals and latency histograms sat unread in the
// registry. Command codes name the interface, so the breakdown is also the
// answer to "is my Cx working but my Rf not".
//
// The page now answers four questions rather than one, because "peers: 1,
// requests: 640" said nothing about whether any of it was working:
//
//   which peer   — per-peer up/down, since a count cannot say whether it is the
//                  HSS or the OCS that went away
//   which point  — requests grouped by 3GPP reference point
//   which answer — Result-Code breakdown. The error counter beside it only ever
//                  counted *transport* failures, so an OCS answering every CCR
//                  with 4012 read as zero errors, on a card that also showed
//                  the CCRs going out
//   how slow     — the round-trip histogram, collected since the metric was
//                  added and never once rendered

import { $, html, esc } from "../lib/dom.js";
import { notConfigured } from "../lib/dom.js";
import { count, isAbsent, latency, sum } from "../lib/format.js";
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

/**
 * Colour for a Result-Code label, by its RFC 6733 §7.1 class.
 *
 * Labels are either a bare code ("4012"), a class bucket ("5xxx_other"), the
 * 3GPP experimental namespace ("exp:5001"), or "none". The leading digit after
 * any `exp:` prefix is the class in every one of those shapes.
 */
function resultCodeColor(label) {
  const digit = String(label).replace(/^exp:/, "").charAt(0);
  if (digit === "2") return "var(--up)";
  if (digit === "1") return "var(--faint)";
  if (digit === "3" || digit === "4") return "var(--warn)";
  if (digit === "5") return "var(--crit)";
  return "var(--faint)";
}

/** Answers that are not 2xxx — the peer replied, and refused. */
function failedAnswers(answers) {
  return Object.entries(answers || {})
    .filter(([label]) => {
      const digit = String(label).replace(/^exp:/, "").charAt(0);
      return digit === "3" || digit === "4" || digit === "5";
    })
    .reduce((total, [, value]) => total + (value || 0), 0);
}

/**
 * Result codes as a bar list, each row coloured by its class.
 *
 * `barList` paints one colour for the whole list, so this renders per-class
 * sub-lists in class order. Success first, then the failures in ascending
 * severity — the eye should land on 2xxx being the tall one, and on anything
 * red immediately after.
 */
function resultCodeBars(answers) {
  const entries = Object.entries(answers || {}).filter(([, value]) => value > 0);
  if (!entries.length) return '<div class="empty">no answers yet</div>';

  const classOf = (label) => {
    const digit = String(label).replace(/^exp:/, "").charAt(0);
    return "12345".includes(digit) ? digit : "0";
  };
  return ["2", "1", "3", "4", "5", "0"]
    .map((cls) => {
      const group = entries.filter(([label]) => classOf(label) === cls);
      if (!group.length) return "";
      return barList(Object.fromEntries(group), { color: resultCodeColor(cls + "000") });
    })
    .join("");
}

/** Per-peer connection state, mirroring the per-instance media health card. */
function peerRows(peers) {
  const entries = Object.entries(peers || {});
  if (!entries.length) {
    return '<div class="empty">no Diameter peers configured</div>';
  }
  return entries
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([peer, up]) =>
      metaLine(peer, up ? "up" : "down", { color: up ? "var(--up)" : "var(--crit)" }),
    )
    .join("");
}

/**
 * Round-trip latency per command: mean, and p95 when it is bounded.
 *
 * p95 is absent when the 95th sample landed in the `+Inf` bucket, where the
 * histogram has no upper edge to interpolate against. Rendering it as an em
 * dash says "off the top of the scale", which is the honest reading and the one
 * worth alerting on — a number invented there would understate it.
 */
function latencyRows(byCommand) {
  const entries = Object.entries(byCommand || {});
  if (!entries.length) return '<div class="empty">no answered requests yet</div>';
  return entries
    .sort(([, a], [, b]) => (b.mean || 0) - (a.mean || 0))
    .map(([command, stats]) => {
      const p95 = isAbsent(stats.p95) ? "p95 over scale" : "p95 " + latency(stats.p95);
      return metaLine(command, latency(stats.mean) + "  ·  " + p95, {
        color: isAbsent(stats.p95) ? "var(--warn)" : undefined,
      });
    })
    .join("");
}

export function render(snapshot) {
  const diameter = snapshot.diameter;
  const sip = snapshot.sip || {};

  // The dependent cards only mean anything alongside a configured Diameter
  // stack, so they are hidden rather than left as empty boxes — an empty card
  // reads as "no data", which is a different claim.
  const dependent = [
    $("sig-peers-card"),
    $("sig-commands-card"),
    $("sig-answers-card"),
    $("sig-errors-card"),
    $("sig-latency-card"),
  ];
  dependent.forEach((card) => card && (card.hidden = isAbsent(diameter)));

  // The inbound (server / DRA role) card is hidden unless this node has
  // actually served a request. On a pure client — a P-CSCF talking to an HSS
  // and nothing else — an empty inbound card is noise, not information.
  const servedAny = !isAbsent(diameter) && sum(diameter.inbound_requests_by_command) > 0;
  const inboundCard = $("sig-inbound-card");
  if (inboundCard) inboundCard.hidden = !servedAny;

  if (isAbsent(diameter)) {
    html("sig-diameter", notConfigured("Diameter", "diameter"));
  } else {
    const peers = diameter.peers_connected || 0;
    const commands = diameter.requests_by_command || {};
    const answers = diameter.answers_by_result_code || {};
    // The watchdog (RFC 6733 DWR/DWA) failing is the early warning that a peer
    // is about to drop, well before peers_connected moves.
    const watchdog = diameter.watchdog_failures || 0;
    const refused = failedAnswers(answers);
    const transportErrors = sum(diameter.errors_by_kind);
    html(
      "sig-diameter",
      [
        metaLine("Peers connected", peers, { color: peers > 0 ? "var(--up)" : "var(--crit)" }),
        metaLine("Requests total", count(sum(commands))),
        metaLine("Answers total", count(sum(answers))),
        // Two different failures, deliberately on two lines. A peer that cannot
        // be reached and a peer that answers "no" need different people woken
        // up, and folding them into one "errors" number is what hid the second
        // one entirely.
        metaLine("Refused answers (3xxx–5xxx)", count(refused), {
          color: refused > 0 ? "var(--crit)" : undefined,
        }),
        metaLine("Transport errors", count(transportErrors), {
          color: transportErrors > 0 ? "var(--warn)" : undefined,
        }),
        metaLine("Watchdog failures", count(watchdog), { color: watchdog > 0 ? "var(--warn)" : undefined }),
        '<div class="subhead" style="margin-top:12px">By reference point</div>',
        barList(byInterface(commands), { color: "var(--cyan)", empty: "no Diameter traffic yet" }),
      ].join(""),
    );
    html("sig-peers", peerRows(diameter.peers));
    html("sig-commands", barList(commands, { color: "var(--indigo)", empty: "no commands yet" }));
    html("sig-answers", resultCodeBars(answers));
    html(
      "sig-errors",
      barList(diameter.errors_by_kind, { color: "var(--crit)", empty: "no transport errors" }),
    );
    html("sig-latency", latencyRows(diameter.latency_by_command));

    if (servedAny) {
      const servedRefused = failedAnswers(diameter.inbound_answers_by_result_code);
      // 3002 here is siphon's own "no on_request handler matched" fallback, so
      // it points at a gap in the script rather than at the peer. Worth its own
      // line: the peer sees a rejection either way and nothing else records
      // that we are the one rejecting.
      const noHandler = (diameter.inbound_answers_by_result_code || {})["3002"] || 0;
      html(
        "sig-inbound",
        [
          metaLine("Requests served", count(sum(diameter.inbound_requests_by_command))),
          metaLine("Refused answers sent (3xxx–5xxx)", count(servedRefused), {
            color: servedRefused > 0 ? "var(--warn)" : undefined,
          }),
          noHandler > 0
            ? metaLine("Rejected — no handler matched (3002)", count(noHandler), {
                color: "var(--crit)",
              })
            : "",
          '<div class="subhead" style="margin-top:12px">By command</div>',
          barList(diameter.inbound_requests_by_command, { color: "var(--cyan)" }),
          '<div class="subhead" style="margin-top:12px">Answers sent</div>',
          resultCodeBars(diameter.inbound_answers_by_result_code),
          '<div class="subhead" style="margin-top:12px">Time to answer</div>',
          latencyRows(diameter.inbound_latency_by_command),
        ].join(""),
      );
    }
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
  // with Diameter rather than with the 5GC or with access security. They are
  // also independent of each other: a node commonly runs online charging with
  // no offline charging at all, and this card used to read Ro's state off Rf's
  // flag and declare online charging unconfigured on every one of them.
  const sessions = snapshot.sessions || {};
  const denials = sessions.ro_denials || {};
  const teardowns = sessions.ro_credit_teardowns || {};
  const deniedTotal = sum(denials);
  const tornDownTotal = sum(teardowns);
  html(
    "sig-charging",
    [
      isAbsent(sessions.rf)
        ? metaLine("Rf — offline (ACR/ACA)", "not configured", { color: "var(--faint)" })
        : metaLine("Rf — offline (ACR/ACA)", count(sessions.rf) + " sessions"),
      isAbsent(sessions.ro)
        ? metaLine("Ro — online (CCR/CCA)", "not configured", { color: "var(--faint)" })
        : metaLine("Ro — online (CCR/CCA)", count(sessions.ro) + " sessions"),
      // A live session count says the OCS is answering; it cannot say what it
      // is answering. A denial is a call that never happened and a teardown is
      // one cut off mid-way, and neither moves any other counter siphon keeps.
      isAbsent(sessions.ro)
        ? ""
        : [
            metaLine("Calls refused credit", count(deniedTotal), {
              color: deniedTotal > 0 ? "var(--crit)" : undefined,
            }),
            deniedTotal > 0
              ? barList(denials, { color: "var(--crit)" })
              : "",
            metaLine("Torn down on credit", count(tornDownTotal), {
              color: tornDownTotal > 0 ? "var(--warn)" : undefined,
            }),
            tornDownTotal > 0 ? barList(teardowns, { color: "var(--warn)" }) : "",
            // Credit ran out and siphon had nothing wired to act on it, so the
            // call is still up and unpaid. Worth its own line, not a row in a
            // breakdown nobody scrolls to.
            teardowns.no_teardown_hook > 0
              ? metaLine("Unenforced (no teardown hook)", count(teardowns.no_teardown_hook), {
                  color: "var(--crit)",
                })
              : "",
          ].join(""),
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
      <div class="card" id="sig-peers-card">
        <div class="panelhead"><span class="t">Peers</span><span class="count-pill">RFC 6733</span></div>
        <div class="panelbody" id="sig-peers"></div>
      </div>
      <div class="card" id="sig-commands-card">
        <div class="panelhead"><span class="t">By command</span><span class="count-pill">requests</span></div>
        <div class="panelbody" id="sig-commands"></div>
      </div>
      <!-- The card the dashboard was missing: what the peers actually said.
           "Errors" below counts transport failures only, so a peer refusing
           every request sat at zero there. -->
      <div class="card" id="sig-answers-card">
        <div class="panelhead"><span class="t">Answers by Result-Code</span><span class="count-pill">RFC 6733 §7.1</span></div>
        <div class="panelbody" id="sig-answers"></div>
      </div>
      <div class="card" id="sig-errors-card">
        <div class="panelhead"><span class="t">Transport errors</span><span class="count-pill">by kind</span></div>
        <div class="panelbody" id="sig-errors"></div>
      </div>
      <div class="card" id="sig-latency-card">
        <div class="panelhead"><span class="t">Round-trip latency</span><span class="count-pill">mean · p95</span></div>
        <div class="panelbody" id="sig-latency"></div>
      </div>
      <!-- Server / DRA role. Everything above is what this node SENDS and what
           came back; this is what it SERVES. Hidden until the node has actually
           answered something, so a pure client carries no empty card. -->
      <div class="card" id="sig-inbound-card">
        <div class="panelhead"><span class="t">Inbound (served)</span><span class="count-pill">server role</span></div>
        <div class="panelbody" id="sig-inbound"></div>
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
