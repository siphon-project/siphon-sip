// Overview — live operational state, not a Grafana imitation.
//
// The previous version spent its three largest panels on sparklines of counters
// that were never incremented, and gave one thin table to the listable state
// only this dashboard can show. Rates and history belong in Prometheus; what
// belongs here is what is happening on this node right now.

import { $, html, text, esc } from "../lib/dom.js";
import { count, mb, toMB, isAbsent, duration, rate, sum } from "../lib/format.js";
import { barList, metaLine, tile } from "../lib/widgets.js";
import { Chart } from "../lib/chart.js";

const TRANSPORT_COLORS = {
  udp: "var(--sky)",
  tcp: "var(--indigo)",
  tls: "var(--cyan)",
  ws: "var(--violet)",
  wss: "var(--violet)",
  sctp: "var(--warn)",
};

let charts = null;
let previous = null;

function ensureCharts() {
  if (charts) return charts;
  charts = {
    requests: new Chart("c-rps", "#22d3ee", {
      key: "requests_per_sec",
      format: (v) => count(v) + " req/s",
    }),
    calls: new Chart("c-calls", "#818cf8", { key: "calls_active" }),
    memory: new Chart("c-mem", "#0ea5e9", { key: "memory_mb", format: (v) => mb(v * 1048576) + " MB" }),
  };
  return charts;
}

export function resize() {
  if (charts) Object.values(charts).forEach((chart) => chart.resize());
}

export function redraw() {
  if (charts) Object.values(charts).forEach((chart) => chart.draw());
}

export function render(snapshot) {
  const sip = snapshot.sip || {};
  const traffic = snapshot.traffic || {};
  const memory = snapshot.memory || {};
  const pyexec = snapshot.pyexec || {};

  // Rates are derived from the cumulative totals across polls. Prometheus does
  // this properly with rate(); here it only has to be good enough to watch.
  const now = Date.now();
  const requestsIn = sum(traffic.requests_in);
  const requestsOut = sum(traffic.requests_out);
  const responsesIn = sum(traffic.responses_in);
  const responsesOut = sum(traffic.responses_out);

  let requestRate = 0;
  let responseRate = 0;
  if (previous && now > previous.at) {
    const seconds = (now - previous.at) / 1000;
    requestRate = rate(requestsIn + requestsOut, previous.requests, seconds);
    responseRate = rate(responsesIn + responsesOut, previous.responses, seconds);
  }
  previous = { at: now, requests: requestsIn + requestsOut, responses: responsesIn + responsesOut };

  const proxyDialogs = sip.proxy_dialog_sessions;
  const b2buaCalls = sip.b2bua_calls_active;

  html(
    "ov-kpis",
    [
      tile("Calls", count(b2buaCalls), "B2BUA call actors", { hero: true }),
      tile("Proxy dialogs", count(proxyDialogs), "answered, within ACK window", { hero: true }),
      tile("SIP messages / s", count(requestRate + responseRate), count(requestRate) + " req/s in+out"),
      tile("Transactions", count(sip.transactions_active), "RFC 3261 §17 state machines"),
      tile("Registrations", count(snapshot.registrations_active), "active bindings"),
      tile("Memory", mb(memory.allocated), "jemalloc live bytes", { unit: "MB" }),
    ].join(""),
  );

  // Charts. `calls` is the honest total: proxy dialogs plus B2BUA call actors.
  const active = (proxyDialogs || 0) + (b2buaCalls || 0);
  const memoryMB = toMB(memory.allocated);
  const chart = ensureCharts();
  chart.requests.push(requestRate + responseRate);
  chart.calls.push(active);
  chart.memory.push(memoryMB);
  text("n-rps", count(requestRate + responseRate));
  text("n-calls", count(active));
  text("n-mem", mb(memory.allocated));

  // Method / class mix. This is the part Prometheus cannot show at a glance and
  // the part that was entirely missing before.
  html("ov-methods", barList(traffic.requests_in, { color: "var(--cyan)", empty: "no requests received yet" }));
  html(
    "ov-classes",
    barList(traffic.responses_out, {
      color: "var(--indigo)",
      keep: ["2xx", "4xx", "5xx"],
      empty: "no responses sent yet",
    }),
  );

  renderConnections(sip.connections);
  renderHealth(snapshot);
}

function renderConnections(connections) {
  const entries = Object.entries(connections || {});
  const total = entries.reduce((acc, [, value]) => acc + value, 0);

  let stack = "";
  let legend = "";
  entries.sort().forEach(([transport, value]) => {
    const color = TRANSPORT_COLORS[transport.toLowerCase()] || "var(--muted)";
    const percent = total > 0 ? (value / total) * 100 : 0;
    if (percent > 0) stack += '<i style="width:' + percent + "%;background:" + color + '"></i>';
    legend +=
      '<div class="legrow"><span class="sw" style="background:' +
      color +
      '"></span><span class="n">' +
      esc(transport.toUpperCase()) +
      '</span><span class="val">' +
      count(value) +
      "</span></div>";
  });

  // UDP is connectionless, so it has no series here at all. Saying so is the
  // point — an empty bar previously read as "no traffic".
  legend +=
    '<div class="legrow"><span class="sw" style="background:var(--border)"></span>' +
    '<span class="n" title="UDP is connectionless — there is no connection to count">UDP</span>' +
    '<span class="val" style="color:var(--faint)">n/a</span></div>';

  html("ov-conn-stack", stack || '<i style="width:100%;background:var(--border)"></i>');
  html("ov-conn-legend", legend);
}

function renderHealth(snapshot) {
  const gateways = snapshot.gateways;
  const rtpengine = snapshot.rtpengine;
  const diameter = snapshot.diameter;
  const control = snapshot.control;
  const security = snapshot.security || {};
  const sip = snapshot.sip || {};

  const lines = [];

  if (!isAbsent(gateways) && (gateways.groups_total || 0) > 0) {
    const issues = gateways.groups_with_issues || 0;
    lines.push(
      metaLine(
        "Gateway groups",
        issues > 0 ? gateways.groups_total + " · " + issues + " with issues" : gateways.groups_total + " · all healthy",
        { color: issues > 0 ? "var(--warn)" : "var(--up)", goto: "gateways" },
      ),
    );
  }

  if (!isAbsent(rtpengine)) {
    const up = rtpengine.up || 0;
    const totalInstances = rtpengine.total || 0;
    lines.push(
      metaLine("Media engines", up + " / " + totalInstances + " up", {
        color: up < totalInstances ? "var(--warn)" : "var(--up)",
        goto: "media",
      }),
    );
  }

  if (!isAbsent(diameter)) {
    const peers = diameter.peers_connected || 0;
    lines.push(
      metaLine("Diameter peers", peers + " connected", {
        color: peers > 0 ? "var(--up)" : "var(--warn)",
        goto: "signalling",
      }),
    );
  }

  if (!isAbsent(control)) {
    const apps = Object.keys(control.connections || {}).length;
    lines.push(metaLine("Control apps", apps + " connected", { goto: "control" }));
  }

  const banned = security.banned_ips || 0;
  lines.push(
    metaLine("Banned sources", banned + " active", {
      color: banned > 0 ? "var(--warn)" : undefined,
      goto: "security",
    }),
  );

  const handshakeFailures = security.handshake_failures || 0;
  if (handshakeFailures > 0) {
    lines.push(metaLine("Handshake failures", count(handshakeFailures), { color: "var(--warn)", goto: "security" }));
  }

  lines.push(metaLine("Python pool", count(sip.uac_pending) + " UAC in flight"));

  html("ov-health", lines.join(""));
}

export function markup() {
  return `
    <div class="sectlabel">Live state · polled from /admin/metrics.json</div>
    <section class="kpis" id="ov-kpis"></section>

    <div class="sectlabel">Throughput &amp; resources</div>
    <section class="charts">
      <div class="card">
        <div class="head"><span class="t">SIP messages / sec</span>
          <span class="now"><b id="n-rps" style="color:var(--cyan)">—</b><span class="u">msg/s</span></span></div>
        <div class="chartwrap"><canvas id="c-rps"></canvas></div>
      </div>
      <div class="card">
        <div class="head"><span class="t">Active calls &amp; dialogs</span>
          <span class="now"><b id="n-calls" style="color:var(--violet)">—</b></span></div>
        <div class="chartwrap"><canvas id="c-calls"></canvas></div>
      </div>
      <div class="card">
        <div class="head"><span class="t">Memory allocated</span>
          <span class="now"><b id="n-mem" style="color:var(--sky)">—</b><span class="u">MB</span></span></div>
        <div class="chartwrap"><canvas id="c-mem"></canvas></div>
      </div>
    </section>

    <div class="sectlabel">Traffic mix</div>
    <section class="charts two">
      <div class="card">
        <div class="panelhead"><span class="t">Requests received</span><span class="count-pill">by method</span></div>
        <div class="panelbody" id="ov-methods"></div>
      </div>
      <div class="card">
        <div class="panelhead"><span class="t">Responses sent</span><span class="count-pill">by class</span></div>
        <div class="panelbody" id="ov-classes"></div>
      </div>
    </section>

    <section class="lower">
      <div class="card">
        <div class="panelhead"><span class="t">Inbound connections</span><span class="count-pill">by transport</span></div>
        <div class="panelbody">
          <div class="stack" id="ov-conn-stack" role="img" aria-label="Connection mix by transport"></div>
          <div class="legend" id="ov-conn-legend"></div>
        </div>
      </div>
      <div class="card">
        <div class="panelhead"><span class="t">Subsystem health</span></div>
        <div class="panelbody" id="ov-health"></div>
      </div>
    </section>
  `;
}
