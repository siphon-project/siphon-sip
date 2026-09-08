// Control plane — connected external applications (ARI/ESL-class).
//
// Entirely absent from the previous dashboard, including on nodes where an app
// was connected and driving calls. Dropped events matter most here: a slow
// consumer silently loses events while the calls themselves carry on.

import { html, esc, table, notConfigured } from "../lib/dom.js";
import { count, isAbsent } from "../lib/format.js";
import { metaLine } from "../lib/widgets.js";

export function render(snapshot) {
  const control = snapshot.control;

  if (isAbsent(control)) {
    html("control-body", notConfigured("The external control plane", "control"));
    html("control-apps", "");
    return;
  }

  const connections = control.connections || {};
  const calls = control.controlled_calls || {};
  const commands = control.commands_total || {};
  const dropped = control.events_dropped_total || {};

  const apps = [...new Set([...Object.keys(connections), ...Object.keys(calls), ...Object.keys(commands)])].sort();

  const totalDropped = Object.values(dropped).reduce((total, value) => total + value, 0);
  html(
    "control-body",
    [
      metaLine("Apps connected", count(apps.filter((app) => (connections[app] || 0) > 0).length)),
      metaLine("Controlled calls", count(Object.values(calls).reduce((t, v) => t + v, 0))),
      metaLine("Auth failures", count(control.auth_failures), {
        color: (control.auth_failures || 0) > 0 ? "var(--warn)" : undefined,
      }),
      // A non-zero here means an app's outbound queue overflowed and events were
      // discarded — the app's view of the calls it owns is now incomplete.
      metaLine("Events dropped", count(totalDropped), {
        color: totalDropped > 0 ? "var(--crit)" : undefined,
      }),
    ].join(""),
  );

  html(
    "control-apps",
    table(
      ["App", { label: "Connections" }, { label: "Calls" }, { label: "Commands" }, { label: "Dropped" }],
      apps.map((app) => {
        const appDropped = dropped[app] || 0;
        return (
          '<tr><td class="aor">' +
          esc(app) +
          '</td><td class="num">' +
          count(connections[app] || 0) +
          '</td><td class="num">' +
          count(calls[app] || 0) +
          '</td><td class="num">' +
          count(commands[app] || 0) +
          '</td><td class="num"' +
          (appDropped > 0 ? ' style="color:var(--crit)"' : "") +
          ">" +
          count(appDropped) +
          "</td></tr>"
        );
      }),
      "no control apps have connected",
    ),
  );
}

export function markup() {
  return `
    <div class="sectlabel">External control plane</div>
    <section class="grid2">
      <div class="card">
        <div class="panelhead"><span class="t">Control plane</span></div>
        <div class="panelbody" id="control-body"></div>
      </div>
      <div class="card">
        <div class="panelhead"><span class="t">Per app</span></div>
        <div id="control-apps"></div>
      </div>
    </section>
  `;
}
