// Media — the RTP engine set.
//
// The snapshot already carried per-instance health as a labelled gauge; the old
// dashboard collapsed it to "3 / 4 up", which does not say which one is down.

import { html, esc, table, notConfigured } from "../lib/dom.js";
import { count, isAbsent } from "../lib/format.js";
import { metaLine } from "../lib/widgets.js";

export function render(snapshot) {
  const media = snapshot.rtpengine;

  if (isAbsent(media)) {
    html("media-body", notConfigured("Media anchoring", "media"));
    html("media-instances", "");
    return;
  }

  const up = media.up || 0;
  const total = media.total || 0;
  html(
    "media-body",
    [
      metaLine("Instances up", up + " / " + total, {
        color: total === 0 ? "var(--faint)" : up === total ? "var(--up)" : up > 0 ? "var(--warn)" : "var(--crit)",
      }),
      metaLine("Degraded", count(Math.max(0, total - up)), {
        color: total - up > 0 ? "var(--warn)" : undefined,
      }),
    ].join(""),
  );

  const instances = Object.entries(media.instances || {});
  html(
    "media-instances",
    table(
      ["Instance", "Health"],
      instances
        .sort((a, b) => a[0].localeCompare(b[0]))
        .map(
          ([address, healthy]) =>
            '<tr><td class="aor">' +
            esc(address) +
            "</td><td>" +
            (healthy
              ? '<span class="spill up">● up</span>'
              : '<span class="spill down">● down</span>') +
            "</td></tr>",
        ),
      "no media instances reporting",
    ),
  );
}

export function markup() {
  return `
    <div class="sectlabel">Media engine</div>
    <section class="grid2">
      <div class="card">
        <div class="panelhead"><span class="t">Engine set</span></div>
        <div class="panelbody" id="media-body"></div>
      </div>
      <div class="card">
        <div class="panelhead"><span class="t">Per instance</span><span class="count-pill">health probe</span></div>
        <div id="media-instances"></div>
      </div>
    </section>
  `;
}
