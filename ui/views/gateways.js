// Gateways — the configured destination groups and their probe health.

import { $, html, text, esc, transportChip } from "../lib/dom.js";
import { notConfigured } from "../lib/dom.js";
import * as api from "../lib/api.js";

let unlocked = false;

export function setUnlocked(value) {
  unlocked = value;
}

export async function load() {
  let groups;
  try {
    groups = await api.gateways();
  } catch (error) {
    html(
      "gw-groups",
      '<div class="card"><div class="panelbody empty">' +
        (error instanceof api.Unauthorized ? "read access is protected — unlock first" : "failed to load") +
        "</div></div>",
    );
    return;
  }

  text("nav-gw", groups.length || "");
  if (!groups.length) {
    html("gw-groups", '<div class="card">' + notConfigured("Gateway routing", "gateway") + "</div>");
    return;
  }

  html(
    "gw-groups",
    groups
      .map((group) => {
        const rows = (group.destinations || [])
          .map((destination) => {
            const attributes = Object.entries(destination.attrs || {})
              .map(([key, value]) => key + "=" + value)
              .join(" ");
            const action = destination.healthy ? "down" : "up";
            const actionLabel = destination.healthy ? "drain" : "enable";
            // Consecutive probe failures, shown while degrading or down — a
            // destination on 2/3 is about to go out of rotation.
            const missed =
              (destination.checks_missed || 0) > 0
                ? ' <span class="missed' +
                  (destination.healthy ? "" : " crit") +
                  '" title="consecutive health-probe failures">' +
                  destination.checks_missed +
                  "/" +
                  (group.failure_threshold || "?") +
                  " missed</span>"
                : "";
            return (
              '<tr><td class="aor">' +
              esc(destination.uri) +
              '</td><td class="contact">' +
              esc(destination.address) +
              " " +
              transportChip(destination.transport) +
              "</td><td>" +
              (destination.healthy
                ? '<span class="spill up">● up</span>'
                : '<span class="spill down">● down</span>') +
              missed +
              '</td><td class="q num">' +
              esc(destination.weight) +
              '</td><td class="q num">' +
              esc(destination.priority) +
              '</td><td class="contact">' +
              esc(attributes) +
              '</td><td><button class="rowbtn' +
              (unlocked ? " armed" : "") +
              '" data-gw="' +
              esc(group.name) +
              "|" +
              esc(destination.uri) +
              "|" +
              action +
              '">' +
              actionLabel +
              "</button></td></tr>"
            );
          })
          .join("");

        const color = group.up === group.total ? "var(--up)" : group.up > 0 ? "var(--warn)" : "var(--crit)";
        return (
          '<div class="card"><div class="panelhead"><span class="t">' +
          esc(group.name) +
          ' <span class="count-pill" style="margin-left:8px">' +
          esc(group.algorithm) +
          '</span></span><span class="count-pill"><b style="color:' +
          color +
          '">' +
          group.up +
          " / " +
          group.total +
          '</b> up</span></div><div class="tblscroll"><table class="tbl"><thead><tr>' +
          '<th>Destination</th><th>Address</th><th>Health</th><th class="num">Weight</th>' +
          '<th class="num">Priority</th><th>Attrs</th><th></th>' +
          "</tr></thead><tbody>" +
          rows +
          "</tbody></table></div></div>"
        );
      })
      .join(""),
  );
}

export function bind(onAction) {
  $("gw-groups").addEventListener("click", (event) => {
    const button = event.target.closest("[data-gw]");
    if (button) onAction(button.getAttribute("data-gw").split("|"));
  });
}

export function markup() {
  return `
    <div class="sectlabel">Destination groups · health probed on the configured interval</div>
    <div id="gw-groups"><div class="card"><div class="panelbody empty">loading…</div></div></div>
  `;
}
