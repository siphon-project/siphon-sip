// Shared render helpers used by more than one view, so the same kind of data
// always looks the same wherever it appears.

import { esc } from "./dom.js";
import { count, isAbsent, ABSENT } from "./format.js";

/**
 * A `{label: value}` map as a bar list, sorted by value descending.
 *
 * Every label→count breakdown in the dashboard goes through this — SIP methods,
 * response classes, Diameter commands, connection-refusal reasons — so they are
 * directly comparable by eye.
 *
 * `options.keep` lists labels that should be shown even at zero (the SIP method
 * set, say, where a zero is meaningful); anything else at zero is hidden to keep
 * the list readable.
 */
export function barList(map, options = {}) {
  if (isAbsent(map)) return '<div class="empty">not available</div>';
  const entries = Object.entries(map).filter(
    ([label, value]) => value > 0 || (options.keep || []).includes(label),
  );
  if (!entries.length) return '<div class="empty">' + esc(options.empty || "nothing yet") + "</div>";

  entries.sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  const max = Math.max(...entries.map(([, value]) => value), 1);
  const color = options.color || "var(--indigo)";

  return (
    '<div class="bars">' +
    entries
      .map(([label, value]) => {
        const width = Math.max(value > 0 ? 2 : 0, Math.round((value / max) * 100));
        return (
          '<div class="barrow' +
          (value > 0 ? "" : " zero") +
          '"><span class="bl" title="' +
          esc(label) +
          '">' +
          esc(label) +
          '</span><span class="bt"><i style="width:' +
          width +
          "%;background:" +
          color +
          '"></i></span><span class="bv">' +
          count(value) +
          "</span></div>"
        );
      })
      .join("") +
    "</div>"
  );
}

/** A `key: value` fact row. */
export function fact(key, value) {
  return '<div class="fact"><span class="k">' + esc(key) + '</span><span class="v">' + esc(value) + "</span></div>";
}

/** A `key: value` stat row, optionally coloured. */
export function stat(key, value, color) {
  return (
    '<div class="stat"><span class="k">' +
    esc(key) +
    '</span><span class="v"' +
    (color ? ' style="color:' + color + '"' : "") +
    ">" +
    esc(value) +
    "</span></div>"
  );
}

/** A left-label / right-value line, as used in the health panels. */
export function metaLine(label, value, options = {}) {
  return (
    '<div class="metaline' +
    (options.goto ? " clickable" : "") +
    '"' +
    (options.goto ? ' data-goto="' + esc(options.goto) + '"' : "") +
    "><span>" +
    esc(label) +
    "</span><b" +
    (options.color ? ' style="color:' + options.color + '"' : "") +
    ">" +
    esc(value) +
    "</b></div>"
  );
}

/** A KPI tile. A `null` value renders as an em dash, never as a zero. */
export function tile(label, value, footer, options = {}) {
  const absent = isAbsent(value);
  return (
    '<div class="tile' +
    (options.hero && !absent ? " hero" : "") +
    (absent ? " na" : "") +
    '"><span class="lab">' +
    esc(label) +
    '</span><div class="v">' +
    (absent ? ABSENT : esc(value)) +
    (options.unit && !absent ? "<small>" + esc(options.unit) + "</small>" : "") +
    '</div><div class="foot">' +
    esc(absent ? options.absentFooter || "not configured" : footer) +
    "</div></div>"
  );
}

/** A proportional bar for a memory figure. */
export function memoryBar(name, valueMB, maxMB, color) {
  const percent = maxMB > 0 ? Math.max(2, Math.min(100, Math.round((valueMB / maxMB) * 100))) : 0;
  return (
    '<div class="membar"><span class="ml">' +
    esc(name) +
    '</span><span class="track"><i style="width:' +
    percent +
    "%;background:" +
    color +
    '"></i></span><span class="mv">' +
    count(valueMB) +
    " MB</span></div>"
  );
}
