// Minimal DOM helpers.
//
// Views build markup as strings, so *everything* interpolated into them must go
// through `esc`. Much of this data is attacker-influenced: From/To URIs,
// Contact URIs, User-Agent, gateway attribute values and SIP method tokens all
// arrive from the network. Treat every value as hostile.

export const $ = (id) => document.getElementById(id);

const ENTITIES = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };

/** Escape a value for interpolation into HTML text or a quoted attribute. */
export function esc(value) {
  return String(value == null ? "" : value).replace(/[&<>"']/g, (c) => ENTITIES[c]);
}

/** Replace an element's children with `html`. No-op if the element is absent. */
export function html(id, markup) {
  const el = typeof id === "string" ? $(id) : id;
  if (el) el.innerHTML = markup;
}

/** Set an element's text content (never parsed as HTML). */
export function text(id, value) {
  const el = typeof id === "string" ? $(id) : id;
  if (el) el.textContent = value;
}

/**
 * A "this subsystem is not configured" panel body.
 *
 * Deliberately distinct from an empty table: an empty table means "configured,
 * nothing in it right now", which is a different answer to the same question
 * and the one an operator acts on differently.
 */
export function notConfigured(title, configKey) {
  return (
    '<div class="notconfigured"><b>' +
    esc(title) +
    " is not configured on this node</b>" +
    (configKey ? "add a <code>" + esc(configKey) + "</code> block to siphon.yaml to enable it" : "") +
    "</div>"
  );
}

/** Wrap a table in the standard scroll container. */
export function table(headers, rows, emptyMessage) {
  const head = headers
    .map((h) => (typeof h === "string" ? "<th>" + esc(h) + "</th>" : '<th class="num">' + esc(h.label) + "</th>"))
    .join("");
  const body = rows.length
    ? rows.join("")
    : '<tr><td colspan="' + headers.length + '" class="empty">' + esc(emptyMessage) + "</td></tr>";
  return (
    '<div class="tblscroll"><table class="tbl"><thead><tr>' +
    head +
    "</tr></thead><tbody>" +
    body +
    "</tbody></table></div>"
  );
}

/** Transport chip, coloured consistently wherever a transport is displayed. */
export function transportChip(transport) {
  if (!transport) return '<span class="tp">—</span>';
  const key = String(transport).toLowerCase();
  return '<span class="tp ' + esc(key) + '">' + esc(String(transport).toUpperCase()) + "</span>";
}
