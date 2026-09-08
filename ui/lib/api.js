// Admin API client.
//
// The bearer token lives in sessionStorage so it dies with the tab. It is sent
// on every request because `admin.auth.protect_reads` may gate the read routes
// too.

const TOKEN_KEY = "siphon_admin_token";

let token = sessionStorage.getItem(TOKEN_KEY) || "";

export const hasToken = () => Boolean(token);

export function setToken(value) {
  token = (value || "").trim();
  if (token) sessionStorage.setItem(TOKEN_KEY, token);
  else sessionStorage.removeItem(TOKEN_KEY);
}

export function clearToken() {
  token = "";
  sessionStorage.removeItem(TOKEN_KEY);
}

/** Raised for a 401, so callers can render "locked" rather than "failed". */
export class Unauthorized extends Error {}

async function request(path, options = {}) {
  const headers = Object.assign({}, options.headers || {});
  if (token) headers.Authorization = "Bearer " + token;
  const response = await fetch(path, Object.assign({}, options, { headers }));
  if (response.status === 401) throw new Unauthorized(path);
  if (!response.ok) throw new Error(path + " -> " + response.status);
  return response;
}

export async function get(path) {
  return (await request(path)).json();
}

export async function del(path) {
  return request(path, { method: "DELETE" });
}

export async function post(path) {
  return request(path, { method: "POST" });
}

/**
 * Open a Server-Sent Events stream with the bearer token attached.
 *
 * `EventSource` cannot carry an Authorization header, which would force the
 * token into the query string; `fetch` can, so the stream authenticates exactly
 * like every other admin call. Returns the raw Response — the caller reads
 * `response.body` and does its own framing.
 */
export async function stream(path, signal) {
  const headers = { Accept: "text/event-stream" };
  return request(path, { headers, signal });
}

export const snapshot = () => get("/admin/metrics.json");
export const logs = () => get("/admin/logs");
export const registrations = () => get("/admin/registrations");
export const calls = () => get("/admin/calls");
export const bans = () => get("/admin/bans");
export const gateways = () => get("/admin/gateways");
export const ready = () => get("/admin/ready");
