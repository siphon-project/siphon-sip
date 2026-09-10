// Value formatting.
//
// One rule runs through all of it: `null`/`undefined` means "this node does not
// have that subsystem" and renders as an em dash, while `0` means "it is there
// and the value is zero". Collapsing the two is what let a dead counter sit on
// the dashboard indefinitely looking like an idle one.

export const ABSENT = "—";

/** True when a value is absent (not configured), as opposed to zero. */
export const isAbsent = (value) => value === null || value === undefined;

/** Integer with thousands separators, or an em dash when absent. */
export function count(value) {
  return isAbsent(value) ? ABSENT : Math.round(value).toLocaleString("en-US");
}

/** Bytes as MB — one decimal below 100 so small movements stay visible. */
export function mb(bytes) {
  if (isAbsent(bytes)) return ABSENT;
  const value = bytes / 1048576;
  return value < 100
    ? value.toLocaleString("en-US", { minimumFractionDigits: 1, maximumFractionDigits: 1 })
    : Math.round(value).toLocaleString("en-US");
}

export const toMB = (bytes) => (isAbsent(bytes) ? 0 : bytes / 1048576);

/** Seconds as `1d 02:03` / `02:03:04` / `03:04`. */
export function duration(seconds) {
  if (isAbsent(seconds)) return ABSENT;
  const total = Math.max(0, Math.floor(seconds));
  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const secs = total % 60;
  const pad = (n) => String(n).padStart(2, "0");
  if (days) return days + "d " + pad(hours) + ":" + pad(minutes);
  if (hours) return pad(hours) + ":" + pad(minutes) + ":" + pad(secs);
  return pad(minutes) + ":" + pad(secs);
}

/** Compact elapsed time for a table cell: `4s`, `2m 10s`, `1h 04m`. */
export function elapsed(seconds) {
  if (isAbsent(seconds)) return ABSENT;
  const total = Math.max(0, Math.floor(seconds));
  if (total < 60) return total + "s";
  if (total < 3600) return Math.floor(total / 60) + "m " + String(total % 60).padStart(2, "0") + "s";
  return Math.floor(total / 3600) + "h " + String(Math.floor((total % 3600) / 60)).padStart(2, "0") + "m";
}

/**
 * Rate of change between two cumulative counter readings.
 *
 * Returns 0 rather than a negative rate when the counter went backwards, which
 * happens on a process restart — a large negative spike on a graph is a worse
 * lie than a momentary zero.
 */
export function rate(current, previous, seconds) {
  if (isAbsent(current) || isAbsent(previous) || !(seconds > 0)) return 0;
  return Math.max(0, (current - previous) / seconds);
}

/**
 * Seconds as a latency reading, in whichever of µs / ms / s keeps it readable.
 *
 * Diameter round trips to a co-located HSS run in the tens of microseconds, to
 * a remote OCS in the tens of milliseconds, and a timing-out one sits at the
 * request timeout in whole seconds. A fixed unit renders one of those three as
 * "0" and another as a wall of digits.
 */
export function latency(seconds) {
  if (isAbsent(seconds)) return ABSENT;
  if (seconds < 0.001) return Math.round(seconds * 1e6) + " µs";
  if (seconds < 1) {
    const ms = seconds * 1000;
    return (ms < 10 ? ms.toFixed(1) : Math.round(ms)) + " ms";
  }
  return (seconds < 10 ? seconds.toFixed(1) : Math.round(seconds).toLocaleString("en-US")) + " s";
}

/** Sum the values of a `{label: count}` map. */
export function sum(map) {
  if (!map) return 0;
  return Object.values(map).reduce((total, value) => total + (value || 0), 0);
}
