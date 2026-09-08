// Server-Sent Events over fetch.
//
// `EventSource` would be less code, but it cannot send an Authorization header,
// so the bearer token would have to travel in the query string — logged by every
// proxy in front of the node and kept in browser history. `fetch` carries the
// header normally, at the cost of framing the stream ourselves, which is the
// twenty lines below.

import { stream as openStream, Unauthorized } from "./api.js";

const MAX_BACKOFF_MS = 15000;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Open an SSE stream and dispatch its events until closed.
 *
 * handlers: { onMessage(data), onEvent(name, data), onStatus(state) }
 * state is "live" | "reconnecting" | "locked" | "closed".
 *
 * Returns a handle with close(). Reconnects with exponential backoff, because
 * the node restarting under a watching operator should heal on its own rather
 * than leave a dead panel that looks like silence.
 */
export function openEventStream(path, handlers = {}) {
  let controller = null;
  let stopped = false;
  let attempt = 0;

  const status = (state) => handlers.onStatus && handlers.onStatus(state);

  function dispatch(block) {
    let name = "message";
    const data = [];
    for (const line of block.split("\n")) {
      if (line.startsWith("event:")) name = line.slice(6).trim();
      else if (line.startsWith("data:")) data.push(line.slice(5).trim());
      // ":" comment lines and anything else are ignored, per the SSE spec.
    }
    if (!data.length) return;
    const payload = data.join("\n");
    if (name === "message") {
      if (handlers.onMessage) handlers.onMessage(payload);
    } else if (handlers.onEvent) {
      handlers.onEvent(name, payload);
    }
  }

  async function run() {
    while (!stopped) {
      controller = new AbortController();
      try {
        const response = await openStream(path, controller.signal);
        attempt = 0;
        status("live");
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";
        for (;;) {
          const { value, done } = await reader.read();
          if (done || stopped) break;
          buffer += decoder.decode(value, { stream: true });
          let index;
          while ((index = buffer.indexOf("\n\n")) >= 0) {
            dispatch(buffer.slice(0, index));
            buffer = buffer.slice(index + 2);
          }
        }
      } catch (error) {
        if (stopped) break;
        // A token that is missing or wrong will not fix itself by retrying.
        if (error instanceof Unauthorized) {
          status("locked");
          return;
        }
        status("reconnecting");
      }
      if (stopped) break;
      attempt += 1;
      await sleep(Math.min(500 * 2 ** (attempt - 1), MAX_BACKOFF_MS));
    }
    status("closed");
  }

  run();

  return {
    close() {
      stopped = true;
      if (controller) controller.abort();
    },
  };
}
