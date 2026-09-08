// Dashboard bootstrap: router, poll loop, and the shared unlock/toast plumbing.
//
// Polling rather than a push socket: it is stateless, survives a reconnect for
// free, and at one operator browser costs nothing. What it does do is poll only
// the visible view, and back off entirely while the tab is hidden — the old
// version re-fetched every list on its own timer regardless.

import { $, html, text } from "./lib/dom.js";
import { count, duration } from "./lib/format.js";
import * as api from "./lib/api.js";
import { bindDrawer, openDrawer } from "./drawer.js";

import * as overview from "./views/overview.js";
import * as calls from "./views/calls.js";
import * as registrations from "./views/registrations.js";
import * as security from "./views/security.js";
import * as gateways from "./views/gateways.js";
import * as signalling from "./views/signalling.js";
import * as media from "./views/media.js";
import * as control from "./views/control.js";
import * as system from "./views/system.js";
import * as logs from "./views/logs.js";
import * as cost from "./views/cost.js";

const SNAPSHOT_INTERVAL = 2000;
const LIST_INTERVAL = 4000;

const VIEWS = {
  overview: { title: "Overview", module: overview },
  calls: { title: "Calls", module: calls },
  registrations: { title: "Registrations", module: registrations },
  security: { title: "Security", module: security },
  gateways: { title: "Gateways", module: gateways },
  signalling: { title: "Signalling", module: signalling },
  media: { title: "Media", module: media },
  control: { title: "Control", module: control },
  system: { title: "System", module: system },
  cost: { title: "Cost", module: cost },
  logs: { title: "Logs", module: logs },
};

let current = "overview";
let lastSnapshot = null;

// ------------------------------------------------------------------ toast --

let toastTimer = null;

function say(message, isError) {
  text("toast-t", message);
  $("toast").classList.toggle("err", Boolean(isError));
  $("toast").classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => $("toast").classList.remove("show"), 2800);
}

// ----------------------------------------------------------------- unlock --

function applyUnlock() {
  const unlocked = api.hasToken() || unlockedWithoutToken;
  $("unlock").classList.toggle("on", unlocked);
  text("unlock-t", unlocked ? "Unlocked" : "Unlock");
  registrations.setUnlocked(unlocked);
  security.setUnlocked(unlocked);
  gateways.setUnlocked(unlocked);
  document.querySelectorAll(".rowbtn").forEach((button) => button.classList.toggle("armed", unlocked));
}

// A deployment with no admin token still needs the write actions armed; the
// button then only toggles local intent.
let unlockedWithoutToken = false;

function bindUnlock() {
  $("unlock").addEventListener("click", () => {
    if (api.hasToken() || unlockedWithoutToken) {
      api.clearToken();
      unlockedWithoutToken = false;
      say("Locked — write actions disabled");
      applyUnlock();
      return;
    }
    const entered = window.prompt("Admin bearer token (leave blank if auth is disabled):", "");
    if (entered === null) return;
    api.setToken(entered);
    unlockedWithoutToken = !entered.trim();
    say(entered.trim() ? "Token stored — write actions enabled" : "Write actions enabled (no auth configured)");
    applyUnlock();
    refreshCurrentView();
  });
}

// ----------------------------------------------------------------- router --

function buildViews() {
  const container = $("views");
  container.innerHTML = Object.entries(VIEWS)
    .map(
      ([name, view]) =>
        '<div class="view" id="view-' + name + '">' + view.module.markup() + "</div>",
    )
    .join("");
}

function go(name) {
  if (!VIEWS[name]) name = "overview";
  // Navigating away from the log view releases its stream: the server caps
  // concurrent tails, so a background tab holding one open would spend a slot
  // for a panel nobody is looking at.
  if (current === "logs" && name !== "logs") logs.suspend();
  current = name;
  document.querySelectorAll(".navitem").forEach((item) => {
    item.classList.toggle("active", item.getAttribute("data-view") === name);
  });
  document.querySelectorAll(".view").forEach((view) => {
    view.classList.toggle("show", view.id === "view-" + name);
  });
  text("crumb", VIEWS[name].title);
  if (location.hash !== "#" + name) history.replaceState(null, "", "#" + name);

  if (name === "overview") overview.resize();
  if (lastSnapshot) renderSnapshotViews(lastSnapshot);
  refreshCurrentView();
}

/** Fetch the list data for whichever view is open. */
function refreshCurrentView() {
  if (current === "calls") calls.load();
  else if (current === "registrations") registrations.load();
  else if (current === "security") security.load();
  else if (current === "gateways") gateways.load();
  // The log view holds a live stream rather than polling, so it is loaded once
  // on open and left alone by the list timer.
  else if (current === "logs") logs.load();
  else if (current === "cost") cost.load();
}

// ------------------------------------------------------------------- poll --

function renderSnapshotViews(snapshot) {
  // Only the visible view is re-rendered; the others pick up the latest
  // snapshot when they are opened.
  if (current === "overview") overview.render(snapshot);
  else if (current === "security") security.render(snapshot);
  else if (current === "signalling") signalling.render(snapshot);
  else if (current === "media") media.render(snapshot);
  else if (current === "control") control.render(snapshot);
  else if (current === "system") system.render(snapshot);
  else if (current === "cost") cost.render(snapshot);
}

function setBadge(id, cls, label) {
  const element = $(id);
  element.classList.remove("ok", "bad", "info", "warn");
  if (cls) element.classList.add(cls);
  element.lastChild.textContent = label;
}

/** Grey out the nav entry for a subsystem this node has not configured. */
function markAbsentNav(snapshot) {
  const absent = {
    signalling: snapshot.diameter === null,
    media: snapshot.rtpengine === null,
    control: snapshot.control === null,
  };
  Object.entries(absent).forEach(([name, isAbsent]) => {
    const item = document.querySelector('.navitem[data-view="' + name + '"]');
    if (!item) return;
    item.classList.toggle("absent", isAbsent);
    const badge = item.querySelector(".count");
    if (badge) badge.textContent = isAbsent ? "n/a" : "";
  });
}

async function poll() {
  let snapshot;
  try {
    snapshot = await api.snapshot();
  } catch (error) {
    text("foot-node", "● disconnected");
    $("foot-node").style.color = "var(--crit)";
    setBadge("b-live", "bad", "OFFLINE");
    return;
  }

  lastSnapshot = snapshot;
  text("foot-node", "● node healthy");
  $("foot-node").style.color = "var(--up)";
  text("foot-ver", "siphon " + (snapshot.version || ""));
  setBadge("b-live", "ok", "LIVE");
  setBadge("b-jem", snapshot.jemalloc_active ? "info" : "warn", snapshot.jemalloc_active ? "jemalloc" : "system alloc");
  text("b-up", "up " + duration(snapshot.uptime_seconds));
  text("nav-regs", count(snapshot.registrations_active));

  markAbsentNav(snapshot);
  renderSnapshotViews(snapshot);
}

async function pollReady() {
  try {
    const body = await api.ready();
    const draining = body.status === "draining";
    setBadge("b-ready", draining ? "bad" : "ok", draining ? "DRAINING" : "READY");
  } catch {
    setBadge("b-ready", "bad", "UNKNOWN");
  }
}

// ------------------------------------------------------------------- boot --

function bindActions() {
  registrations.bind((aor) => {
    if (!api.hasToken() && !unlockedWithoutToken) {
      say("Locked — press Unlock and enter an admin token", true);
      return;
    }
    if (!confirm("Force-unregister " + aor + "? This removes all its contacts.")) return;
    api
      .del("/admin/registrations/" + encodeURIComponent(aor))
      .then(() => {
        say("Unregistered " + aor);
        registrations.load();
      })
      .catch((error) => say(error instanceof api.Unauthorized ? "Unauthorized — check the token" : "Failed", true));
  });

  security.bind((ip) => {
    if (!api.hasToken() && !unlockedWithoutToken) {
      say("Locked — press Unlock and enter an admin token", true);
      return;
    }
    api
      .del("/admin/bans/" + encodeURIComponent(ip))
      .then(() => {
        say("Ban lifted for " + ip);
        security.load();
      })
      .catch((error) => say(error instanceof api.Unauthorized ? "Unauthorized — check the token" : "Failed", true));
  });

  gateways.bind(([group, destination, action]) => {
    if (!api.hasToken() && !unlockedWithoutToken) {
      say("Locked — press Unlock and enter an admin token", true);
      return;
    }
    api
      .post(
        "/admin/gateways/" + encodeURIComponent(group) + "/" + encodeURIComponent(destination) + "/" + action,
      )
      .then(() => {
        say("Gateway " + destination + " marked " + action);
        gateways.load();
      })
      .catch((error) => say(error instanceof api.Unauthorized ? "Unauthorized — check the token" : "Failed", true));
  });

  calls.bind();
  logs.bind();
  bindSearch();
  bindNavToggle();
}

/**
 * Mobile navigation.
 *
 * Under 780px the sidebar is an overlay: without this it was `display: none`
 * with nothing to reopen it, so a phone could only ever see the view it landed
 * on. Selecting a destination closes it again, which is what a drawer nav is
 * expected to do.
 */
function bindNavToggle() {
  const toggle = $("navtoggle");
  const backdrop = $("navbackdrop");
  const sidebar = document.querySelector(".sidebar");
  if (!toggle || !backdrop || !sidebar) return;

  const setOpen = (open) => {
    sidebar.classList.toggle("open", open);
    backdrop.classList.toggle("show", open);
    toggle.setAttribute("aria-expanded", open ? "true" : "false");
  };

  toggle.addEventListener("click", () => setOpen(!sidebar.classList.contains("open")));
  backdrop.addEventListener("click", () => setOpen(false));
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") setOpen(false);
  });
  // Any nav choice closes the overlay; on a wide screen this is a no-op.
  $("nav").addEventListener("click", () => setOpen(false));
}

/**
 * One box that finds a call by whatever the operator actually has — a number,
 * a Call-ID, a fragment of either. Searches the capture ring (message content,
 * so a dialled number matches) and the live call list.
 */
function bindSearch() {
  const box = $("topsearch");
  if (!box) return;
  box.addEventListener("keydown", async (event) => {
    if (event.key !== "Enter") return;
    const query = box.value.trim();
    if (!query) return;

    let result;
    try {
      result = await api.get("/admin/search?q=" + encodeURIComponent(query));
    } catch (error) {
      say(
        error instanceof api.Unauthorized
          ? "Search is protected — press Unlock and enter an admin token"
          : "Search failed",
        true,
      );
      return;
    }

    const live = result.live_calls || [];
    // `null` means capture is switched off, which is a different answer from
    // "capture is on and found nothing" — say which.
    const captured = result.captured;

    let body =
      '<div class="subhead">Live calls (' + live.length + ")</div>" +
      (live.length
        ? '<div class="tblscroll"><table class="tbl"><tbody>' +
          live
            .map(
              (call) =>
                '<tr class="rowlink" data-goto-call="' +
                encodeURIComponent(call.call_id) +
                '"><td class="aor">' +
                call.call_id +
                '</td><td class="q">' +
                (call.a_party || "") +
                " &#8594; " +
                (call.b_party || "") +
                "</td><td>" +
                call.state +
                "</td></tr>",
            )
            .join("") +
          "</tbody></table></div>"
        : '<div class="empty">no live call matches</div>');

    body += '<div class="subhead" style="margin-top:14px">Captured signalling</div>';
    if (captured === null || captured === undefined) {
      body +=
        '<div class="notconfigured"><b>Message capture is off on this node</b>' +
        "set <code>admin.capture.enabled</code> to search past calls by number.</div>";
    } else if (!captured.length) {
      body += '<div class="empty">nothing captured matches</div>';
    } else {
      body +=
        '<div class="tblscroll"><table class="tbl"><tbody>' +
        captured
          .map(
            (hit) =>
              '<tr class="rowlink" data-goto-call="' +
              encodeURIComponent(hit.call_id) +
              '"><td class="aor">' +
              hit.call_id +
              '</td><td class="q">' +
              (hit.first_line || "") +
              '</td><td class="num q">' +
              hit.messages +
              "</td></tr>",
          )
          .join("") +
        "</tbody></table></div>";
    }

    openDrawer('Search "' + query + '"', body);
  });

  // A search hit opens that call's log view, filtered — the one deep link that
  // makes having both the ladder and the tail in one place pay off.
  document.addEventListener("click", (event) => {
    const row = event.target.closest("[data-goto-call]");
    if (!row) return;
    const callId = decodeURIComponent(row.getAttribute("data-goto-call"));
    go("logs");
    logs.focusCall(callId);
  });
}

function boot() {
  buildViews();
  bindDrawer();
  bindUnlock();
  bindActions();
  applyUnlock();

  $("nav").addEventListener("click", (event) => {
    const item = event.target.closest(".navitem");
    if (!item) return;
    event.preventDefault();
    go(item.getAttribute("data-view"));
  });

  // Health lines and the overview "view all" links navigate too.
  document.addEventListener("click", (event) => {
    const target = event.target.closest("[data-goto]");
    if (target) go(target.getAttribute("data-goto"));
  });

  $("theme").addEventListener("click", () => {
    const root = document.documentElement;
    const currentTheme =
      root.getAttribute("data-theme") ||
      (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    root.setAttribute("data-theme", currentTheme === "dark" ? "light" : "dark");
    overview.redraw();
  });

  go((location.hash || "#overview").slice(1));
  addEventListener("hashchange", () => go((location.hash || "#overview").slice(1)));

  poll();
  pollReady();

  // Back off while the tab is hidden: an operator with the dashboard parked in a
  // background tab should not keep a poll running against a production node.
  setInterval(() => {
    if (!document.hidden) poll();
  }, SNAPSHOT_INTERVAL);
  setInterval(() => {
    if (!document.hidden) pollReady();
  }, 5000);
  setInterval(() => {
    if (!document.hidden) refreshCurrentView();
  }, LIST_INTERVAL);
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) {
      poll();
      refreshCurrentView();
    }
  });
}

boot();
