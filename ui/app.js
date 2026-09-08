// Dashboard bootstrap: router, poll loop, and the shared unlock/toast plumbing.
//
// Polling rather than a push socket: it is stateless, survives a reconnect for
// free, and at one operator browser costs nothing. What it does do is poll only
// the visible view, and back off entirely while the tab is hidden — the old
// version re-fetched every list on its own timer regardless.

import { $, html, text } from "./lib/dom.js";
import { count, duration } from "./lib/format.js";
import * as api from "./lib/api.js";
import { bindDrawer } from "./drawer.js";

import * as overview from "./views/overview.js";
import * as calls from "./views/calls.js";
import * as registrations from "./views/registrations.js";
import * as security from "./views/security.js";
import * as gateways from "./views/gateways.js";
import * as signalling from "./views/signalling.js";
import * as media from "./views/media.js";
import * as control from "./views/control.js";
import * as system from "./views/system.js";

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
