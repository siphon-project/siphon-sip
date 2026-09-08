// Slide-in detail drawer, shared by every view that has a per-row detail.

import { $, html, text } from "./lib/dom.js";

export function openDrawer(title, bodyHtml) {
  text("drawer-title", title);
  html("drawer-body", bodyHtml);
  $("drawer").classList.add("show");
  $("drawer-backdrop").classList.add("show");
}

export function closeDrawer() {
  $("drawer").classList.remove("show");
  $("drawer-backdrop").classList.remove("show");
}

export function bindDrawer() {
  $("drawer-close").addEventListener("click", closeDrawer);
  $("drawer-backdrop").addEventListener("click", closeDrawer);
  addEventListener("keydown", (event) => {
    if (event.key === "Escape") closeDrawer();
  });
}
