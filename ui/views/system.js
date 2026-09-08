// System — allocator, Python executor and runtime facts.

import { html } from "../lib/dom.js";
import { count, mb, toMB, duration, isAbsent } from "../lib/format.js";
import { fact, memoryBar, stat } from "../lib/widgets.js";

export function render(snapshot) {
  const memory = snapshot.memory || {};
  const pyexec = snapshot.pyexec || {};

  const max = Math.max(toMB(memory.mapped), toMB(memory.resident), toMB(memory.allocated), 1);
  html(
    "sys-mem",
    [
      // `allocated` is the leak signal: live bytes, independent of allocator
      // retention and fragmentation, which is why RSS alone is not gated on.
      memoryBar("allocated", toMB(memory.allocated), max, "var(--sky)"),
      memoryBar("active", toMB(memory.active), max, "var(--indigo)"),
      memoryBar("resident", toMB(memory.resident), max, "var(--violet)"),
      memoryBar("mapped", toMB(memory.mapped), max, "var(--cyan)"),
      memoryBar("retained", toMB(memory.retained), max, "var(--faint)"),
      memoryBar("metadata", toMB(memory.metadata), max, "var(--faint)"),
    ].join(""),
  );

  // The glibc arenas are the C-side pool that jemalloc cannot see — libsctp,
  // OpenSSL and CPython's raw domain all allocate here.
  const glibcMax = Math.max(toMB(memory.glibc_system), 1);
  html(
    "sys-glibc",
    [
      memoryBar("system", toMB(memory.glibc_system), glibcMax, "var(--faint)"),
      memoryBar("in-use", toMB(memory.glibc_in_use), glibcMax, "var(--faint)"),
      '<div class="membar"><span class="ml">arenas</span><span class="track"></span><span class="mv">' +
        count(memory.glibc_arenas) +
        "</span></div>",
    ].join(""),
  );

  const shed = pyexec.jobs_shed || 0;
  html(
    "sys-py",
    [
      stat("pool size", count(pyexec.pool_size) + " / " + count(pyexec.pool_max)),
      stat("inflight", count(pyexec.inflight)),
      stat("queue depth", count(pyexec.queue_depth)),
      stat("jobs completed", count(pyexec.jobs_completed)),
      // Shedding means handlers were dropped rather than run — never routine.
      stat("jobs shed", count(shed), shed > 0 ? "var(--crit)" : "var(--up)"),
      stat("python blocks", count(memory.python_allocated_blocks)),
    ].join(""),
  );

  html(
    "sys-facts",
    [
      fact("version", snapshot.version || "—"),
      fact("instance id", snapshot.instance_id || "—"),
      fact("uptime", duration(snapshot.uptime_seconds)),
      fact("allocator", snapshot.jemalloc_active ? "jemalloc" : "system"),
      fact("registrations", count(snapshot.registrations_active)),
      fact("transactions", count((snapshot.sip || {}).transactions_active)),
    ].join(""),
  );
}

export function markup() {
  return `
    <section class="grid2">
      <div class="card">
        <div class="panelhead"><span class="t">Memory</span><span class="count-pill" id="sys-alloc-tag">—</span></div>
        <div class="panelbody">
          <div class="subhead">jemalloc (Rust side)</div>
          <div id="sys-mem"></div>
          <div class="subhead" style="margin-top:14px">glibc (C side — libsctp, OpenSSL, CPython raw)</div>
          <div id="sys-glibc"></div>
        </div>
      </div>
      <div class="card">
        <div class="panelhead"><span class="t">Python executor pool</span></div>
        <div class="panelbody"><div class="statrow" id="sys-py"></div></div>
      </div>
    </section>
    <div class="card">
      <div class="panelhead"><span class="t">Runtime</span></div>
      <div class="panelbody"><div class="facts" id="sys-facts"></div></div>
    </div>
  `;
}
