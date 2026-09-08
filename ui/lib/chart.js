// Sparkline charts.
//
// History is kept in sessionStorage so a reload does not wipe the graph back to
// a single point — the old dashboard lost every series on refresh, which made
// the charts close to useless for watching anything.

const HISTORY_KEY = "siphon_chart_history";
const MAX_POINTS = 120;

let tip = null;

function tooltip() {
  if (!tip) {
    tip = document.createElement("div");
    tip.className = "charttip";
    document.body.appendChild(tip);
  }
  return tip;
}

function loadHistory() {
  try {
    return JSON.parse(sessionStorage.getItem(HISTORY_KEY) || "{}");
  } catch {
    // A corrupt or unreadable store must never stop the dashboard rendering.
    return {};
  }
}

const history = loadHistory();
let saveTimer = null;

function persist() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    try {
      sessionStorage.setItem(HISTORY_KEY, JSON.stringify(history));
    } catch {
      // Private-window or quota failure — the charts still work in memory.
    }
  }, 1000);
}

export class Chart {
  constructor(canvasId, color, options = {}) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.context = this.canvas.getContext("2d");
    this.key = options.key || canvasId;
    this.color = color;
    this.format = options.format || ((v) => Math.round(v).toLocaleString("en-US"));

    const stored = history[this.key];
    this.data = stored && Array.isArray(stored.data) ? stored.data.slice(-MAX_POINTS) : [];
    this.times = stored && Array.isArray(stored.times) ? stored.times.slice(-MAX_POINTS) : [];
    this.hoverIndex = null;

    this.resize();
    addEventListener("resize", () => this.resize());
    this.canvas.addEventListener("mousemove", (event) => this.onHover(event));
    this.canvas.addEventListener("mouseleave", () => {
      this.hoverIndex = null;
      tooltip().classList.remove("show");
      this.draw();
    });
  }

  push(value) {
    if (!this.canvas) return;
    this.data.push(value);
    this.times.push(Date.now());
    if (this.data.length > MAX_POINTS) {
      this.data.shift();
      this.times.shift();
    }
    history[this.key] = { data: this.data, times: this.times };
    persist();
    this.draw();
  }

  resize() {
    if (!this.canvas) return;
    const ratio = devicePixelRatio || 1;
    const rect = this.canvas.getBoundingClientRect();
    this.width = rect.width;
    this.height = rect.height;
    this.canvas.width = rect.width * ratio;
    this.canvas.height = rect.height * ratio;
    this.context.setTransform(ratio, 0, 0, ratio, 0, 0);
    this.draw();
  }

  cssVar(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }

  // Axis bounds plus a symmetric margin, so the printed labels are the true
  // top/bottom edges of the plot and the line floats inside with matching
  // headroom.
  geometry() {
    const data = this.data;
    const n = data.length;
    if (n < 2 || !this.width || !this.height) return null;
    const pad = 6;
    const plotHeight = this.height - pad * 2;
    const min = Math.min(...data);
    const max = Math.max(...data);
    let range = max - min;
    if (range < 1e-9) range = Math.max(Math.abs(max) * 0.1, 1); // flat series
    const margin = range * 0.18;
    const low = min - margin;
    const span = max + margin - low;
    return {
      pad,
      n,
      low,
      high: max + margin,
      x: (i) => pad + (this.width - pad * 2) * (i / (n - 1)),
      y: (v) => pad + plotHeight - ((v - low) / span) * plotHeight,
    };
  }

  draw() {
    if (!this.canvas || !this.width || !this.height) return;
    const ctx = this.context;
    const pad = 6;
    const plotHeight = this.height - pad * 2;
    ctx.clearRect(0, 0, this.width, this.height);

    ctx.strokeStyle = this.cssVar("--grid");
    ctx.lineWidth = 1;
    for (let line = 0; line <= 3; line++) {
      const y = pad + (plotHeight * line) / 3;
      ctx.beginPath();
      ctx.moveTo(pad, y);
      ctx.lineTo(this.width - pad, y);
      ctx.stroke();
    }

    const geo = this.geometry();
    if (!geo) return;
    const { x, y } = geo;
    const data = this.data;

    const gradient = ctx.createLinearGradient(0, pad, 0, this.height);
    gradient.addColorStop(0, this.color + "55");
    gradient.addColorStop(1, this.color + "00");
    ctx.beginPath();
    ctx.moveTo(x(0), y(data[0]));
    for (let i = 1; i < data.length; i++) ctx.lineTo(x(i), y(data[i]));
    ctx.lineTo(x(data.length - 1), this.height - pad);
    ctx.lineTo(x(0), this.height - pad);
    ctx.closePath();
    ctx.fillStyle = gradient;
    ctx.fill();

    ctx.beginPath();
    ctx.moveTo(x(0), y(data[0]));
    for (let i = 1; i < data.length; i++) ctx.lineTo(x(i), y(data[i]));
    ctx.strokeStyle = this.color;
    ctx.lineWidth = 2;
    ctx.lineJoin = "round";
    ctx.stroke();

    if (this.hoverIndex != null && this.hoverIndex >= 0 && this.hoverIndex < data.length) {
      const hx = x(this.hoverIndex);
      ctx.strokeStyle = this.cssVar("--faint");
      ctx.lineWidth = 1;
      ctx.setLineDash([3, 3]);
      ctx.beginPath();
      ctx.moveTo(hx, pad);
      ctx.lineTo(hx, this.height - pad);
      ctx.stroke();
      ctx.setLineDash([]);
      ctx.beginPath();
      ctx.arc(hx, y(data[this.hoverIndex]), 3.4, 0, 7);
      ctx.fillStyle = this.color;
      ctx.fill();
      ctx.lineWidth = 1.5;
      ctx.strokeStyle = this.cssVar("--panel");
      ctx.stroke();
    }

    ctx.beginPath();
    ctx.arc(x(data.length - 1), y(data[data.length - 1]), 3.2, 0, 7);
    ctx.fillStyle = this.color;
    ctx.fill();

    this.label(geo.high, pad + 2, "top");
    this.label(geo.low, this.height - pad - 2, "alphabetic");
  }

  label(value, y, baseline) {
    const ctx = this.context;
    const textValue = this.format(value);
    ctx.font = '10px ui-monospace, "JetBrains Mono", monospace';
    ctx.textAlign = "right";
    ctx.textBaseline = baseline;
    ctx.lineWidth = 3;
    ctx.lineJoin = "round";
    ctx.strokeStyle = this.cssVar("--panel");
    ctx.strokeText(textValue, this.width - 8, y);
    ctx.fillStyle = this.cssVar("--faint");
    ctx.fillText(textValue, this.width - 8, y);
  }

  onHover(event) {
    const geo = this.geometry();
    if (!geo) return;
    const fraction = (event.offsetX - geo.pad) / (this.width - geo.pad * 2);
    const index = Math.min(geo.n - 1, Math.max(0, Math.round(fraction * (geo.n - 1))));
    this.hoverIndex = index;
    this.draw();

    const age = Math.max(0, Math.round((Date.now() - this.times[index]) / 1000));
    const element = tooltip();
    element.textContent = this.format(this.data[index]) + " · " + (age <= 1 ? "now" : age + "s ago");
    element.style.left = event.clientX + 12 + "px";
    element.style.top = event.clientY + 12 + "px";
    element.classList.add("show");
  }
}
