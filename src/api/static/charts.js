const CHART_W = 940;

const escHost = s => String(s).replace(/[&<>"']/g, c =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function svgWrap(h, inner) {
  return `<svg viewBox="0 0 ${CHART_W} ${h}" width="100%" height="${h}"
    preserveAspectRatio="xMidYMid meet" role="img">${inner}</svg>`;
}

function niceTime(s) {
  if (s < 1) return s.toFixed(2) + "s";
  if (s < 60) return s.toFixed(s < 10 ? 1 : 0) + "s";
  return Math.floor(s / 60) + "m" + String(Math.round(s % 60)).padStart(2, "0");
}

function shortBytes(n) {
  if (n < 1024) return n + " B";
  if (n < 1048576) return (n / 1024).toFixed(0) + " KB";
  if (n < 1073741824) return (n / 1048576).toFixed(1) + " MB";
  return (n / 1073741824).toFixed(1) + " GB";
}

function niceStep(range, target) {
  const raw = range / target;
  const mag = Math.pow(10, Math.floor(Math.log10(raw)));
  return [1, 2, 2.5, 5, 10].map(m => m * mag).find(s => s >= raw) || mag * 10;
}

/* Destination port against time, on a linear scale so a scan that walks the
   ports in order reads as the straight diagonal it actually is. */
function portMap(points) {
  const H = 260, PAD_L = 58, PAD_R = 20, PAD_T = 14, PAD_B = 30;
  const plotW = CHART_W - PAD_L - PAD_R;
  const plotH = H - PAD_T - PAD_B;
  if (!points.length) return "";

  const maxT = Math.max(...points.map(p => p[0])) || 1;

  // A couple of stray high ports would otherwise stretch the axis to 60k and
  // squash everything real into the bottom of the chart. Scale to the bulk of
  // the data and pin the few outliers to the top edge.
  const sorted = points.map(p => p[1]).sort((a, b) => a - b);
  const bulk = sorted[Math.floor(sorted.length * 0.98)] || 1;
  const step = niceStep(Math.max(bulk, 1), 5);
  const top = Math.max(Math.ceil(bulk / step) * step, step);
  const over = sorted.filter(v => v > top).length;

  const x = t => PAD_L + (t / maxT) * plotW;
  const y = port => PAD_T + plotH - (Math.min(port, top) / top) * plotH;

  let grid = "";
  for (let v = 0; v <= top + 1e-9; v += step) {
    const yy = y(v).toFixed(1);
    grid += `<line x1="${PAD_L}" x2="${CHART_W - PAD_R}" y1="${yy}" y2="${yy}"
      stroke="var(--grid)" stroke-width="1"/>
      <text x="${PAD_L - 12}" y="${(y(v) + 3.5).toFixed(1)}" text-anchor="end"
        font-size="10.5" fill="var(--muted)">${v >= 1000 ? (v / 1000) + "k" : v}</text>`;
  }

  const xTicks = [0, 0.5, 1].map(f => {
    const t = maxT * f;
    return `<text x="${x(t).toFixed(1)}" y="${H - 10}"
      text-anchor="${f === 0 ? "start" : f === 1 ? "end" : "middle"}"
      font-size="10.5" fill="var(--muted)">${niceTime(t)}</text>`;
  }).join("");

  const r = points.length > 900 ? 1.9 : points.length > 300 ? 2.7 : 3.8;

  const normal = [], threat = [];
  for (const [t, port, pkts, bad] of points) {
    const c = `<circle cx="${x(t).toFixed(1)}" cy="${y(port).toFixed(1)}" r="${bad ? r + 2 : r}"/>`;
    (bad ? threat : normal).push(c);
  }

  return svgWrap(H, `
    ${grid}
    <line x1="${PAD_L}" x2="${CHART_W - PAD_R}" y1="${(PAD_T + plotH).toFixed(1)}"
      y2="${(PAD_T + plotH).toFixed(1)}" stroke="var(--axis)" stroke-width="1"/>
    <g fill="var(--dim)">${normal.join("")}</g>
    <g fill="var(--ink)">${threat.join("")}</g>
    ${xTicks}
    ${over ? `<text x="${CHART_W - PAD_R}" y="${PAD_T + 9}" text-anchor="end" font-size="10"
      fill="var(--muted)">${over} above ${top >= 1000 ? (top / 1000) + "k" : top}</text>` : ""}`);
}

/* Packets over time, split by verdict. */
function timeline(points) {
  const H = 150, PAD_L = 52, PAD_R = 16, PAD_T = 12, PAD_B = 30;
  const plotW = CHART_W - PAD_L - PAD_R;
  const plotH = H - PAD_T - PAD_B;
  if (!points.length) return "";

  const maxT = Math.max(...points.map(p => p[0])) || 1;
  const N = 48;
  const ok = new Array(N).fill(0), bad = new Array(N).fill(0);
  for (const [t, port, pkts, isBad] of points) {
    const i = Math.min(N - 1, Math.floor((t / maxT) * N));
    (isBad ? bad : ok)[i] += pkts;
  }
  const peak = Math.max(...ok.map((v, i) => v + bad[i]), 1);

  const bw = plotW / N;
  const bars = ok.map((v, i) => {
    const total = v + bad[i];
    if (!total) return "";
    const hTotal = (total / peak) * plotH;
    const hBad = (bad[i] / peak) * plotH;
    const bx = PAD_L + i * bw + 1;
    const w = Math.max(bw - 2, 1);
    let out = "";
    if (v) out += `<rect x="${bx.toFixed(1)}" y="${(PAD_T + plotH - hTotal).toFixed(1)}"
      width="${w.toFixed(1)}" height="${Math.max(hTotal - hBad - (hBad ? 2 : 0), 0.8).toFixed(1)}"
      rx="1.5" fill="var(--dim)"/>`;
    if (bad[i]) out += `<rect x="${bx.toFixed(1)}" y="${(PAD_T + plotH - hBad).toFixed(1)}"
      width="${w.toFixed(1)}" height="${Math.max(hBad, 0.8).toFixed(1)}" rx="1.5" fill="var(--ink)"/>`;
    return out;
  }).join("");

  return svgWrap(H, `
    <line x1="${PAD_L}" x2="${CHART_W - PAD_R}" y1="${PAD_T + plotH}" y2="${PAD_T + plotH}"
      stroke="var(--axis)" stroke-width="1"/>
    <text x="${PAD_L - 10}" y="${PAD_T + 10}" text-anchor="end" font-size="11"
      fill="var(--muted)">${peak.toLocaleString()}</text>
    <text x="${PAD_L - 10}" y="${PAD_T + plotH}" text-anchor="end" font-size="11" fill="var(--muted)">0</text>
    ${bars}
    <text x="${PAD_L}" y="${H - 10}" font-size="11" fill="var(--muted)">0s</text>
    <text x="${CHART_W - PAD_R}" y="${H - 10}" text-anchor="end" font-size="11"
      fill="var(--muted)">${niceTime(maxT)}</text>`);
}

/* Busiest destinations by volume. */
function talkerBars(talkers) {
  if (!talkers.length) return "";
  const peak = Math.max(...talkers.map(t => t.bytes), 1);
  return `<div class="bars">` + talkers.map(t => `
    <div class="brow">
      <div class="bname mono">${escHost(t.host)}</div>
      <div class="btrack"><div class="bfill" style="width:${Math.max((t.bytes / peak) * 100, 1.5)}%"></div></div>
      <div class="bval">${shortBytes(t.bytes)}</div>
    </div>`).join("") + `</div>`;
}
