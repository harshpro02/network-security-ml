const $ = (id) => document.getElementById(id);
const esc = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
const bytes = shortBytes;
const PROTO = { 1: "ICMP", 6: "TCP", 17: "UDP" };
const titles = {
  overview: [
    "See the whole picture.",
    "Follow the traffic. Understand the signal.",
  ],
  behaviour: [
    "Find the pattern.",
    "Context across connections, separate from model verdicts.",
  ],
  connections: [
    "Follow every connection.",
    "Search the evidence. Inspect the features.",
  ],
  devices: [
    "Know what was visible.",
    "Passive device observations from the selected capture.",
  ],
  how: [
    "Look under the hood.",
    "The decisions, evidence and limitations behind Guardian.",
  ],
};
let analysis = null,
  busy = false,
  liveAvailable = false,
  demoAvailable = false,
  playbackTimer = null,
  activeView = "overview";
let returnFocus = null;

function show(view) {
  activeView = view;
  document.querySelectorAll(".tab").forEach((tab) => {
    tab.classList.toggle("on", tab.dataset.view === view);
    if (tab.dataset.view === view) tab.setAttribute("aria-current", "page");
    else tab.removeAttribute("aria-current");
  });
  document
    .querySelectorAll(".view")
    .forEach((panel) => panel.classList.toggle("on", panel.id === `v-${view}`));
  $("view-name").textContent =
    view === "how" ? "Behind the model" : view[0].toUpperCase() + view.slice(1);
  $("page-title").textContent = titles[view][0];
  $("page-subtitle").textContent = titles[view][1];
}
document
  .querySelectorAll(".tab")
  .forEach((tab) =>
    tab.addEventListener("click", () => show(tab.dataset.view)),
  );
$("learn-link").onclick = () => show("how");
$("summary-link").onclick = () => show("connections");
$("behaviour-link").onclick = () => show("behaviour");

function stopPlayback() {
  clearInterval(playbackTimer);
  playbackTimer = null;
  $("play").textContent = "▶";
  $("play").setAttribute("aria-label", "Play capture visualization");
}
function drawCapture() {
  if (!analysis) return;
  const points = analysis.points || [];
  const end = points.reduce((max, p) => Math.max(max, p[0]), 0);
  const fraction = Number($("scrubber").value) / 100;
  const shown = points.filter((p) => p[0] <= end * fraction);
  $("map").classList.remove("chart-empty");
  $("map").innerHTML = shown.length
    ? portMap(shown, end, points)
    : '<p class="empty">No connections at this visualization position.</p>';
  $("map-count").textContent =
    `${shown.length.toLocaleString()} / ${points.length.toLocaleString()} flows`;
  $("play-time").textContent = `${niceTime(end * fraction)} / ${niceTime(end)}`;
}
$("scrubber").oninput = () => {
  stopPlayback();
  drawCapture();
};
$("play").onclick = () => {
  if (playbackTimer) {
    stopPlayback();
    return;
  }
  if (Number($("scrubber").value) >= 100) $("scrubber").value = 0;
  drawCapture();
  $("play").textContent = "Ⅱ";
  $("play").setAttribute("aria-label", "Pause capture visualization");
  playbackTimer = setInterval(() => {
    $("scrubber").value = Math.min(100, Number($("scrubber").value) + 1);
    drawCapture();
    if (Number($("scrubber").value) >= 100) stopPlayback();
  }, 100);
};

function renderFlows() {
  if (!analysis) return;
  const query = $("flow-search").value.trim().toLowerCase();
  const verdict = $("verdict-filter").value,
    protocol = $("protocol-filter").value;
  const rows = (analysis.flows || [])
    .map((flow, index) => ({ flow, index }))
    .filter(
      ({ flow: f }) =>
        (verdict === "all" || f.is_threat === (verdict === "attack")) &&
        (protocol === "all" || String(f.protocol) === protocol) &&
        `${f.source}:${f.src_port} ${f.destination}:${f.dst_port} ${f.verdict} ${f.attack_type || ""} ${PROTO[f.protocol] || ""}`
          .toLowerCase()
          .includes(query),
    );
  const sort = $("flow-sort").value;
  rows.sort((a, b) =>
    sort === "packets"
      ? b.flow.packets - a.flow.packets
      : sort === "time"
        ? a.flow.started_at - b.flow.started_at
        : sort === "port"
          ? a.flow.dst_port - b.flow.dst_port
          : Number(b.flow.is_threat) - Number(a.flow.is_threat) ||
            b.flow.packets - a.flow.packets,
  );
  $("flow-scope").textContent =
    `${rows.length.toLocaleString()} matching of ${(analysis.flows || []).length.toLocaleString()} returned flows · ${analysis.flow_count.toLocaleString()} total scored. Filters apply to the returned subset only; charts cover the full capture.`;
  $("flows").innerHTML = rows.length
    ? `<table><thead><tr><th>Source / port</th><th>Destination / port</th><th>Protocol</th><th class="n">Fwd packets</th><th class="n">Payload</th><th class="n">Duration</th><th>Model verdict</th><th><span class="sr-only">Details</span></th></tr></thead><tbody>${rows.map(({ flow: f, index }) => `<tr class="${f.is_threat ? "hi" : ""}"><td class="mono">${esc(f.source)}:${f.src_port}</td><td class="mono">${esc(f.destination)}:${f.dst_port}</td><td>${PROTO[f.protocol] || `IP/${f.protocol}`}</td><td class="n">${f.packets.toLocaleString()}</td><td class="n">${bytes(f.bytes)}</td><td class="n">${f.duration_sec.toFixed(3)}s</td><td><span class="vtag ${f.is_threat ? "bad" : ""}"><i></i>${esc(f.attack_type || (f.is_threat ? "Attack" : "Benign"))}</span></td><td><button class="inspect-flow" data-index="${index}" aria-label="Inspect connection to ${esc(f.destination)} port ${f.dst_port}">Inspect ↗</button></td></tr>`).join("")}</tbody></table>`
    : '<p class="empty">No returned connections match these filters. Try a different address, protocol or verdict.</p>';
}
["flow-search", "verdict-filter", "protocol-filter", "flow-sort"].forEach(
  (id) =>
    $(id).addEventListener(
      id === "flow-search" ? "input" : "change",
      renderFlows,
    ),
);
$("flows").addEventListener("click", (event) => {
  const button = event.target.closest(".inspect-flow");
  if (!button || !analysis) return;
  const f = analysis.flows[Number(button.dataset.index)];
  returnFocus = button;
  $("flow-title").textContent =
    f.attack_type ||
    (f.is_threat
      ? "Flagged by the flow model"
      : "Rated benign by the flow model");
  $("flow-detail").innerHTML =
    `<div class="flow-route">${esc(f.source)}:${f.src_port} → ${esc(f.destination)}:${f.dst_port} / ${PROTO[f.protocol] || f.protocol}</div><dl class="feature-list"><div><dt>Duration</dt><dd>${f.duration_sec.toFixed(3)} s</dd></div><div><dt>Forward packet count</dt><dd>${f.packets.toLocaleString()}</dd></div><div><dt>Forward payload bytes</dt><dd>${f.bytes.toLocaleString()} B</dd></div><div><dt>Average packet size</dt><dd>${f.avg_packet_size} B</dd></div></dl><p class="dialog-note">These are the four inputs used by the model. Average packet size includes both directions; packet count and payload bytes describe the opening direction. This interface does not provide feature attribution or a probability score.</p><p class="dialog-note">Started ${niceTime(f.started_at)} into the capture. A benign model verdict does not rule out participation in a behaviour alert.</p>`;
  $("flow-dialog").showModal();
});
$("close-flow").onclick = () => $("flow-dialog").close();
$("flow-dialog").addEventListener("close", () => returnFocus?.focus());

function render(data) {
  analysis = data;
  stopPlayback();
  const total = data.flow_count,
    bad = data.threat_count,
    alerts = data.alerts || [],
    points = data.points || [];
  const scan = alerts.find((alert) => alert.kind === "port_scan");
  const ports = new Set(points.map((p) => p[1])).size;
  const sources = {
    demo: "Recorded port scan",
    upload: "Uploaded capture",
    live: "Local network capture",
  };
  $("capture-name").textContent = sources[data.source] || "Capture analysis";
  $("capture-meta").textContent =
    `Analysis completed ${new Date().toLocaleTimeString("en-CA", { hour: "2-digit", minute: "2-digit" })} · ${data.packets_read.toLocaleString()} packets · ${data.source === "live" ? "Completed capture, not continuous monitoring" : "Recorded data, not live traffic"}`;
  $("footer-source").textContent =
    `${sources[data.source] || "Capture"} · Full-capture detection totals`;
  $("summary-kicker").textContent =
    alerts.length || bad ? "SIGNALS TO INVESTIGATE" : "ANALYSIS COMPLETE";
  $("hero-figure").textContent = ports.toLocaleString();
  $("hero-label").textContent = "distinct destination ports";
  $("hero-title").textContent = scan
    ? "The pattern tells the story."
    : alerts.length || bad
      ? "A closer look starts here."
      : "No flags in this capture.";
  $("hero-text").textContent = scan
    ? `${scan.source} contacted ${scan.count.toLocaleString()} distinct ports on ${scan.target} within a ${scan.window_seconds}-second window. The model flagged ${bad.toLocaleString()} of ${total.toLocaleString()} flows; the behaviour rules identified the wider scan pattern.`
    : `${total.toLocaleString()} conversations scored. ${bad.toLocaleString()} model flags and ${alerts.length} behaviour alerts. These are detector observations, not a guarantee that traffic is safe or malicious.`;
  $("facts").innerHTML = [
    ["Conversations", total, "Bidirectional flows", ""],
    ["Model flags", bad, "Individual flow verdicts", "flag"],
    ["Behaviour alerts", alerts.length, "Patterns across flows", "pattern"],
    ["Packets read", data.packets_read, "From the selected capture", ""],
  ]
    .map(
      ([label, value, note, style]) =>
        `<div class="metric ${style}"><span>${label}</span><strong>${value.toLocaleString()}</strong><small>${note}</small></div>`,
    )
    .join("");
  $("layer-model").textContent = bad;
  $("layer-behaviour").textContent = alerts.length;
  $("layer-insight").innerHTML =
    `<span>SEPARATE SIGNALS, SHARED CONTEXT</span><p>${scan ? "The model sees individual flows. The behaviour rules see a scan across them. Rules count raw packet destinations; the chart counts scored bidirectional flows, so port counts can differ." : "Model verdicts describe individual flows. Behaviour alerts describe groups of observations. Neither establishes intent on its own."}</p>`;
  $("n-flow").textContent = total.toLocaleString();
  $("n-alert").textContent = alerts.length || "";
  $("n-dev").textContent = data.device_count || "";
  $("conn-count").textContent = `${total.toLocaleString()} scored`;
  $("beh-count").textContent = `${alerts.length} alerts`;
  $("dev-count").textContent = `${data.device_count || 0} observed`;
  $("alerts").innerHTML = alertRecords(alerts);
  document.querySelectorAll("#alerts .rec").forEach((record, index) => {
    const source = alerts[index].source;
    if (!source) return;
    const button = document.createElement("button");
    button.className = "text-link";
    button.textContent = "Find returned flows from this source ↗";
    button.onclick = () => {
      $("flow-search").value = source;
      $("verdict-filter").value = "all";
      $("protocol-filter").value = "all";
      renderFlows();
      show("connections");
    };
    record.lastElementChild.append(button);
  });
  $("devices").innerHTML = deviceList(data.devices || []);
  $("timeline").innerHTML = points.length
    ? timeline(points)
    : '<p class="empty">No scored connections in this capture.</p>';
  $("talkers").innerHTML = data.talkers?.length
    ? talkerBars(data.talkers)
    : '<p class="empty">No destination volume recorded.</p>';
  $("scrubber").value = 100;
  $("scrubber").disabled = !points.length;
  $("play").disabled = !points.length;
  $("export").disabled = false;
  renderFlows();
  drawCapture();
  show(activeView);
  window.dispatchEvent(new CustomEvent("guardian-analysis", { detail: data }));
}

function syncButtons() {
  $("btn-demo").disabled = busy || !demoAvailable;
  $("btn-scan").disabled = busy || !liveAvailable;
  $("btn-upload").disabled = busy;
}
async function call(id, url, options = {}, message = "Analysing capture…") {
  if (busy) return;
  busy = true;
  stopPlayback();
  syncButtons();
  $(id).classList.add("busy");
  $("msg").classList.remove("error");
  $("msg").textContent = message;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 120000);
  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok)
      throw new Error(data.detail || `Analysis failed (${response.status}).`);
    if (!Array.isArray(data.flows) || !Array.isArray(data.points))
      throw new Error("The server returned an invalid analysis.");
    render(data);
    $("msg").textContent =
      `Analysis complete · ${data.threat_count} model flags · ${data.alert_count} behaviour alerts. Explore both layers before drawing conclusions.`;
  } catch (error) {
    window.dispatchEvent(
      new CustomEvent("guardian-analysis-error", { detail: error.message }),
    );
    $("msg").classList.add("error");
    $("msg").textContent =
      `${error.name === "AbortError" ? "Analysis timed out. A sleeping host may need a moment; try again." : error.message}${analysis ? " Previous analysis is still displayed." : ""}`;
  } finally {
    clearTimeout(timeout);
    busy = false;
    $(id).classList.remove("busy");
    syncButtons();
  }
}
$("btn-demo").onclick = () =>
  call(
    "btn-demo",
    "/api/demo",
    {},
    "Scoring the bundled recording. This does not scan a network.",
  );
$("btn-scan").onclick = () =>
  call(
    "btn-scan",
    "/api/scan",
    {},
    "Listening on the local host. Results appear when the capture finishes.",
  );
$("btn-upload").onclick = () => $("file").click();
function upload(file) {
  if (!file || busy) return;
  if (
    !/\.pcap(ng)?$/i.test(file.name) ||
    file.size > 10 * 1024 * 1024 ||
    !file.size
  ) {
    $("msg").classList.add("error");
    $("msg").textContent =
      "Choose a non-empty .pcap or .pcapng file up to 10 MB.";
    return;
  }
  const form = new FormData();
  form.append("file", file);
  call(
    "btn-upload",
    "/api/analyze",
    { method: "POST", body: form },
    `Analysing ${file.name}…`,
  );
}
$("file").onchange = (event) => {
  upload(event.target.files[0]);
  event.target.value = "";
};
let dragDepth = 0;
window.addEventListener("dragenter", (event) => {
  if (event.dataTransfer?.types.includes("Files")) {
    event.preventDefault();
    dragDepth++;
    $("upload-drop").hidden = false;
  }
});
window.addEventListener("dragover", (event) => {
  if (event.dataTransfer?.types.includes("Files")) event.preventDefault();
});
window.addEventListener("dragleave", () => {
  dragDepth = Math.max(0, dragDepth - 1);
  if (!dragDepth) $("upload-drop").hidden = true;
});
window.addEventListener("drop", (event) => {
  if (!event.dataTransfer?.files.length) return;
  event.preventDefault();
  dragDepth = 0;
  $("upload-drop").hidden = true;
  upload(event.dataTransfer.files[0]);
});
$("export").onclick = () => {
  if (!analysis) return;
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(analysis, null, 2)], { type: "application/json" }),
  );
  const link = document.createElement("a");
  link.href = url;
  link.download = `guardian-${analysis.source}-analysis.json`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
};
fetch("/api/health", { signal: AbortSignal.timeout(15000) })
  .then(async (response) => {
    if (!response.ok) throw new Error("Host unavailable");
    return response.json();
  })
  .then((health) => {
    liveAvailable = health.live_capture;
    demoAvailable = health.demo_available;
    $("mode").textContent = liveAvailable
      ? "LOCAL CAPTURE AVAILABLE"
      : "REPLAY + UPLOAD HOST";
    $("btn-scan").title = liveAvailable
      ? "Capture traffic visible to this local host"
      : "Local capture is disabled on this host. Replay and upload remain available.";
    syncButtons();
  })
  .catch(() => {
    $("mode").textContent = "HOST UNREACHABLE";
    demoAvailable = true;
    syncButtons();
    $("msg").textContent =
      "Could not reach the host. Run demo to retry; a sleeping host may need time to wake.";
  });
