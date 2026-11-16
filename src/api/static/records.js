function alertRecords(alerts) {
  if (!alerts.length) {
    return `<p class="empty">No cross-flow rules triggered in this capture. A port scan, a
      sweep of the network, a device that has never been here before, or software checking in on
      a fixed timer would all be listed here.</p>`;
  }
  return alerts
    .map((a) => {
      let kind, title, body;
      if (a.kind === "beacon") {
        kind = "Beacon";
        title = `A regular connection pattern reaches ${esc(a.target)} on a timer.`;
        body = `It connected <b>${a.count}</b> times, once every <b>${a.interval_seconds} seconds</b>,
        varying by only ${(a.jitter * 100).toFixed(0)}%. Regular intervals can come from legitimate telemetry, update checks or unwanted software. This is a pattern observation, not a malware verdict.`;
      } else if (a.kind === "host_sweep") {
        kind = "Host sweep";
        title = `${esc(a.source)} contacted many destinations.`;
        body = `It contacted <b>${a.count.toLocaleString()} different devices</b> in ${a.window_seconds}
        seconds, meeting the host-sweep rule threshold. Legitimate discovery tools can also produce this pattern.`;
      } else if (a.kind === "new_device") {
        kind = "New device";
        title = `${esc(a.vendor || "An unrecognised device")} was not in the previous device observations.`;
        body = `It was seen at <b>${esc(a.source)}</b> and was absent from the saved device baseline.
        On a home network that is usually a phone or a visitor. It is worth a look when it is not.`;
      } else {
        kind = "Port scan";
        title = `${esc(a.source)} triggered the port-scan rule for ${esc(a.target)}.`;
        body = `It reached <b>${a.count.toLocaleString()} different ports</b> in ${a.window_seconds}
        seconds. The rule triggers at 20 distinct ports per source/target in a fixed 60-second bucket. This can include authorised scanning and does not establish intent.`;
      }
      return `<div class="rec"><div class="kind">${kind}</div>
      <div><h3>${title}</h3><p>${body}</p></div></div>`;
    })
    .join("");
}

function deviceList(devices) {
  if (!devices.length) {
    return `<p class="empty">No devices seen. Only devices visible in the selected capture can appear here.</p>`;
  }
  return devices
    .map((d) => {
      const name = d.hostname || d.vendor || "Unrecognised device";
      const ip = d.ips[0] || "no address seen";
      const chips = [
        d.role === "gateway" ? `<span class="chip solid">Router</span>` : "",
        d.randomised_mac ? `<span class="chip">Randomised MAC</span>` : "",
      ].join("");
      return `<div class="dev">
      <div><div class="name">${esc(name)}${chips}</div>
        <div class="meta">${esc(ip)} &nbsp;&middot;&nbsp; ${esc(d.mac)}</div></div>
      <div class="right"><div class="amt">${bytes(d.bytes)}</div>
        <div class="amtk">${d.packets.toLocaleString()} packets</div></div>
    </div>`;
    })
    .join("");
}
