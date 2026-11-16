let storyStep = 0;
let storyData = null;
let storyLoading = false;
function openGuardianDashboard() {
  document.body.classList.remove("beginner-mode");
  window.scrollTo(0, 0);
  $("main").focus();
}
$("story-dashboard").onclick = openGuardianDashboard;
$("story-details").onclick = openGuardianDashboard;
$("simple-view").onclick = () => {
  document.body.classList.add("beginner-mode");
  window.scrollTo(0, 0);
};
function drawStoryDoors(ports, many = false) {
  $("story-doors").classList.toggle("many-doors", many);
  $("story-doors").replaceChildren();
  ports.forEach((port, index) => {
    const door = document.createElement("div");
    door.className = "digital-door";
    door.style.setProperty("--delay", `${index * 25}ms`);
    const icon = document.createElement("span");
    icon.textContent = "▯";
    const label = document.createElement("small");
    label.textContent = port === null ? "A port" : `Port ${port}`;
    door.append(icon, label);
    $("story-doors").append(door);
  });
}
function updateGuardianStory() {
  document
    .querySelectorAll(".story-steps>span")
    .forEach((step, index) =>
      step.classList.toggle("active", index === Math.max(0, storyStep - 1)),
    );
  const data = storyData;
  if (!data) {
    drawStoryDoors([null]);
    return;
  }
  const scan = (data.alerts || []).find((alert) => alert.kind === "port_scan");
  const ordinary = data.flows.find((flow) => !flow.is_threat) || data.flows[0];
  const ports = [...new Set(data.points.map((point) => point[1]))];
  $("story-source").textContent =
    scan?.source || ordinary?.source || "Observed computer";
  if (storyStep === 1) {
    drawStoryDoors(ordinary ? [ordinary.dst_port] : []);
    $("story-kicker").textContent = "01 / LOOK AT ONE CONNECTION";
    $("story-title").textContent =
      ordinary && !ordinary.is_threat
        ? "This one looked ordinary."
        : "Start with one small conversation.";
    $("story-text").textContent = ordinary
      ? `A computer contacted port ${ordinary.dst_port}. The check that looks at individual connections treated this one as ${ordinary.is_threat ? "similar to a known attack" : "ordinary"}. Now see what changes when we look at many connections together.`
      : "No scored connections were found in this recording.";
    $("story-evidence").textContent = ordinary
      ? `Real recording · ${ordinary.packets} forward packets · ${ordinary.duration_sec.toFixed(3)} seconds`
      : "No connection evidence available.";
    $("story-next").textContent = "Now reveal the bigger picture →";
    $("story-visual-note").textContent =
      "This is one actual conversation from the recording.";
  } else if (storyStep === 2) {
    drawStoryDoors(ports.slice(0, 24), true);
    $("story-kicker").textContent = "02 / CONNECT THE DOTS";
    $("story-title").textContent = scan
      ? "One knock? Ordinary. Hundreds? A pattern."
      : "The wider view adds context.";
    $("story-text").textContent = scan
      ? `Across the recording, a behaviour rule found ${scan.source} contacting ${scan.count.toLocaleString()} different ports on ${scan.target} in a ${scan.window_seconds}-second window. That repeated checking triggered the port-scan rule.`
      : `Guardian compared ${data.flow_count.toLocaleString()} conversations and found ${data.alert_count} behaviour alerts. These rules look for repetition across connections.`;
    $("story-evidence").textContent =
      `${data.alert_count} wider-pattern alerts · Detected across the recording`;
    $("story-visual-note").textContent =
      `Showing ${Math.min(24, ports.length)} example destination ports from the scored conversations, not every packet destination.`;
    $("story-next").textContent = "See what each detector found →";
  } else {
    drawStoryDoors(ports.slice(0, 24), true);
    $("story-kicker").textContent = "03 / THE TWO LAYERS";
    $("story-title").textContent = scan
      ? "The pattern was the warning sign."
      : "Two checks. A clearer explanation.";
    $("story-text").textContent =
      `Checking connections one at a time flagged ${data.threat_count}. Looking across connections revealed ${data.alert_count} wider patterns. ${scan ? "Here, the repeated door-checking was the warning sign." : "Both checks help explain what stood out in this recording."}`;
    $("story-evidence").textContent =
      "A scan is a warning to investigate, not proof of a break-in. Legitimate security tools can scan too.";
    $("story-next").textContent = "Explore the real evidence ↗";
    $("story-takeaway").hidden = false;
    $("story-takeaway").replaceChildren();
    for (const [value, label] of [
      [data.flow_count.toLocaleString(), "connections checked"],
      [data.threat_count, "flagged individually"],
      [data.alert_count, "wider patterns found"],
    ]) {
      const card = document.createElement("div");
      const strong = document.createElement("strong");
      strong.textContent = value;
      const text = document.createElement("span");
      text.textContent = label;
      card.append(strong, text);
      $("story-takeaway").append(card);
    }
  }
}
$("story-next").onclick = async () => {
  if (storyLoading) return;
  if (!storyData) {
    storyLoading = true;
    $("story-next").disabled = true;
    $("story-message").textContent = "Connecting to the detector…";
    await healthReady;
    if ($("btn-demo").disabled) {
      storyLoading = false;
      $("story-next").disabled = false;
      $("story-message").textContent =
        "The recording is not available on this host right now. Please try again shortly.";
      return;
    }
    $("story-message").textContent =
      "Reading and scoring the bundled recording…";
    $("btn-demo").click();
  } else if (storyStep >= 3) openGuardianDashboard();
  else {
    storyStep++;
    updateGuardianStory();
  }
};
window.addEventListener("guardian-analysis", (event) => {
  storyData = event.detail;
  storyStep = 1;
  storyLoading = false;
  $("story-next").disabled = false;
  $("story-message").textContent =
    "Recorded data, not a live scan. Every number comes from this analysis.";
  $("story-takeaway").hidden = true;
  updateGuardianStory();
});
window.addEventListener("guardian-analysis-error", (event) => {
  storyLoading = false;
  $("story-next").disabled = false;
  $("story-message").textContent =
    `Could not load the recording: ${event.detail}. Try again.`;
});
updateGuardianStory();
