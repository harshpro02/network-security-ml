# Dashboard review, November 16, 2026

Implemented a responsive investigation dashboard using the existing FastAPI endpoints, model and behavioural rules. Extracted the stylesheet and browser logic from the original inline page. No training, model weights or detection thresholds changed.

Local preview: http://127.0.0.1:8010. The preview was launched with ALLOW_LIVE_CAPTURE=0, so it uses replay/upload and does not listen to the user's network. The regular startup command and hosted Render setting remain unchanged.

## Checked

- 86 Python tests passed. An existing Starlette/httpx deprecation warning remains.
- Browser validation used the actual bundled PCAP through both replay and upload, not fabricated analysis responses.
- Confirmed 1,029 scored flows, two model flags and one behavioural alert for the bundled recording. The rule's raw-packet destination-port count differs from the chart's scored bidirectional-flow count; the interface and README explain this distinction.
- Search, verdict filters, protocol filters and sorting operate on at most 200 returned flows. Overview charts include all scored flow points.
- Inspected the four-feature dialog, Escape/focus restoration, behaviour-to-flow navigation, model methodology and JSON download.
- Replay scrubber uses fixed time/port scales and updates only the visualization, not detection totals. Play/pause is user-controlled.
- Invalid upload is rejected. A simulated 503 preserves the previous analysis with an explicit message.
- Desktop and 390-pixel mobile checks passed with no JavaScript page errors. All five views fit at 390, 768 and 1024 pixels after constraining a hidden accessibility label to the scrolling table. Inspected desktop/mobile screenshots. Protocol filtering, port sorting and empty-capture playback states also passed.

## Boundaries

Model verdicts and behavioural observations remain separate. The page does not invent probabilities, feature attribution, continuous live monitoring, devices absent from capture evidence, or production deployment. Existing packet-capture and model limitations still apply. Screenshot records come from the bundled recording; data is loaded only after a user action.

## Plain-language entry, November 16

The default experience is now a three-step visual story: one ordinary-looking connection, a wider scan pattern, and the two detector results. The sampled port doors and displayed outcomes are derived from the actual bundled analysis; the animation illustrates a recording rather than live probing. Definitions and the full dashboard are available on demand. The computer/door drawing is a conceptual illustration, not a discovered network topology.

Browser checks passed the complete story, actual replay, step outcomes, glossary/navigation, return to simple view and mobile fit. Repeated the original full-dashboard smoke checks after introducing the entry screen; they passed with no page errors. Existing backend/model tests from the prior implementation remain applicable; no backend/model code changed.
