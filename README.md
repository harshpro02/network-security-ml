# Guardian — ML Network Intrusion Detection

Captures live network packets, groups them into flows, and scores each flow with a
random forest trained on CICIDS2017. Runs as a local tool with a web dashboard.

<!-- TODO: replace once deployed -->
**Live demo:** _not deployed yet_ · **Demo video:** _not recorded yet_

---

## What it does

Three ways to get traffic in, one detection path out:

| Mode | Endpoint | Needs admin? | Runs in the cloud? |
|---|---|---|---|
| Live capture | `GET /api/scan` | yes | no |
| Upload a PCAP | `POST /api/analyze` | no | yes |
| Replay a recording | `GET /api/demo` | no | yes |

Live capture is the point of the tool. It is also the reason a hosted version can only
do so much — a cloud server has no meaningful traffic of its own to watch. The hosted
build serves upload and replay, and says so on the page. Clone the repo to run live.

## How it works

```
packets  ──►  flow table  ──►  4 features  ──►  binary detector  ──►  verdict
(scapy)       (120s expiry,     duration        BENIGN / ATTACK
               FIN/RST)         packet count
                                total bytes     ──►  type classifier  ──►  attack name
                                avg pkt size         (precision-gated)
```

Two models, because one could not do both jobs honestly:

- **`live_detector.joblib`** decides BENIGN vs ATTACK. This is the verdict.
- **`live_classifier.joblib`** names the attack type — but only for classes it was
  measured to be precise on. The reliable list is computed at training time from the
  test set and saved alongside the model, so serving cannot drift from what was
  measured. Everything else reports as a generic threat.

## Results

All figures are on a held-out 20% of a 500,000-row sample.

**Live detector — 4 features, this is what runs**

| | precision | recall | f1 |
|---|---|---|---|
| ATTACK | 0.926 | 0.980 | 0.953 |
| BENIGN | 0.995 | 0.981 | 0.988 |

Accuracy **0.9809**, macro-F1 **0.9704**, 3.1 MB.

**Attack types reported by name** (precision ≥ 0.80 on the test set)

| type | precision |
|---|---|
| DDoS | 0.996 |
| PortScan | 0.990 |
| DoS slowloris | 0.984 |
| FTP-Patator | 0.958 |
| DoS Slowhttptest | 0.932 |
| DoS Hulk | 0.834 |

Bot, SSH-Patator, Heartbleed, Infiltration and the web attacks all scored below 0.08
precision on these four features. They are detected as generic threats, never named.

**Offline model — all 78 features, not deployed**

Accuracy **0.9981**, macro-F1 0.9015. Kept for reference only. Most of its features
come from CICFlowMeter and cannot be computed from raw packets in real time, and at
52 MB it does not belong in a repo.

## Design decisions

**The train–serve mismatch.** The first live model was fed the 78-feature vector with
zeros in every slot that could not be measured live. It produced confident nonsense.
The fix was to retrain on only the four features that are genuinely computable from a
packet stream, and accept the lower ceiling that comes with them.

**Binary verdict, gated type naming.** A 15-class model on four features looks fine on
accuracy (0.926) and falls apart on precision — Bot scored 0.036, meaning roughly 27
false alarms for every true one. Splitting the verdict from the naming, and only
naming classes that clear a measured threshold, took macro-F1 from 0.56 to 0.97.

**The minimum-packet floor.** Flows shorter than 5 packets were skipped. Checked
against the training data, that floor was discarding 62% of all attack traffic and
99.9% of PortScan — the single class the model is best at. Lowering it to 1 recovered
that and produced one extra false positive across 1,000 packets of real benign
capture.

**Flow expiry.** CICFlowMeter closes a flow after 120 seconds or on FIN/RST. The live
bridge originally never closed flows at all, so a long conversation grew into one
enormous flow that looked like nothing in the training set. `FlowTable` now matches
CICFlowMeter's rules.

**Payload bytes, not frame bytes.** Found by running a real scan through the pipeline —
see the section below. Every flow's size was being overstated by a header's worth.

## What happened when it met a real attack

The numbers above all come from CICIDS2017 rows. `scripts/record_demo.py` runs a real
1,024-port TCP connect scan against loopback, captures it with the project's own code,
and scores it. That is the only test that exercises the whole pipeline end to end.

**It caught 3 of 2,050 scan flows.**

Chasing that down found a third train–serve mismatch, and the most subtle one. Median
values for a single scanned port:

| | our capture | CICIDS2017 PortScan | CICIDS2017 BENIGN |
|---|---|---|---|
| total bytes | 56 | 0 | 66 |
| avg packet size | 48 | 3 | 74.25 |

`flow_to_features` measured `len(packet)` — the whole frame, headers included.
CICFlowMeter counted transport payload only, which is why a bare SYN is recorded as
0 bytes there. Every small flow was being inflated by roughly a header, landing our
scan traffic on top of the benign cluster instead of the PortScan cluster.

Switching to payload bytes is definitionally correct and measurably better: detections
went 0 → 3, the two named ones came back as `PortScan`, and false positives on real
benign captures went down, not up.

But 3 out of 2,050 is still a failure, and the reason is structural. A single SYN to a
closed port is four numbers: near-zero duration, one packet, zero bytes, zero average.
A single benign packet looks the same. **Nothing in a per-flow feature vector can
separate them.** What identifies a port scan is that one host touched a thousand ports
in a minute — a property of the set of flows, not of any flow in it.

So the honest claim for this project is narrower than "intrusion detection." It detects
the volume- and duration-shaped attacks in CICIDS2017. It does not detect port scans in
the field, whatever the 0.99 test-set precision on `PortScan` suggests.

## Known limitations

Worth stating plainly, because they are real.

- **The accuracy figures are optimistic.** The split is random, and CICIDS2017 attack
  flows arrive in bursts of near-identical records, so near-duplicates land on both
  sides. A day-held-out split would be the honest test and is not done yet.
- **Test-set precision does not survive contact with live traffic.** See above: 0.99 on
  held-out `PortScan` rows, 3/2050 on a scan this code captured itself.
- **No cross-flow context.** Detecting scans, sweeps or beaconing needs features over a
  group of flows (distinct ports per source per minute). Everything here is per-flow.
- **Four features is a low ceiling.** Many more are computable from raw packets —
  destination port, packet-length statistics, inter-arrival times, TCP flag counts.
  Destination port alone would likely fix the FTP-Patator and SSH-Patator confusion.
- **Flows are directional.** `A→B` and `B→A` are scored separately. Real IDS tooling
  treats a conversation as one bidirectional flow.

## Running it

```bash
git clone <repo-url> && cd network-security-ml
python -m venv venv && venv\Scripts\activate      # Windows
pip install -r requirements.txt

uvicorn src.api.main:app --reload                  # then open http://127.0.0.1:8000
```

Live capture needs administrator privileges and [Npcap](https://npcap.com/).
Without them, upload and replay still work.

**Record a demo capture** (runs a port scan against your own machine, then captures it):

```bash
python scripts/record_demo.py        # from an Administrator terminal
```

**Retrain** (needs `data/processed/clean_for_training.csv`, not in the repo):

```bash
python src/model/train_live.py
```

## Tests

```bash
python -m pytest tests/ -q           # 29 tests
```

Covers flow keying, the 120-second expiry, FIN/RST teardown, feature arithmetic, and
upload validation — including that a malformed capture returns 400 without leaking
parser internals.

## Docker

```bash
docker build -t guardian .
docker run -p 8000:8000 guardian
```

Live capture is disabled in the image (`ALLOW_LIVE_CAPTURE=0`), since a container has
no interface worth watching. The API returns a clear 503 rather than a permission
error.

## Layout

```
src/
  api/main.py            FastAPI app, three endpoints, upload validation
  api/static/index.html  dashboard
  model/live_bridge.py   FlowTable, feature extraction, scoring
  model/train_live.py    trains both live models
  model/train.py         trains the 78-feature reference model
  dataset/               CICIDS2017 cleaning and combining
  packet_capture/        sniffer, PCAP reader, feature extractor
scripts/record_demo.py   records a real port scan for the demo
tests/                   pytest suite
models/                  the two live models (6.9 MB, committed)
```

## Data

[CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html), Canadian Institute for
Cybersecurity, University of New Brunswick. 2.8M flows across five days of traffic.
Not committed — download it separately.

## Built by

Harsh Shah · CS Network Engineering · Sheridan College
