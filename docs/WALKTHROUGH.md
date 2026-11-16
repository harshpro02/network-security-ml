# Guardian: two-minute walkthrough

Open https://guardian-dty5.onrender.com. Keep a local replay ready if the free host is waking. Speak from the actual displayed result, not a memorised score if the recording changes.

## 0:00-0:20: problem

“Guardian helps explain warning signs in network traffic. My main question was whether a machine-learning model could recognise an attack from the traffic I could actually capture, rather than only perform well on a prepared dataset.”

## 0:20-1:05: demonstrate

Choose Watch the recorded scan, then follow the three steps.

“This is a real recorded port scan, replayed through the detector. It does not scan the visitor's network. One short conversation looks ordinary. The model flagged only two of the 1,029 scored conversations in this recording. Looking across the traffic revealed repeated checks of many ports, so the behaviour layer raised a scan alert. These are different kinds of evidence, and the interface keeps them separate.”

Open the full dashboard, choose Connections, filter Model flags and inspect one flow.

“Here are the actual four model inputs: duration, forward packet count, forward payload bytes and average packet size. I expose the inputs rather than invent a confidence percentage.”

## 1:05-1:40: engineering decision

“The difficult part was matching capture definitions to training definitions. Counting frame headers instead of payload, splitting both directions into separate flows and discarding short flows distorted the inputs. Fixing those mismatches improved the implementation, but did not solve the model's underlying blind spot. A scan is a pattern across connections, so I added a second layer instead of pretending every small flow was identifiable as an attack.”

## 1:40-2:00: limitation and next evidence

“This is an experimental detector, not proof that a network is safe or compromised. CICIDS2017 results do not establish performance on new traffic. Authorised scanners and periodic software can trigger behaviour rules too. My next evaluation would use independently collected traffic and report false positives as well as detections.”

## Questions to practise

- Why are the scan rule's raw destination-port counts different from scored bidirectional-flow counts?
- What changes between random train/test splitting and holding out an entire day?
- Why does the hosted service support recording replay and upload rather than capturing a visitor's WiFi?

If you cannot answer one, trace that part of the implementation before presenting it.
