# Network Security ML

ML-based network intrusion detection system that captures live network packets and uses machine learning to detect security threats in real time.

## Status

Week 1 Day 1 complete.

## What works

- Live packet capture from network interface using Scapy
- Packet storage in PCAP format
- Feature extraction to CSV (IPs, ports, protocol, size, TCP flags)

## Project Structure

network-security-ml/
src/
  packet_capture/
    sniffer.py       Captures live packets
    reader.py        Reads saved PCAP files
    extractor.py     Extracts features to CSV
data/
  raw/
    capture_001.pcap   100 captured packets
    features_001.csv   50 extracted feature rows

## Tech Stack

- Python 3.10
- Scapy for packet capture
- Pandas for data processing

## Next Steps

- Week 2: Download CICIDS2017 dataset, expand feature engineering
- Week 3: Train Random Forest classifier
- Week 4: Build FastAPI real time pipeline
- Week 5: React dashboard
- Week 6: Docker deployment

## Built By

Harsh Shah | CS Network Engineering | Sheridan College