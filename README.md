# icmp-ids-ips-soc-triage
A lightweight Intrusion Detection and Prevention System (IDS/IPS) that monitors incoming ICMP traffic, detects ping flood attacks, and automatically blocks source IPs exceeding a threshold of 40 ping requests. Features real-time packet monitoring, automated firewall-based blocking, logging, and configurable detection for enhanced network security.

# Network Intrusion Detection System (IDS)

A Python-based Intrusion Detection System (IDS) that monitors ICMP (Ping) traffic, detects suspicious network activity, and generates structured alerts for SOC (Security Operations Center) analysis.

> **Note:** This project focuses on intrusion detection and alert generation. It does not automatically block network traffic.

## Features

- Captures network traffic using Tshark
- Detects high-volume ICMP traffic
- Counts packets from each source IP
- Generates JSON security alerts
- Integrates with Airia for AI-assisted SOC analysis
- Simple and modular Python implementation

## Tech Stack

- Python 3
- Tshark (Wireshark CLI)
- CSV & JSON
- Requests Library
- Airia API

## Project Workflow

```text
Network Traffic
      ↓
Capture Packets
      ↓
Analyze Traffic
      ↓
Detect Suspicious Activity
      ↓
Generate JSON Alert
      ↓
Airia SOC Analysis
```

## Project Structure

```
project/
├── main.py
├── traffic.pcap
├── traffic.csv
├── alert.json
├── README.md
└── requirements.txt
```

## Getting Started

1. Clone the repository.
2. Install the required dependencies.
3. Configure the network interface and Airia API credentials.
4. Run:

```bash
python main.py
```

## Output

The project generates:

- `traffic.pcap` – Captured network traffic
- `traffic.csv` – Extracted packet information
- `alert.json` – Structured security alert

## Future Improvements

- Continuous monitoring
- Detection of additional attack types
- Dashboard for visualization
- SIEM integration
- Threat intelligence support

## Disclaimer

This project was built for educational purposes to demonstrate the workflow of an Intrusion Detection System (IDS). It is not intended to be a production-ready security solution.
