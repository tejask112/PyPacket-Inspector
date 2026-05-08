# PyPacket-Inspector
A real-time network packet sniffer and analyser built with Python

**Compact View**
![Compact View](https://github.com/user-attachments/assets/9b7e88f9-2b12-41d2-ba26-c2068d46ba75)
 
**Detailed View**
![Detailed View](https://github.com/user-attachments/assets/af8a1662-21ef-4201-a38f-c4b82e92d9e9)
 

## Features

- **Full OSI Stack Parsing** — Ethernet → IPv4/IPv6/ARP → TCP/UDP/ICMP → DNS
- **Anomaly Detection** — Port scan, DNS tunnelling, and C2 beaconing detection
- **Flexible Filtering** — Filter by IP version, single address, or CIDR subnet
- **Two Display Modes** — `Compact` for busy networks, `Detailed` for deep protocol analysis
- **Checksum Validation** — IPv4, TCP, UDP, and ICMP checksums verified per packet
- **Session Statistics** — Auto-generated session summary on exit protocol breakdown, top talkers, DNS mappings


## Project Structure

```
PyPacket-Inspector/
├── app.py                  # Entry point
├── Sniffer.py              # Sniffer orchestrator
├── core/                   # Parsing, filtering, rendering, stats
├── parsers/                # Per-protocol parsers (eth, ip, tcp, udp, icmp, dns...)
├── attack_detectors/       # Port scan, DNS tunnel, beaconing detectors
└── visuals/                # ASCII banner
```

## Anomaly Detection

| Detector | Attempts to catch |
|---|---|
| `PortScanDetector` | IPs probing 10+ unique ports within a 5s window threshold|
| `DnsTunnellingDetector` | High-entropy / oversized DNS subdomains |
| `BeaconingDetector` | Periodic outbound connections (C2 patterns) |

Thresholds are configurable in `Sniffer.py`.


## Session Summary
Hit `Ctrl+C` at any time to exit and generate a session report covering protocol distribution, top talkers, DNS query logs, and any triggered anomaly alerts.

## Disclaimer

This tool is Linux-only. It relies on a Linux-specific kernel feature and that is not available on macOS or Windows. Running on an unsupported platform will fail at the socket initialisation stage (in Sniffer.py).

## Getting Started

**Install dependencies:**
```bash
pip install InquirerPy prompt_toolkit
```

**Run (root required for raw socket access):**
```bash
sudo python3 app.py
```
