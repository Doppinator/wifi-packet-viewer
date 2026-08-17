# Development Log

## 17 August 2026 — Initial Scapy Capture

### Objective
Test whether Python and Scapy can capture live network packets.

### Environment
- Pop!_OS
- Python 3.12
- Scapy
- VSCodium

### Result
Successfully captured five live packets.

### Observation
Initial captures were Ethernet/IP/UDP traffic containing mDNS
rather than raw IEEE 802.11 frames.

### Next step
Investigate monitor mode and raw 802.11 packet capture.