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

Initial captures were Ethernet/IP/UDP traffic containing mDNS rather than raw IEEE 802.11 frames.

### Next step

Investigate monitor mode and raw 802.11 packet capture.

---

## 18 August 2026 — Initial Packet Inspection

### Objective

Inspect the structure and contents of individual captured packets.

### Implementation

Scapy's packet inspection functionality was used to display the complete contents of captured packets.

### Result

An ARP packet was successfully captured and inspected, showing Ethernet and ARP layers together with fields including:

- Source MAC address
- Source IP address
- Destination MAC address
- Destination IP address
- ARP operation

### Observation

A single captured packet can contain multiple protocol layers. This demonstrated the distinction between the underlying packet structure and the information displayed by Scapy.

### Next step

Begin extracting individual fields from identified protocol layers.

---

## 18 August 2026 — Packet Processing with `prn`

### Environment CHange

- Pop!_OS
- Python 3.12
- Scapy
- VSCode

### Objective

Process each captured packet automatically rather than only displaying complete packet contents.

### Implementation

A `packet_received()` function was introduced and passed to Scapy's `sniff()` function using the `prn` parameter.

```python
sniff(count=5, prn=packet_received)

