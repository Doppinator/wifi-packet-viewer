# Wi-Fi Packet Viewer

A Python-based network packet inspection tool built using [Scapy](https://scapy.net/). The project explores how network traffic can be captured, inspected and organised to discover conversational network activity.

## Overview

Wi-Fi Packet Viewer captures live network packets and examines their contents to provide a readable overview of network activity. Rather than displaying packets only as raw data, it identifies selected protocols and extracts relevant information to make traffic easier to understand.

The project was developed as a practical exploration of network packet analysis, protocol handling and Python programming.

## Features

- **Live packet capture:** Capture packets from the network using Scapy.
- **ARP inspection:** Display Address Resolution Protocol requests and replies, including relevant IP and MAC address information.
- **DNS inspection:** Identify and examine DNS traffic.
- **TCP and UDP inspection:** Recognise TCP and UDP packets and extract useful information about the traffic.
- **Conversation tracking:** Group communications between endpoints and maintain packet counts for tracked conversations.
- **TCP connection-state tracking:** Follow basic TCP connection activity.
- **Service identification:** Use TCP port numbers to identify common network services.
- **Readable output:** Present selected packet information in a human-readable format, with timestamps and capture statistics.

## How it works

The application captures packets using Scapy and passes them to protocol-specific handlers for inspection. Each handler extracts information relevant to the protocol being examined, while shared utility functions help organise the output and track conversations.

The project is organised into separate Python modules, keeping packet capture, protocol handling, conversation tracking, service identification and output formatting distinct. This makes the code easier to understand, maintain and extend.

## Requirements
- Python 3.13 or later.
- Scapy 

## Running the application

Clone the repository and enter the project directory:

```bash
git clone https://github.com/Doppinator/wifi-packet-viewer.git
cd wifi-packet-viewer
```

Create and activate a virtual environment. The following commands are for Bash; Fish users should use `source .venv/bin/activate.fish` instead.

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the project dependencies:

```bash
python -m pip install -r requirements.txt
```

Run the application:

```bash
sudo ./.venv/bin/python packet_viewer.py
```

Elevated privileges may be required for live packet capture on Linux. Only capture traffic on networks and devices you are authorised to inspect.

## Project structure

| File | Purpose |
|---|---|
| `packet_viewer.py` | Main application and packet-capture workflow |
| `protocols.py` | Protocol-specific packet inspection |
| `conversation.py` | Conversation tracking and packet counts |
| `services.py` | Common service identification and TCP state handling |
| `utils.py` | Output formatting and timestamp utilities |

## Scope and limitations

This project is a lightweight packet inspection tool intended for learning and experimentation. It focuses on selected network protocols and presents information extracted from captured packets. It is not intended to be a complete network monitoring platform or an intrusion detection system.

## Learning objectives

This project has provided practical experience with:

- Network packet capture and protocol analysis.
- Ethernet, IP, ARP, DNS, TCP and UDP traffic.
- Python modular programming and separation of concerns.
- Tracking network conversations and basic connection states.
- Working with Scapy to inspect live network traffic.

