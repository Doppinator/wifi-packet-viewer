from datetime import datetime

from scapy.all import ARP, DNS, IP, TCP, UDP, sniff

packet_counter = 0
conversation_counter = 0
conversations = {}

COMMON_TCP_PORTS = {
    20: "FTP Data",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    465: "SMTPS",
    587: "SMTP Submission",
    993: "IMAPS",
    995: "POP3S",
}


def track_conversation(endpoint1, endpoint2):
    """Create or update a conversation and return its record."""
    global conversation_counter

    conversation = tuple(sorted([endpoint1, endpoint2]))

    if conversation not in conversations:
        conversation_counter += 1
        conversations[conversation] = {
            "id": conversation_counter,
            "count": 1,
        }
    else:
        conversations[conversation]["count"] += 1

    return conversations[conversation]


def get_tcp_service(packet):
    """Return a human-readable TCP service name."""
    return (
        COMMON_TCP_PORTS.get(packet[TCP].dport)
        or COMMON_TCP_PORTS.get(packet[TCP].sport)
        or "Unknown"
    )


def packet_received(packet):
    global packet_counter

    packet_counter += 1
    timestamp = datetime.now().strftime("%H:%M:%S")

    if ARP in packet:
        if packet[ARP].op == 1:
            action = f"Who has {packet[ARP].pdst}?"
        elif packet[ARP].op == 2:
            action = f"{packet[ARP].psrc} is at {packet[ARP].hwsrc}"
        else:
            action = "Unknown ARP"

        print(
            f"[{packet_counter:03}] {timestamp}  ARP  {action}"
        )
        print(f"Source MAC: {packet[ARP].hwsrc}")
        print(f"Destination MAC: {packet[ARP].hwdst}")
        print(f"Source IP: {packet[ARP].psrc}")
        print(f"Destination IP: {packet[ARP].pdst}")

    elif DNS in packet:
        conv = track_conversation(
            (packet[IP].src, packet[UDP].sport),
            (packet[IP].dst, packet[UDP].dport),
        )

        print(
            f"[{packet_counter:03}] {timestamp}  DNS  "
            f"{packet[IP].src}:{packet[UDP].sport} → "
            f"{packet[IP].dst}:{packet[UDP].dport}  "
            f"Conn#{conv['id']} ({conv['count']})"
        )

    elif TCP in packet:
        conv = track_conversation(
            (packet[IP].src, packet[TCP].sport),
            (packet[IP].dst, packet[TCP].dport),
        )

        service = get_tcp_service(packet)
        flags = str(packet[TCP].flags)

        print(
            f"[{packet_counter:03}] {timestamp}  TCP  "
            f"{service:<8} [{flags:<2}] "
            f"{packet[IP].src}:{packet[TCP].sport} → "
            f"{packet[IP].dst}:{packet[TCP].dport}  "
            f"Conn#{conv['id']} ({conv['count']})"
        )

    elif UDP in packet:
        conv = track_conversation(
            (packet[IP].src, packet[UDP].sport),
            (packet[IP].dst, packet[UDP].dport),
        )

        print(
            f"[{packet_counter:03}] {timestamp}  UDP  "
            f"{packet[IP].src}:{packet[UDP].sport} → "
            f"{packet[IP].dst}:{packet[UDP].dport}  "
            f"Conn#{conv['id']} ({conv['count']})"
        )


capture_start = datetime.now()

print("\n" + "=" * 60)
print(f"Capture started: {capture_start.strftime('%Y-%m-%d %H:%M:%S')}")
print("=" * 60)

sniff(count=10, prn=packet_received)

capture_end = datetime.now()

print("=" * 60)
print(f"Capture ended: {capture_end.strftime('%H:%M:%S')}")
print(f"Total packets captured: {packet_counter}")
print(f"Duration: {(capture_end - capture_start).total_seconds():.2f} seconds")
print("=" * 60)