from scapy.all import sniff, ARP, DNS, TCP, UDP, IP
from datetime import datetime

packet_counter = 0
conversation_counter = 0
conversations = {}


def packet_received(packet):
    global packet_counter, conversation_counter, conversations

    packet_counter += 1
    timestamp = datetime.now().strftime("%H:%M:%S")

    if ARP in packet:
        endpoint1 = (packet[ARP].psrc, packet[ARP].hwsrc)
        endpoint2 = (packet[ARP].pdst, packet[ARP].hwdst)
        conversation = tuple(sorted([endpoint1, endpoint2]))    

        if conversation not in conversations:
            conversation_counter += 1
            conversations[conversation] = {
                "id": conversation_counter,
                "count": 1,
            }
        else:
            conversations[conversation]["count"] += 1
        print(
            f"[{packet_counter:03}] [{timestamp}] ARP "
            f"{packet[ARP].psrc} ({packet[ARP].hwsrc}) → "
            f"{packet[ARP].pdst} ({packet[ARP].hwdst}) "
            f"Conn#{conversations[conversation]['id']} "
            f"({conversations[conversation]['count']})"
        )

    elif DNS in packet:
        endpoint1 = (packet[IP].src, packet[UDP].sport)
        endpoint2 = (packet[IP].dst, packet[UDP].dport)
        conversation = tuple(sorted([endpoint1, endpoint2]))

        if conversation not in conversations:
            conversation_counter += 1
            conversations[conversation] = {
                "id": conversation_counter,
                "count": 1,
            }
        else:
            conversations[conversation]["count"] += 1

        print(
            f"[{packet_counter:03}] [{timestamp}] DNS "
            f"{packet[IP].src}:{packet[UDP].sport} → "
            f"{packet[IP].dst}:{packet[UDP].dport} "
            f"Conn#{conversations[conversation]['id']} "
            f"({conversations[conversation]['count']})"
        )

    elif TCP in packet:
        endpoint1 = (packet[IP].src, packet[TCP].sport)
        endpoint2 = (packet[IP].dst, packet[TCP].dport)
        conversation = tuple(sorted([endpoint1, endpoint2]))

        if conversation not in conversations:
            conversation_counter += 1
            conversations[conversation] = {
                "id": conversation_counter,
                "count": 1,
            }
        else:
            conversations[conversation]["count"] += 1

        print(
            f"[{packet_counter:03}] [{timestamp}] TCP "
            f"{packet[IP].src}:{packet[TCP].sport} "
            f"→ {packet[IP].dst}:{packet[TCP].dport} "
            f"Conn#{conversations[conversation]['id']} "
            f"({conversations[conversation]['count']})"
        )

    elif UDP in packet:
        endpoint1 = (packet[IP].src, packet[UDP].sport)
        endpoint2 = (packet[IP].dst, packet[UDP].dport)
        conversation = tuple(sorted([endpoint1, endpoint2]))

        if conversation not in conversations:
            conversation_counter += 1
            conversations[conversation] = {
                "id": conversation_counter,
                "count": 1,
            }
        else:
            conversations[conversation]["count"] += 1

        print(
            f"[{packet_counter:03}] [{timestamp}] UDP "
            f"{packet[IP].src}:{packet[UDP].sport} → "
            f"{packet[IP].dst}:{packet[UDP].dport} "
            f"Conn#{conversations[conversation]['id']} "
            f"({conversations[conversation]['count']})"
        )


capture_start = datetime.now()
print("\n" + "=" * 60)
print(f"Capture started: {capture_start.strftime('%Y-%m-%d %H:%M:%S')}")
print("=" * 60)

sniff(
    count=10,
    prn=packet_received,
)

capture_end = datetime.now()
print("=" * 60)
print(f"Capture ended: {capture_end.strftime('%H:%M:%S')}")
print(f"Total packets captured: {packet_counter}")
print(f"Duration: {capture_end - capture_start}")
print("=" * 60)
