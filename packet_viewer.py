from scapy.all import sniff, ARP, DNS, TCP, UDP, IP
from datetime import datetime

def packet_received(packet):
    timestamp = datetime.now().strftime("%H:%M:%S")

    if ARP in packet:
        print(f"{timestamp}] ARP Packet: {packet[ARP].op!r}")
        print(f"Source MAC: {packet[ARP].hwsrc}")
        print(f"Destination MAC: {packet[ARP].hwdst}")
        print(f"Source IP: {packet[ARP].psrc}")
        print(f"Destination IP: {packet[ARP].pdst}")

    elif DNS in packet:
        print(f"{timestamp}] DNS Packet")

    elif TCP in packet:
        if packet[TCP].dport == 443:
            print(f"{timestamp}] TCP Client → Server (HTTPS)")
        elif packet[TCP].sport == 443:
            print(f"{timestamp}] TCP Server → Client (HTTPS)")
        else:
            print(f"{timestamp}] TCP packet")
        print(f"Source Port: {packet[TCP].sport}")
        print(f"Destination Port: {packet[TCP].dport}")
        print(f"Source IP: {packet[IP].src}")
        print(f"Destination IP: {packet[IP].dst}")
        print(f"Flags: {packet[TCP].flags}")

    elif UDP in packet:
        print(f"{timestamp}] UDP Packet")
        print(f"Source Port: {packet[UDP].sport}")
        print(f"Destination Port: {packet[UDP].dport}")
        print(f"Source IP: {packet[IP].src}")
        print(f"Destination IP: {packet[IP].dst}")

    else:
        print(f"[{timestamp}] Other packet")

capture_start = datetime.now()
print("\n" + "=" * 60)
print(f"Capture started: {capture_start.strftime('%Y-%m-%d %H:%M:%S')}")    
print("=" * 60)

sniff(
    count=10,
    prn=packet_received
)

capture_end = datetime.now()
print("=" * 60)
print(f"Capture ended: {capture_end.strftime('%H:%M:%S')}")
print(f"Total packets captured: {10}")
print(f"Duration: {capture_end - capture_start}") 
print("=" * 60)
