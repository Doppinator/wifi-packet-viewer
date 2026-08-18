from scapy.all import sniff, ARP, DNS, TCP, UDP, IP


def packet_received(packet):
    if ARP in packet:
        print(f"ARP Operation: {packet[ARP].op!r}")
        print(f"Source MAC: {packet[ARP].hwsrc}")
        print(f"Destination MAC: {packet[ARP].hwdst}")
        print(f"Source IP: {packet[ARP].psrc}")
        print(f"Destination IP: {packet[ARP].pdst}")

    elif DNS in packet:
        print("DNS packet")

    elif TCP in packet:
        print("TCP packet")
        print(f"Source Port: {packet[TCP].sport}")
        print(f"Destination Port: {packet[TCP].dport}")
        print(f"Source IP: {packet[IP].src}")
        print(f"Destination IP: {packet[IP].dst}")

    elif UDP in packet:
        print("UDP packet")
        print(f"Source Port: {packet[UDP].sport}")
        print(f"Destination Port: {packet[UDP].dport}")
        print(f"Source IP: {packet[IP].src}")
        print(f"Destination IP: {packet[IP].dst}")

    else:
        print("Other packet")

print("Starting packet capture...")

sniff(count=20, prn=packet_received)

print("Capture complete.")
