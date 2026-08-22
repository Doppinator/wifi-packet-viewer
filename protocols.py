from scapy.all import ARP, IP, TCP, UDP

from conversation import track_conversation
from services import get_tcp_service
from utils import timestamp


def handle_arp(packet, number):
    conv = track_conversation(
        (packet[ARP].psrc, packet[ARP].hwsrc),
        (packet[ARP].pdst, packet[ARP].hwdst),
    )

    if packet[ARP].op == 1:
        action = f"Who has {packet[ARP].pdst}?"
    else:
        action = f"{packet[ARP].psrc} is at {packet[ARP].hwsrc}"

    print(
        f"[{number:03}] {timestamp()}  ARP  {action}  "
        f"Conn#{conv['id']} ({conv['count']})"
    )
def handle_dns(packet, number):
    conv = track_conversation(
        (packet[IP].src, packet[UDP].sport),
        (packet[IP].dst, packet[UDP].dport),
    )

    print(
        f"[{number:03}] {timestamp()}  DNS  "
        f"{packet[IP].src}:{packet[UDP].sport} → "
        f"{packet[IP].dst}:{packet[UDP].dport}  "
        f"Conn#{conv['id']} ({conv['count']})"
    )
def handle_tcp(packet, number):
    conv = track_conversation(
        (packet[IP].src, packet[TCP].sport),
        (packet[IP].dst, packet[TCP].dport),
    )

    service = get_tcp_service(packet[TCP])
    flags = str(packet[TCP].flags)

    print(
        f"[{number:03}] {timestamp()}  TCP  "
        f"{service:<8} [{flags:<2}] "
        f"{packet[IP].src}:{packet[TCP].sport} → "
        f"{packet[IP].dst}:{packet[TCP].dport}  "
        f"Conn#{conv['id']} ({conv['count']})"
    )
def handle_udp(packet, number):
    conv = track_conversation(
        (packet[IP].src, packet[UDP].sport),
        (packet[IP].dst, packet[UDP].dport),
    )

    print(
        f"[{number:03}] {timestamp()}  UDP  "
        f"{packet[IP].src}:{packet[UDP].sport} → "
        f"{packet[IP].dst}:{packet[UDP].dport}  "
        f"Conn#{conv['id']} ({conv['count']})"
    )