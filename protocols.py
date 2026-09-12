from scapy.all import ARP, IP, TCP, UDP  # Imports protocol classes for use by handlers

from conversation import (
    track_conversation,  # Update conversation tracking for each packet
)
from services import (  # Translate TCP ports to service names and update TCP state machine
    get_tcp_service,
    update_tcp_state,
)
from utils import timestamp


def handle_arp(packet, number):
    # Create source and destination identities for the conversation tracking
    conv = track_conversation(
        (packet[ARP].psrc, packet[ARP].hwsrc),  # Source identity
        (packet[ARP].pdst, packet[ARP].hwdst),  # Destination identity
    )

    if packet[ARP].op == 1:  # ARP request Who has <IP>?
        arp_message = f"Who has {packet[ARP].pdst}?"
    else:  # ARP reply <IP> belongs to <MAC>
        arp_message = f"{packet[ARP].psrc} is at {packet[ARP].hwsrc}"

    print(  # Print the ARP packet information, including the conversation ID and count
        f"[{number:03}] {timestamp()}  ARP  {arp_message}  "
        f"Conn#{conv['id']} ({conv['count']})"
    )


def handle_dns(packet, number):
    conv = track_conversation(
        (packet[IP].src, packet[UDP].sport),  # Source identity
        (packet[IP].dst, packet[UDP].dport),  # Destination identity
    )

    print(  # Print DNS packet info inc IP source/dest, UDP source/dest, conv ID
        f"[{number:03}] {timestamp()}  DNS  "
        f"{packet[IP].src}:{packet[UDP].sport} → "
        f"{packet[IP].dst}:{packet[UDP].dport}  "
        f"Conn#{conv['id']} ({conv['count']})"
    )


def handle_tcp(packet, number):
    conv = track_conversation(
        (packet[IP].src, packet[TCP].sport),  # Source identity
        (packet[IP].dst, packet[TCP].dport),  # Destination identity
    )

    service = get_tcp_service(packet[TCP])
    flags = str(packet[TCP].flags)
    event = update_tcp_state(conv, flags)

    print(  # Print TCP packet info inc IP source/dest,
        # TCP source/dest, conv ID, service, flags
        f"[{number:03}] {timestamp()}  TCP  "
        f"{service:<8} [{flags:<2}] "
        f"{packet[IP].src}:{packet[TCP].sport} → "
        f"{packet[IP].dst}:{packet[TCP].dport}  "
        f"Conn#{conv['id']} ({conv['count']})"
    )
    if event:
        print(f"      ✓ {event}")


def handle_udp(packet, number):
    conv = track_conversation(
        (packet[IP].src, packet[UDP].sport),  # Source identity
        (packet[IP].dst, packet[UDP].dport),  # Destination identity
    )

    print(  # Print UDP packet info inc IP source/dest, UDP source/dest, conv ID
        f"[{number:03}] {timestamp()}  UDP  "
        f"{packet[IP].src}:{packet[UDP].sport} → "
        f"{packet[IP].dst}:{packet[UDP].dport}  "
        f"Conn#{conv['id']} ({conv['count']})"
    )
