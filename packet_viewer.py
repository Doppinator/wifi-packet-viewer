from datetime import datetime
from scapy.all import ARP, DNS, TCP, UDP, sniff

from protocols import handle_arp, handle_dns, handle_tcp, handle_udp
from utils import print_footer, print_header

packet_counter = 0


def packet_received(packet):
    global packet_counter

    packet_counter += 1

    if ARP in packet:
        handle_arp(packet, packet_counter)

    elif DNS in packet:
        handle_dns(packet, packet_counter)

    elif TCP in packet:
        handle_tcp(packet, packet_counter)

    elif UDP in packet:
        handle_udp(packet, packet_counter)


capture_start = datetime.now()

print_header(capture_start)

sniff(count=30, prn=packet_received)
capture_end = datetime.now()

print_footer(capture_start, capture_end, packet_counter)

