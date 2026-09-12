# imports
# datetime is used to get the current time and date of the packet capture
from datetime import datetime

# scapy is a Python library used for packet manipulation and analysis
from scapy.layers.dns import DNS
from scapy.layers.inet import TCP, UDP
from scapy.layers.l2 import ARP
from scapy.sendrecv import sniff

# importing handlers for different protocols from the protocols module
from protocols import handle_arp, handle_dns, handle_tcp, handle_udp

# This is formmatting for the output of the packet capture,
from utils import print_footer, print_header

packet_counter = 0  # Keeps track of the number of packets captured


def packet_received(packet):  # Processes each packet received by the sniff function
    global packet_counter

    packet_counter += 1  # Increments the packet counter for each packet received

    if ARP in packet:  # Check if the packet contains an ARP layer
        handle_arp(packet, packet_counter)

    elif DNS in packet:  # Otherwise, check if the packet contains a DNS layer
        handle_dns(packet, packet_counter)

    elif TCP in packet:  # Otherwise, check if the packet contains a TCP layer
        handle_tcp(packet, packet_counter)

    elif UDP in packet:  # Otherwise, check if the packet contains a UDP layer
        handle_udp(packet, packet_counter)


capture_start = datetime.now()  # Records the start time of the packet capture

print_header(
    capture_start
)  # Prints the header for the packet capture, including the start time

sniff(
    count=30, prn=packet_received
)  # Starts sniffing for packets, calling the packet_received function for each packet
capture_end = datetime.now()

print_footer(capture_start, capture_end, packet_counter)
