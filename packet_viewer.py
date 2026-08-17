from scapy.all import sniff

print("Starting packet capture...")

sniff(count=1, prn=lambda packet: packet.show())

print("Capture complete.")