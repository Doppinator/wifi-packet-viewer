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


def get_tcp_service(packet):
    """Return a human-readable TCP service name."""
    return (
        COMMON_TCP_PORTS.get(packet.dport)
        or COMMON_TCP_PORTS.get(packet.sport)
        or "Unknown"
    )