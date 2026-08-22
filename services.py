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

def update_tcp_state(conv, flags):
    """Update TCP handshake state and return an event message."""

    if conv["state"] == "NEW" and flags == "S":
        conv["state"] = "SYN_SENT"
        return "Connection initiated"

    if conv["state"] == "SYN_SENT" and flags == "SA":
        conv["state"] = "SYN_ACK_RECEIVED"
        return "Server accepted"

    if conv["state"] == "SYN_ACK_RECEIVED" and flags == "A":
        conv["state"] = "ESTABLISHED"
        return "Connection established"

    if flags == "F":
        conv["state"] = "CLOSING"
        return "Connection closing"

    if flags == "R":
        conv["state"] = "RESET"
        return "Connection reset"

    return None