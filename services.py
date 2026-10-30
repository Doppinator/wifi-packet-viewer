COMMON_TCP_PORTS = {
    # Common TCP ports and their corresponding service names
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
    # Returns the service name for a TCP packet based on its source/destination port
    return (
        COMMON_TCP_PORTS.get(packet.dport)
        or COMMON_TCP_PORTS.get(packet.sport)
        or "Unknown"
    )


def update_tcp_state(conv, flags):
    # Updates current TCP connection state based on packet flags

    if conv["state"] == "NEW" and flags == "S":
        # If connection is new and SYN flag is set, update state to SYN_SENT
        conv["state"] = "SYN_SENT"
        return "Connection initiated"

    if conv["state"] == "SYN_SENT" and flags == "SA":
        # If connection is in SYN_SENT state and SYN-ACK flag is set, update state to SYN_ACK_RECEIVED
        conv["state"] = "SYN_ACK_RECEIVED"
        return "Server accepted"

    if conv["state"] == "SYN_ACK_RECEIVED" and flags == "A":
        # If connection is in SYN_ACK_RECEIVED state and ACK flag is set, update state to ESTABLISHED
        conv["state"] = "ESTABLISHED"
        return "Connection established"

    if flags == "F":
        # If FIN flag is set, update state to CLOSING
        conv["state"] = "CLOSING"
        return "Connection closing"

    if flags == "R":
        # If RST flag is set, update state to RESET
        conv["state"] = "RESET"
        return "Connection reset"

    return None
