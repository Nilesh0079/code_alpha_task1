from scapy.all import sniff, IP, TCP, UDP

# Callback function to process each captured packet
def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        if protocol == 6:  # TCP
            if TCP in packet:
                tcp_sport = packet[TCP].sport
                tcp_dport = packet[TCP].dport
                print(f"TCP Packet: {ip_src}:{tcp_sport} -> {ip_dst}:{tcp_dport}")
        elif protocol == 17:  # UDP
            if UDP in packet:
                udp_sport = packet[UDP].sport
                udp_dport = packet[UDP].dport
                print(f"UDP Packet: {ip_src}:{udp_sport} -> {ip_dst}:{udp_dport}")

# Start sniffing on the default network interface
sniff(prn=packet_callback, store=0)
