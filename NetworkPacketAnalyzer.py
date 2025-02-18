from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP

def packet_analysis(packet, protocol_choice):
    if packet.haslayer(IP):
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        protocol = packet[IP].proto

        if protocol_choice == "TCP" and packet.haslayer(TCP):
            print("TCP Packet detected")
            print(f"Source IP: {source_ip}")
            print(f"Destination IP: {destination_ip}")
            print(f"Source Port: {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")
            if packet.haslayer(Raw):
                payload = packet[Raw].load
                print(f"Payload: {payload}")
            print("--------------------------------")

        elif protocol_choice == "UDP" and packet.haslayer(UDP):
            print("UDP Packet detected")
            print(f"Source IP: {source_ip}")
            print(f"Destination IP: {destination_ip}")
            print(f"Source Port: {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")
            if packet.haslayer(Raw):
                payload = packet[Raw].load
                print(f"Payload: {payload}")
            print("--------------------------------")

        elif protocol_choice == "ICMP" and packet.haslayer(ICMP):
            print("ICMP Packet detected")
            print(f"Source IP: {source_ip}")
            print(f"Destination IP: {destination_ip}")
            if packet.haslayer(Raw):
                payload = packet[Raw].load
                print(f"Payload: {payload}")
            print("--------------------------------")

        elif protocol_choice == "IP" and packet.haslayer(IP):
            print("IP Packet detected")
            print(f"Source IP: {source_ip}")
            print(f"Destination IP: {destination_ip}")
            if packet.haslayer(Raw):
                payload = packet[Raw].load
                print(f"Payload: {payload}")
            print("--------------------------------")

def start_sniffing(protocol_choice):
    filter_expr = ""

    # Define the filter expression based on protocol choice
    if protocol_choice == "TCP":
        filter_expr = "tcp"
    elif protocol_choice == "UDP":
        filter_expr = "udp"
    elif protocol_choice == "ICMP":
        filter_expr = "icmp"
    elif protocol_choice == "IP":
        filter_expr = "ip"

    print(f"Starting packet sniffing for {protocol_choice} protocol...")
    sniff(filter=filter_expr, prn=lambda packet: packet_analysis(packet, protocol_choice))

def choose_protocol():
    print("Select the protocol you want to sniff:")
    print("1. TCP")
    print("2. UDP")
    print("3. ICMP")
    print("4. IP")

    choice = input("Enter the number corresponding to the protocol: ")

    if choice == "1":
        return "TCP"
    elif choice == "2":
        return "UDP"
    elif choice == "3":
        return "ICMP"
    elif choice == "4":
        return "IP"
    else:
        print("Invalid choice. Defaulting to IP.")
        return "IP"

# Main function to interactively choose the protocol
def main():
    protocol_choice = choose_protocol()
    start_sniffing(protocol_choice)

# Run the program
if __name__ == "__main__":
    main()
