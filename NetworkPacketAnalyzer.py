import tkinter as tk
from tkinter import scrolledtext
from scapy.all import sniff, IP, TCP, UDP, Ether
import threading

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Analyzer")
        self.root.geometry("800x600")

        # Create a text area to display packet information
        self.packet_info_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=100, height=30)
        self.packet_info_area.pack(padx=10, pady=10)

        # Start button
        self.start_button = tk.Button(root, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(pady=5)

        # Stop button
        self.stop_button = tk.Button(root, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(pady=5)

        # Flag to control the sniffing process
        self.sniffing = False

    def start_sniffing(self):
        self.sniffing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.packet_info_area.delete(1.0, tk.END)
        self.packet_info_area.insert(tk.END, "Starting packet capture...\n")

        # Start sniffing in a separate thread to keep the GUI responsive
        self.sniff_thread = threading.Thread(target=self.sniff_packets)
        self.sniff_thread.start()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.packet_info_area.insert(tk.END, "Packet capture stopped.\n")

    def sniff_packets(self):
        # Sniff packets and call process_packet for each packet
        sniff(prn=self.process_packet, stop_filter=lambda x: not self.sniffing)

    def process_packet(self, packet):
        # Extract relevant information from the packet
        if Ether in packet:
            eth_src = packet[Ether].src
            eth_dst = packet[Ether].dst
            eth_type = packet[Ether].type
            packet_info = f"Ethernet Frame: {eth_src} -> {eth_dst}, Type: {eth_type}\n"
            self.packet_info_area.insert(tk.END, packet_info)

        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            ip_proto = packet[IP].proto
            packet_info = f"IP Packet: {ip_src} -> {ip_dst}, Protocol: {ip_proto}\n"
            self.packet_info_area.insert(tk.END, packet_info)

        if TCP in packet:
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport
            packet_info = f"TCP Segment: {ip_src}:{tcp_sport} -> {ip_dst}:{tcp_dport}\n"
            self.packet_info_area.insert(tk.END, packet_info)

        if UDP in packet:
            udp_sport = packet[UDP].sport
            udp_dport = packet[UDP].dport
            packet_info = f"UDP Datagram: {ip_src}:{udp_sport} -> {ip_dst}:{udp_dport}\n"
            self.packet_info_area.insert(tk.END, packet_info)

        if packet.haslayer(Raw):
            payload = packet[Raw].load
            packet_info = f"Payload: {payload}\n"
            self.packet_info_area.insert(tk.END, packet_info)

        self.packet_info_area.insert(tk.END, "-" * 80 + "\n")
        self.packet_info_area.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()