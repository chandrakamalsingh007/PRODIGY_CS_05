# Network Packet Analyzer

This project is a packet sniffer that allows you to capture and analyze network packets based on user-defined protocols such as TCP, UDP, ICMP, and IP. It uses the Python library `Scapy` to capture packets and display useful information about them such as source/destination IP addresses, source/destination ports, and raw payloads.

## Features

- Sniff TCP, UDP, ICMP, and IP packets.
- Displays detailed information about each packet, including:
  - Source IP address
  - Destination IP address
  - Source and destination ports (for TCP and UDP)
  - Raw payload (if available)
- Allows the user to choose the protocol they want to sniff interactively.

## Requirements

- Python 3.x
- Scapy library

You can install Scapy using pip if you don't have it already:

```bash
pip install scapy

## Features

1. clone the repository or download the script
 ```bash
git clone https://github.com/chandrakamalsingh007/PRODIGY_CS_05.git

2. Run the script
   ```bash
   python3 ./NetworkPacketAnalyzer.py

3. The script will start sniffing the selected protocol and print relevant packet information in the terminal.
   ```bash
   Select the protocol you want to sniff:
  1. TCP
  2. UDP
  3. ICMP
  4. IP
  Enter the number corresponding to the protocol: 1
  Starting packet sniffing for TCP protocol...

