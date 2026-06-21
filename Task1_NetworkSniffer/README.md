🌐 Advanced Network Sniffer (v4.0)

An enterprise-grade, asynchronous network packet sniffer built with Python and Scapy. Designed for Deep Packet Inspection (DPI), real-time network analysis, and high-performance capture using a multi-threaded architecture.

✨ Key Features

Live TUI Dashboard: Utilizes the Rich library to render a locked, dynamically updating terminal UI—eliminating messy console scrolling.

Multi-Threaded Architecture: Implements a Producer/Consumer queue system to ensure zero packet drop during high-traffic network captures.

Deep Packet Inspection (DPI): * Extracts plain-text HTTP Host headers.

Parses cryptographic handshakes to extract HTTPS Server Name Indication (SNI) domains.

Granular Target Filtering: Interactive Berkeley Packet Filter (BPF) injection allows you to isolate traffic by protocol (TCP, UDP, ICMP) or lock onto a specific Target IP address.

Forensic Export: Automatically logs session details to a local .txt file and saves raw binary packet data to a .pcap file for secondary analysis in Wireshark.

🛠️ Architecture & Code Explanation

This tool is separated into two distinct threads that run simultaneously to maximize performance:

The Catcher (Producer): Uses Scapy's sniff() function hooked directly to the physical network card. Its only job is to catch raw binary frames and instantly drop them into a thread-safe Queue.

The Analyzer (Consumer): A background worker that pulls packets from the queue, strips the OSI layers (Layer 2 MAC, Layer 3 IP, Layer 4 TCP/UDP), and performs Deep Packet Inspection on Layer 7 payloads.

The Interface Engine: Uses a deque (double-ended queue) to maintain a rolling memory of the last 15 packets, redrawing the Rich table 10 times per second for a smooth, dashboard-like aesthetic.

📦 Installation & Requirements

Prerequisites:

Python 3.8+

Administrative/Root privileges (required for raw socket access)

Install Dependencies:

pip install scapy rich


🚀 Usage

Run the script interactively to access the main menu:

sudo python3 sniffer.py


Command-Line Arguments

You can bypass the interactive menu by supplying command-line arguments for automated scripting:

# Capture exactly 500 packets and save them to a custom PCAP file
sudo python3 sniffer.py -c 500 -o my_capture.pcap


Flag

Name

Description

-c

--count

Number of packets to capture (Default: 0 / Infinite)

-o

--output

Name of the output PCAP file (Default: capture.pcap)

⚠️ Disclaimer

This tool was developed for educational purposes, portfolio demonstration, and authorized network auditing as part of a cybersecurity internship. Do not use this tool to monitor networks or IP addresses where you do not have explicit, written permission.
