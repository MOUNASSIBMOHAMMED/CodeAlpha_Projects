#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║        CodeAlpha Cyber Security Internship — Task 1                  ║
║               Advanced Network Sniffer (v3.2)                        ║
║                                                                      ║
║  Author  : Mohammed Mounassib                                        ║
║  Version : 3.2.0 (Deep Packet Inspection Edition)                    ║
║  License : MIT (educational use)                                     ║
╚══════════════════════════════════════════════════════════════════════╝

DESCRIPTION:
An asynchronous, multi-threaded network packet sniffer built with Scapy.
Upgraded with Deep Packet Inspection (DPI) to extract HTTP Host headers
and HTTPS Server Name Indication (SNI) domains.
"""

import argparse
import os
import sys
import threading
from queue import Queue
from datetime import datetime

try:
    from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP, conf, Raw, load_layer
    from scapy.layers.dns import DNSQR
    # Load TLS module for Deep Packet Inspection on HTTPS
    load_layer("tls")
    from scapy.layers.tls.handshake import TLSClientHello
    from scapy.layers.tls.extensions import TLS_Ext_ServerName
except ImportError:
    print("[ERROR] Scapy is not installed. Run: pip install scapy")
    sys.exit(1)

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    print("[ERROR] Colorama is not installed. Run: pip install colorama")
    sys.exit(1)

# ================= CONFIGURATION & MAPPING =================
conf.use_pcap = True
packet_queue = Queue()
captured_packets = []

PROTOCOLS = {
    1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 
    41: "IPv6", 47: "GRE", 50: "ESP", 51: "AH", 89: "OSPF"
}

SERVICES = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    123: "NTP", 143: "IMAP", 161: "SNMP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL"
}

class Stats:
    total = 0
    tcp = 0
    udp = 0
    dns = 0
    icmp = 0
    other = 0

base_dir = os.path.dirname(os.path.abspath(__file__))
log_path = os.path.join(base_dir, "session_log.txt")

# ================= WORKER THREAD (CONSUMER) =================
def process_packets(log_file, verbose):
    while True:
        packet = packet_queue.get()
        if packet is None:
            break

        Stats.total += 1
        current_time = datetime.now().strftime("%H:%M:%S")

        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto_num = packet[IP].proto
            proto_name = PROTOCOLS.get(proto_num, f"UNKNOWN({proto_num})")
            
            src_port, dst_port, service = "N/A", "N/A", "N/A"
            color = Fore.WHITE

            # -- TCP LAYER (With HTTP/HTTPS Deep Inspection) --
            if packet.haslayer(TCP):
                Stats.tcp += 1
                color = Fore.LIGHTRED_EX
                src_port, dst_port = packet[TCP].sport, packet[TCP].dport
                service = SERVICES.get(dst_port, SERVICES.get(src_port, "Unknown TCP"))

                # 1. Inspect HTTP (Port 80) for Host name
                if service == "HTTP" and packet.haslayer(Raw):
                    try:
                        payload = packet[Raw].load.decode('utf-8', errors='ignore')
                        for line in payload.split('\r\n'):
                            if line.startswith('Host: '):
                                domain = line.split(' ')[1]
                                service = f"HTTP ({domain})"
                                color = Fore.LIGHTGREEN_EX
                                break
                    except:
                        pass

                # 2. Inspect HTTPS (Port 443) for SNI (Server Name)
                elif service == "HTTPS" and packet.haslayer(TLSClientHello):
                    try:
                        if packet.haslayer(TLS_Ext_ServerName):
                            server_names = packet[TLS_Ext_ServerName].servernames
                            if server_names:
                                domain = server_names[0].servername.decode('utf-8')
                                service = f"HTTPS ({domain})"
                                color = Fore.LIGHTGREEN_EX
                    except:
                        pass
            
            # -- UDP LAYER --
            elif packet.haslayer(UDP):
                Stats.udp += 1
                color = Fore.LIGHTCYAN_EX
                src_port, dst_port = packet[UDP].sport, packet[UDP].dport
                service = SERVICES.get(dst_port, SERVICES.get(src_port, "Unknown UDP"))
                
                if packet.haslayer(DNSQR):
                    Stats.dns += 1
                    color = Fore.LIGHTMAGENTA_EX
                    proto_name = "DNS"
                    service = packet[DNSQR].qname.decode(errors='ignore')
                    
            # -- ICMP LAYER --
            elif packet.haslayer(ICMP):
                Stats.icmp += 1
                color = Fore.LIGHTYELLOW_EX
                proto_name = "ICMP"
                service = "Ping / Control"
                
            else:
                Stats.other += 1
                color = Fore.LIGHTYELLOW_EX

            # -- Live Terminal Dashboard --
            print(color + f"[{current_time}] {proto_name:<4} | {src_ip}:{src_port} -> {dst_ip}:{dst_port} | {service}")

            if verbose:
                print(Style.DIM + f"   └── Size: {len(packet)} bytes | Layers: {packet.summary()}")

            # -- File Logging --
            log_entry = f"[{current_time}] {proto_name} | {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Service: {service}\n"
            log_file.write(log_entry)
            log_file.flush()

        packet_queue.task_done()

# ================= SNIFFER CALLBACK (PRODUCER) =================
def packet_callback(packet):
    captured_packets.append(packet)
    packet_queue.put(packet)

# ================= MAIN LAUNCHER =================
def main():
    parser = argparse.ArgumentParser(description="CodeAlpha Advanced Network Sniffer")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture")
    parser.add_argument("-f", "--filter", type=str, default="", help="BPF filter")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed packet summary")
    parser.add_argument("-o", "--output", type=str, default="capture.pcap", help="Output PCAP filename")
    args = parser.parse_args()

    bpf_filter = args.filter
    if not sys.argv[1:]:
        print(Fore.LIGHTCYAN_EX + "╔══════════════════════════════════════════╗")
        print(Fore.LIGHTGREEN_EX + "║      PYTHON NETWORK SNIFFER v3.2         ║")
        print(Fore.LIGHTCYAN_EX + "╚══════════════════════════════════════════╝")
        print("1 → TCP Only")
        print("2 → UDP Only")
        print("3 → DNS Only (Port 53)")
        print("4 → ICMP Only (Ping)")
        print("5 → IGMP Only (Multicast)")
        print("6 → IPv6 Traffic Only")
        print("7 → OSPF Only (Routing)")
        print("8 → ALL Traffic\n")
        
        choice = input("Enter Choice (1-8): ").strip()
        
        if choice == "1": bpf_filter = "tcp"
        elif choice == "2": bpf_filter = "udp"
        elif choice == "3": bpf_filter = "udp port 53"
        elif choice == "4": bpf_filter = "icmp"
        elif choice == "5": bpf_filter = "igmp"
        elif choice == "6": bpf_filter = "ip6"
        elif choice == "7": bpf_filter = "ip proto 89"
        elif choice == "8": bpf_filter = ""
        else: 
            print(Fore.LIGHTYELLOW_EX + "[!] Invalid choice. Defaulting to ALL Traffic.")
            bpf_filter = ""

    print(Fore.LIGHTGREEN_EX + f"\n[*] Starting capture engine (Deep Packet Inspection Active)...")
    print(Fore.LIGHTGREEN_EX + f"[*] Live logs saving to: {log_path}")
    print(Fore.LIGHTRED_EX + "[*] Press Ctrl+C to stop capture and generate report.\n")

    log_file = open(log_path, "a", encoding="utf-8")
    worker = threading.Thread(target=process_packets, args=(log_file, args.verbose), daemon=True)
    worker.start()

    try:
        sniff(filter=bpf_filter, prn=packet_callback, count=args.count, store=False)
    except PermissionError:
        print(Fore.LIGHTRED_EX + "\n[!] ERROR: You must run this script with sudo/administrative privileges.")
        sys.exit(1)
    except KeyboardInterrupt:
        pass
    finally:
        print(Fore.LIGHTYELLOW_EX + "\n\n[!] HALTING ENGINE & GENERATING REPORT...")
        packet_queue.put(None) 
        worker.join(timeout=2.0)
        log_file.close()

        if captured_packets:
            wrpcap(args.output, captured_packets)
            print(Fore.LIGHTGREEN_EX + f"[+] {len(captured_packets)} raw packets saved to {args.output}")

        print(Fore.LIGHTCYAN_EX + "\n" + "="*40)
        print(Fore.LIGHTYELLOW_EX + "        SESSION TRAFFIC REPORT")
        print(Fore.LIGHTCYAN_EX + "="*40)
        print(Fore.WHITE + f"Total Packets Captured : {Stats.total}")
        print(Fore.LIGHTRED_EX + f"TCP Packets            : {Stats.tcp}")
        print(Fore.LIGHTCYAN_EX + f"UDP Packets            : {Stats.udp}")
        print(Fore.LIGHTMAGENTA_EX + f"DNS Queries            : {Stats.dns}")
        print(Fore.LIGHTYELLOW_EX + f"ICMP Packets           : {Stats.icmp}")
        print(Fore.LIGHTCYAN_EX + "="*40 + "\n")

if __name__ == "__main__":
    main()