#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║        CodeAlpha Cyber Security Internship — Task 1                  ║
║               Advanced Network Sniffer (v4.0)                        ║
║                                                                      ║
║  Author  : Mohammed Mounassib                                        ║
║  Version : 4.0.0 (Rich TUI & Target IP Edition)                      ║
║  License : MIT (educational use)                                     ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import argparse
import os
import sys
import threading
from queue import Queue
from collections import deque
from datetime import datetime

try:
    from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP, conf, Raw, load_layer
    from scapy.layers.dns import DNSQR
    load_layer("tls")
    from scapy.layers.tls.handshake import TLSClientHello
    from scapy.layers.tls.extensions import TLS_Ext_ServerName
except ImportError:
    print("[ERROR] Scapy is not installed. Run: pip install scapy")
    sys.exit(1)

try:
    from rich.console import Console, Group
    from rich.live import Live
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
except ImportError:
    print("[ERROR] Rich is not installed. Run: pip install rich")
    sys.exit(1)

# ================= CONFIGURATION & MAPPING =================
conf.use_pcap = True
packet_queue = Queue()
captured_packets = []
console = Console()

# The "Locked" Memory: Only remember the last 15 packets for the UI
recent_packets = deque(maxlen=15)

PROTOCOLS = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6", 89: "OSPF"}

SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP"
}

class Stats:
    total = 0
    tcp = 0
    udp = 0
    dns = 0
    icmp = 0

base_dir = os.path.dirname(os.path.abspath(__file__))
log_path = os.path.join(base_dir, "session_log.txt")

# ================= UI GENERATOR =================
def generate_dashboard():
    """Builds the dynamic Rich table and stats panel."""
    table = Table(
        title="[bold cyan]⚡ LIVE NETWORK INTERCEPT ⚡[/bold cyan]", 
        border_style="cyan", 
        expand=True
    )
    
    table.add_column("Time", justify="center", style="cyan", no_wrap=True)
    table.add_column("Proto", justify="center", style="bold white")
    table.add_column("Source", style="yellow")
    table.add_column("Destination", style="green")
    table.add_column("Service / Payload", style="magenta")

    for pkt in recent_packets:
        table.add_row(pkt['time'], pkt['proto'], pkt['src'], pkt['dst'], pkt['service'])

    stats_text = (
        f"[white]Total Packets:[/white] [bold cyan]{Stats.total}[/bold cyan]  |  "
        f"[white]TCP:[/white] [bold red]{Stats.tcp}[/bold red]  |  "
        f"[white]UDP:[/white] [bold blue]{Stats.udp}[/bold blue]  |  "
        f"[white]DNS:[/white] [bold magenta]{Stats.dns}[/bold magenta]  |  "
        f"[white]ICMP:[/white] [bold yellow]{Stats.icmp}[/bold yellow]"
    )
    
    stats_panel = Panel(stats_text, border_style="cyan")
    return Group(table, stats_panel)

# ================= WORKER THREAD (CONSUMER) =================
def process_packets(log_file):
    # Start the locked, live-updating UI
    with Live(generate_dashboard(), refresh_per_second=10, screen=True) as live:
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
                proto_name = PROTOCOLS.get(proto_num, f"IP({proto_num})")
                
                src_port, dst_port, service = "", "", "Unknown"
                ui_proto = f"[{proto_name}]"

                # -- TCP & Deep Packet Inspection --
                if packet.haslayer(TCP):
                    Stats.tcp += 1
                    ui_proto = f"[bold red]TCP[/bold red]"
                    src_port, dst_port = packet[TCP].sport, packet[TCP].dport
                    service = SERVICES.get(dst_port, SERVICES.get(src_port, "Unknown TCP"))

                    if service == "HTTP" and packet.haslayer(Raw):
                        try:
                            payload = packet[Raw].load.decode('utf-8', errors='ignore')
                            for line in payload.split('\r\n'):
                                if line.startswith('Host: '):
                                    domain = line.split(' ')[1]
                                    service = f"[bold green]HTTP ({domain})[/bold green]"
                                    break
                        except: pass

                    elif service == "HTTPS" and packet.haslayer(TLSClientHello):
                        try:
                            if packet.haslayer(TLS_Ext_ServerName):
                                server_names = packet[TLS_Ext_ServerName].servernames
                                if server_names:
                                    domain = server_names[0].servername.decode('utf-8')
                                    service = f"[bold green]HTTPS ({domain})[/bold green]"
                        except: pass
                
                # -- UDP & DNS --
                elif packet.haslayer(UDP):
                    Stats.udp += 1
                    ui_proto = f"[bold blue]UDP[/bold blue]"
                    src_port, dst_port = packet[UDP].sport, packet[UDP].dport
                    service = SERVICES.get(dst_port, SERVICES.get(src_port, "Unknown UDP"))
                    
                    if packet.haslayer(DNSQR):
                        Stats.dns += 1
                        ui_proto = f"[bold magenta]DNS[/bold magenta]"
                        service = f"[italic]{packet[DNSQR].qname.decode(errors='ignore')}[/italic]"
                
                # -- ICMP --
                elif packet.haslayer(ICMP):
                    Stats.icmp += 1
                    ui_proto = f"[bold yellow]ICMP[/bold yellow]"
                    service = "Ping / Control"

                # Append to our UI Memory
                src_full = f"{src_ip}:{src_port}" if src_port else src_ip
                dst_full = f"{dst_ip}:{dst_port}" if dst_port else dst_ip
                
                recent_packets.append({
                    'time': current_time,
                    'proto': ui_proto,
                    'src': src_full,
                    'dst': dst_full,
                    'service': service
                })

                # Refresh the dashboard
                live.update(generate_dashboard())

                # File Logging
                log_entry = f"[{current_time}] {proto_name} | {src_full} -> {dst_full} | Service: {service}\n"
                log_file.write(log_entry)
                log_file.flush()

            packet_queue.task_done()

# ================= SNIFFER CALLBACK (PRODUCER) =================
def packet_callback(packet):
    captured_packets.append(packet)
    packet_queue.put(packet)

# ================= MAIN LAUNCHER =================
def main():
    parser = argparse.ArgumentParser(description="Advanced Network Sniffer v4.0")
    parser.add_argument("-c", "--count", type=int, default=0, help="Packets to capture")
    parser.add_argument("-o", "--output", type=str, default="capture.pcap", help="Output PCAP")
    args = parser.parse_args()

    console.clear()
    console.print(Panel("[bold green]PYTHON NETWORK SNIFFER v4.0[/bold green]", expand=False, border_style="cyan"))
    console.print("1 → TCP Only")
    console.print("2 → UDP Only")
    console.print("3 → DNS Only (Port 53)")
    console.print("4 → ICMP Only (Ping)")
    console.print("8 → ALL Traffic")
    console.print("[bold yellow]9 → Target a Specific IP Address 🎯[/bold yellow]\n")
    
    choice = input("Enter Choice: ").strip()
    
    bpf_filter = ""
    if choice == "1": bpf_filter = "tcp"
    elif choice == "2": bpf_filter = "udp"
    elif choice == "3": bpf_filter = "udp port 53"
    elif choice == "4": bpf_filter = "icmp"
    elif choice == "9":
        target_ip = input("    [?] Enter the target IP (e.g., 192.168.1.50): ").strip()
        bpf_filter = f"host {target_ip}"
    elif choice != "8":
        console.print("[yellow][!] Invalid choice. Defaulting to ALL Traffic.[/yellow]")

    console.print("\n[bold green][*] Starting capture engine...[/bold green]")
    console.print("[bold red][*] Press Ctrl+C to stop capture and generate report.[/bold red]\n")
    import time
    time.sleep(2) # Give user a second to read before clearing screen

    log_file = open(log_path, "a", encoding="utf-8")
    worker = threading.Thread(target=process_packets, args=(log_file,), daemon=True)
    worker.start()

    try:
        sniff(filter=bpf_filter, prn=packet_callback, count=args.count, store=False)
    except PermissionError:
        console.print("[bold red]\n[!] ERROR: You must run this script with sudo privileges.[/bold red]")
        sys.exit(1)
    except KeyboardInterrupt:
        pass
    finally:
        packet_queue.put(None) 
        worker.join(timeout=2.0)
        log_file.close()

        if captured_packets:
            wrpcap(args.output, captured_packets)
            
        console.clear()
        console.print(Panel(
            f"[bold white]Total Packets Captured:[/bold white] {Stats.total}\n"
            f"[bold green]PCAP File Saved:[/bold green] {args.output}\n"
            f"[bold cyan]Log File Saved:[/bold cyan] {log_path}",
            title="[bold yellow]SESSION TERMINATED[/bold yellow]",
            border_style="cyan",
            expand=False
        ))

if __name__ == "__main__":
    main()