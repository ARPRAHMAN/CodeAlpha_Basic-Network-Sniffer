from scapy.all import *
import sys
from datetime import datetime
from termcolor import colored
import os

# Initialize packet counter and packet list for PCAP
packet_count = 0
captured_packets = []

# Output log file and PCAP file
LOG_FILE = "sniffer_output.txt"
PCAP_FILE = "sniffer_output.pcap"

def packet_callback(packet):
    """Process and display packet details, append to captured_packets."""
    global packet_count, captured_packets
    packet_count += 1
    captured_packets.append(packet)  # Store packet for PCAP
    
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        proto_name = get_protocol_name(proto)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Format output for console and file
        output = [
            colored(f"\n[+] Packet #{packet_count} Captured at {timestamp}:", "green"),
            colored(f"Source IP: {src_ip}", "cyan"),
            colored(f"Destination IP: {dst_ip}", "cyan"),
            colored(f"Protocol: {proto_name} ({proto})", "yellow")
        ]
        
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            output.extend([
                colored(f"Source Port: {src_port}", "blue"),
                colored(f"Destination Port: {dst_port}", "blue")
            ])
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            output.extend([
                colored(f"Source Port: {src_port}", "blue"),
                colored(f"Destination Port: {dst_port}", "blue")
            ])
        
        if Raw in packet:
            payload = packet[Raw].load
            try:
                payload_decoded = payload.decode('utf-8', errors='ignore')
                output.append(colored(f"Payload: {payload_decoded[:50]}...", "white"))
            except:
                output.append(colored(f"Payload: {payload.hex()[:50]}... (Hex)", "white"))
        
        # Print to console
        for line in output:
            print(line)
        
        # Log to file (strip color codes)
        with open(LOG_FILE, "a") as f:
            for line in output:
                plain_line = line.replace("\x1b[32m", "").replace("\x1b[36m", "").replace("\x1b[33m", "").replace("\x1b[34m", "").replace("\x1b[37m", "").replace("\x1b[0m", "")
                f.write(plain_line + "\n")

def get_protocol_name(proto_num):
    """Map protocol numbers to names."""
    protocols = {1: "ICMP", 6: "TCP", 17: "UDP"}
    return protocols.get(proto_num, f"Unknown ({proto_num})")

def main():
    """Main function to start sniffing and save packets."""
    if len(sys.argv) != 2:
        print(f"Usage: sudo python3 {sys.argv[0]} <interface>")
        sys.exit(1)
    
    interface = sys.argv[1]
    print(f"[*] Starting network sniffer on interface {interface}...")
    print(f"[*] Logging output to {LOG_FILE} and saving packets to {PCAP_FILE}")
    
    # Clear previous log and PCAP files if they exist
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)
    if os.path.exists(PCAP_FILE):
        os.remove(PCAP_FILE)
    
    try:
        # Sniff packets with TCP or UDP filter
        sniff(
            iface=interface,
            prn=packet_callback,
            filter="tcp or udp",
            store=1  # Store packets for PCAP
        )
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n[*] Stopping sniffer. {packet_count} packets captured.")
        # Save captured packets to PCAP file
        if captured_packets:
            wrpcap(PCAP_FILE, captured_packets)
            print(f"[*] Packets saved to {PCAP_FILE}")
        sys.exit(0)

if __name__ == "__main__":
    main()
