#!/usr/bin/env python3
"""
Network Packet Analyzer
Author: Assistant
Description: Capture and analyze network packets with detailed information
"""

from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
import datetime
import sys
import signal
from colorama import init, Fore, Style
import argparse

# Initialize colorama for colored output
init(autoreset=True)

class PacketAnalyzer:
    def __init__(self, interface=None, count=0, filter_expr=None):
        """
        Initialize Packet Analyzer
        
        Args:
            interface: Network interface to capture from (None for all)
            count: Number of packets to capture (0 for infinite)
            filter_expr: BPF filter expression
        """
        self.interface = interface
        self.count = count
        self.filter = filter_expr
        self.packet_count = 0
        self.start_time = datetime.datetime.now()
        
        # Protocol counters
        self.stats = {
            'TCP': 0,
            'UDP': 0,
            'ICMP': 0,
            'ARP': 0,
            'Other': 0
        }
        
        # Set up signal handler for graceful exit
        signal.signal(signal.SIGINT, self.signal_handler)
        
    def signal_handler(self, sig, frame):
        """Handle Ctrl+C to show statistics"""
        print(f"\n{Fore.YELLOW}\n{'='*60}")
        print("Capture Stopped by User")
        self.show_statistics()
        sys.exit(0)
        
    def packet_handler(self, packet):
        """
        Main packet handler - called for each captured packet
        """
        self.packet_count += 1
        
        # Get current timestamp
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        
        # Print packet number and separator
        print(f"\n{Fore.CYAN}{'='*80}")
        print(f"{Fore.CYAN}Packet #{self.packet_count} - {timestamp}")
        print(f"{Fore.CYAN}{'='*80}")
        
        # Ethernet Layer
        if Ether in packet:
            eth_layer = packet[Ether]
            print(f"{Fore.GREEN}[Ethernet]")
            print(f"  Source MAC: {eth_layer.src}")
            print(f"  Destination MAC: {eth_layer.dst}")
            print(f"  Type: {hex(eth_layer.type)}")
        
        # IP Layer
        if IP in packet:
            ip_layer = packet[IP]
            print(f"{Fore.YELLOW}[IP]")
            print(f"  Source IP: {ip_layer.src}")
            print(f"  Destination IP: {ip_layer.dst}")
            print(f"  Version: {ip_layer.version}")
            print(f"  TTL: {ip_layer.ttl}")
            print(f"  Protocol: {ip_layer.proto}")
            print(f"  Length: {ip_layer.len}")
            
            # Update protocol stats
            if ip_layer.proto == 6:
                self.stats['TCP'] += 1
            elif ip_layer.proto == 17:
                self.stats['UDP'] += 1
            elif ip_layer.proto == 1:
                self.stats['ICMP'] += 1
            else:
                self.stats['Other'] += 1
                
        # TCP Layer
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"{Fore.MAGENTA}[TCP]")
            print(f"  Source Port: {tcp_layer.sport}")
            print(f"  Destination Port: {tcp_layer.dport}")
            print(f"  Sequence Number: {tcp_layer.seq}")
            print(f"  Acknowledgment: {tcp_layer.ack}")
            print(f"  Flags: {tcp_layer.flags}")
            print(f"  Window Size: {tcp_layer.window}")
            
            # Check for common services
            self.identify_service(tcp_layer.sport, tcp_layer.dport, 'TCP')
            
        # UDP Layer
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"{Fore.MAGENTA}[UDP]")
            print(f"  Source Port: {udp_layer.sport}")
            print(f"  Destination Port: {udp_layer.dport}")
            print(f"  Length: {udp_layer.len}")
            
            # Check for common services
            self.identify_service(udp_layer.sport, udp_layer.dport, 'UDP')
            
        # ICMP Layer
        elif ICMP in packet:
            icmp_layer = packet[ICMP]
            print(f"{Fore.MAGENTA}[ICMP]")
            print(f"  Type: {icmp_layer.type}")
            print(f"  Code: {icmp_layer.code}")
            
            # Interpret ICMP types
            icmp_types = {
                0: 'Echo Reply',
                3: 'Destination Unreachable',
                8: 'Echo Request',
                11: 'Time Exceeded'
            }
            print(f"  Description: {icmp_types.get(icmp_layer.type, 'Unknown')}")
            
        # ARP Layer
        elif ARP in packet:
            arp_layer = packet[ARP]
            self.stats['ARP'] += 1
            print(f"{Fore.MAGENTA}[ARP]")
            print(f"  Operation: {'Request' if arp_layer.op == 1 else 'Reply'}")
            print(f"  Source IP: {arp_layer.psrc}")
            print(f"  Source MAC: {arp_layer.hwsrc}")
            print(f"  Target IP: {arp_layer.pdst}")
            print(f"  Target MAC: {arp_layer.hwdst}")
            
        # Payload/Data
        if Raw in packet:
            payload = packet[Raw].load
            print(f"{Fore.BLUE}[Payload]")
            
            # Try to decode as text, show hex if binary
            try:
                # Try to decode as UTF-8 text
                text_payload = payload.decode('utf-8', errors='ignore')
                if text_payload.strip() and all(ord(c) < 128 for c in text_payload):
                    print(f"  Text Data: {text_payload[:100]}{'...' if len(text_payload) > 100 else ''}")
                else:
                    # Show hex dump for binary data
                    self.hex_dump(payload[:64])
            except:
                self.hex_dump(payload[:64])
                
        # Check if we've reached the packet count limit
        if self.count > 0 and self.packet_count >= self.count:
            print(f"\n{Fore.GREEN}Reached target packet count: {self.count}")
            self.show_statistics()
            sys.exit(0)
            
    def identify_service(self, sport, dport, protocol):
        """Identify common services based on port numbers"""
        common_ports = {
            80: 'HTTP',
            443: 'HTTPS',
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            110: 'POP3',
            143: 'IMAP',
            123: 'NTP',
            161: 'SNMP',
            389: 'LDAP',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            27017: 'MongoDB',
            6379: 'Redis',
            8080: 'HTTP-Alt'
        }
        
        if sport in common_ports:
            print(f"  Service (Source): {common_ports[sport]}")
        if dport in common_ports:
            print(f"  Service (Dest): {common_ports[dport]}")
            
    def hex_dump(self, data, bytes_per_line=16):
        """Display hex dump of data"""
        print("  Hex Dump:")
        for i in range(0, len(data), bytes_per_line):
            chunk = data[i:i+bytes_per_line]
            hex_str = ' '.join(f'{b:02x}' for b in chunk)
            ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            print(f"  {i:04x}: {hex_str:<{bytes_per_line*3}} {ascii_str}")
            
    def show_statistics(self):
        """Display capture statistics"""
        duration = (datetime.datetime.now() - self.start_time).total_seconds()
        
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}Capture Statistics")
        print(f"{Fore.CYAN}{'='*60}")
        print(f"Total Packets: {self.packet_count}")
        print(f"Duration: {duration:.2f} seconds")
        print(f"Average Rate: {self.packet_count/duration:.2f} packets/sec")
        print(f"\nProtocol Breakdown:")
        
        for protocol, count in self.stats.items():
            if count > 0:
                percentage = (count / self.packet_count) * 100 if self.packet_count > 0 else 0
                bar = '█' * int(percentage / 2)
                print(f"  {protocol:8}: {count:5} ({percentage:5.1f}%) {bar}")
                
    def start_capture(self):
        """Start packet capture"""
        print(f"{Fore.GREEN}Starting Packet Capture...")
        print(f"Interface: {self.interface if self.interface else 'All'}")
        print(f"Filter: {self.filter if self.filter else 'None'}")
        print(f"Press Ctrl+C to stop capture and show statistics")
        print(f"{Fore.CYAN}{'='*60}")
        
        try:
            # Start packet capture
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                filter=self.filter,
                store=False
            )
        except PermissionError:
            print(f"{Fore.RED}Error: Permission denied. Run with sudo/administrator privileges!")
            sys.exit(1)
        except Exception as e:
            print(f"{Fore.RED}Error: {e}")
            sys.exit(1)

def list_interfaces():
    """List available network interfaces"""
    print(f"{Fore.CYAN}Available Network Interfaces:")
    print(f"{Fore.CYAN}{'='*60}")
    
    interfaces = get_if_list()
    for i, iface in enumerate(interfaces, 1):
        try:
            mac = get_if_hwaddr(iface)
            ip = get_if_addr(iface)
            print(f"{i}. {Fore.GREEN}{iface}")
            print(f"   MAC: {mac}")
            print(f"   IP: {ip if ip != '0.0.0.0' else 'No IP assigned'}")
        except:
            print(f"{i}. {Fore.YELLOW}{iface} (Details unavailable)")
            
def main():
    """Main function with argument parsing"""
    parser = argparse.ArgumentParser(description='Network Packet Analyzer')
    parser.add_argument('-i', '--interface', help='Network interface to capture from')
    parser.add_argument('-c', '--count', type=int, default=0, help='Number of packets to capture (0 for infinite)')
    parser.add_argument('-f', '--filter', help='BPF filter expression (e.g., "tcp port 80")')
    parser.add_argument('-l', '--list', action='store_true', help='List available interfaces')
    
    args = parser.parse_args()
    
    if args.list:
        list_interfaces()
        sys.exit(0)
        
    # Create and start packet analyzer
    analyzer = PacketAnalyzer(
        interface=args.interface,
        count=args.count,
        filter_expr=args.filter
    )
    
    analyzer.start_capture()

if __name__ == "__main__":
    main()
