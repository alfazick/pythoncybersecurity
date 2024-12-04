#!/usr/bin/env python3
"""
DNS Query Monitor - A tool to capture and analyze DNS queries on your network

Usage:
    Linux:
        1. Find your interface name:
           $ ip addr show
           or
           $ ifconfig
           Common names: eth0, wlan0, ens33

        2. Run the script (requires root):
           $ sudo python3 01dnsquerymonitor.py -i eth0

    macOS:
        1. Find your interface name:
           $ ifconfig
           Common names: en0 (WiFi), en1, en2

        2. Run the script (requires root):
           $ sudo python3 01dnsquerymonitor.py -i en0

Options:
    -i, --interface : Network interface to monitor (required)
    -f, --filter    : Custom BPF filter (default: "udp port 53")
                      Example: sudo python3 01dnsquerymonitor.py -i en0 -f "udp port 53 and host 8.8.8.8"

Press Ctrl+C to stop monitoring and view summary statistics.

Requirements:
    - Python 3
    - Scapy library (install with: pip3 install scapy)
    - Root/sudo privileges (required for packet capture)
"""

import scapy.all as scapy
import datetime
import argparse
import collections
from collections import defaultdict
import signal
import sys

class DNSMonitor:
    def __init__(self):
        self.query_counts = defaultdict(int)
        self.domain_history = defaultdict(list)
        self.start_time = datetime.datetime.now()

    def process_packet(self, packet):
        """Process each DNS query packet"""
        if packet.haslayer(scapy.DNSQR):
            try:
                # Get DNS query information
                dns_layer = packet[scapy.DNSQR]
                qname = dns_layer.qname.decode('utf-8').rstrip('.')
                
                # Get source IP (handle both IPv4 and IPv6)
                if packet.haslayer(scapy.IP):
                    src_ip = packet[scapy.IP].src
                elif packet.haslayer(scapy.IPv6):
                    src_ip = packet[scapy.IPv6].src
                else:
                    return  # Skip if no IP layer found

                # Record the query
                self.query_counts[qname] += 1
                timestamp = datetime.datetime.now()
                self.domain_history[qname].append({
                    'timestamp': timestamp,
                    'source_ip': src_ip
                })

                # Print the query details
                print(f"\n[{timestamp}] DNS Query:")
                print(f"Source IP: {src_ip}")
                print(f"Domain: {qname}")
                print(f"Total queries for this domain: {self.query_counts[qname]}")
                
                # If it's a response, print the answer
                if packet.haslayer(scapy.DNSRR):
                    answers = []
                    for i in range(packet[scapy.DNS].ancount):
                        rr = packet[scapy.DNSRR][i]
                        if rr.type == 1:  # A record
                            answers.append(f"A: {rr.rdata}")
                        elif rr.type == 28:  # AAAA record
                            answers.append(f"AAAA: {rr.rdata}")
                        elif rr.type == 5:  # CNAME record
                            answers.append(f"CNAME: {rr.rdata.decode('utf-8')}")
                    if answers:
                        print("Answers:", ", ".join(answers))
                
            except Exception as e:
                print(f"Error processing packet: {e}")

    def print_summary(self):
        """Print summary statistics"""
        print("\n=== DNS Monitoring Summary ===")
        duration = datetime.datetime.now() - self.start_time
        print(f"\nMonitoring Duration: {duration}")
        
        if self.query_counts:
            print("\nTop 10 Queried Domains:")
            sorted_domains = sorted(self.query_counts.items(), key=lambda x: x[1], reverse=True)
            for domain, count in sorted_domains[:10]:
                print(f"{domain}: {count} queries")
                # Show unique source IPs for this domain
                unique_ips = set(entry['source_ip'] for entry in self.domain_history[domain])
                print(f"  └─ From {len(unique_ips)} unique IPs: {', '.join(list(unique_ips)[:3])}{'...' if len(unique_ips) > 3 else ''}")
            
            total_queries = sum(self.query_counts.values())
            print(f"\nTotal Statistics:")
            print(f"- Unique Domains: {len(self.query_counts)}")
            print(f"- Total DNS Queries: {total_queries}")
            
            # Calculate query frequency
            queries_per_second = total_queries / duration.total_seconds()
            print(f"- Query Frequency: {queries_per_second:.2f} queries/second")
            
            # Show all unique source IPs
            all_ips = set()
            for domain_history in self.domain_history.values():
                for entry in domain_history:
                    all_ips.add(entry['source_ip'])
            print(f"- Unique Source IPs: {len(all_ips)}")
        else:
            print("\nNo DNS queries captured during this session.")

def main():
    # Configure Scapy for better debugging
    scapy.conf.verb = 0  # Disable verbose mode
    
    parser = argparse.ArgumentParser(description='Monitor DNS queries on the network')
    parser.add_argument('-i', '--interface', required=True, help='Network interface to monitor')
    parser.add_argument('-f', '--filter', default='udp port 53', help='BPF filter for capturing packets')
    args = parser.parse_args()
    
    monitor = DNSMonitor()
    
    def signal_handler(sig, frame):
        print("\nStopping DNS monitoring...")
        monitor.print_summary()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    print(f"Starting DNS monitoring on interface {args.interface}")
    print("Press Ctrl+C to stop and view summary")
    print(f"Using filter: {args.filter}")
    print("Waiting for DNS queries...")

    try:
        # Start packet capture
        scapy.sniff(
            iface=args.interface,
            filter=args.filter,
            prn=monitor.process_packet,
            store=0
        )
    except Exception as e:
        print(f"Error during packet capture: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
