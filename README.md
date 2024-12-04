# Python Cybersecurity Tools

A collection of Python scripts for cybersecurity tasks and network monitoring.

## Tools

### 1. DNS Query Monitor (`01dnsquerymonitor.py`)

A Python script that monitors and analyzes DNS queries on your network in real-time.

#### Features:
- Captures and displays DNS queries in real-time
- Shows query responses including A, AAAA, and CNAME records
- Supports both IPv4 and IPv6
- Provides detailed statistics on DNS traffic
- Works on both Linux and macOS

#### Requirements:
- Python 3
- Scapy library (`pip3 install scapy`)
- Root/sudo privileges (required for packet capture)

#### Usage:
```bash
# Linux
sudo python3 01dnsquerymonitor.py -i eth0

# macOS
sudo python3 01dnsquerymonitor.py -i en0
```

For more details, check the script's documentation.
