# Personal Firewall

## Overview
A lightweight personal firewall in Python using Scapy to sniff packets and apply filtering rules.

## Features
- Packet sniffing with Scapy
- Simple rule-based filtering (block/allow IPs and ports)
- Logs blocked packets to `firewall.log`

## How to run
1. Install dependencies:

pip install -r requirements.txt
2. Customize your rules in `rules.txt`.
3. Run firewall:
python firewall.py
pgsql

4. Stop with Ctrl+C.
## Notes
- Requires administrator/root privileges to sniff packets.
- Tested on Linux (Windows may require different setup).
- Optional: Use iptables for system-level filtering.
