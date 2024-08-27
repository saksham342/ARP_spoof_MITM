# ARP Spoofing and Network Scanning Tool

This project provides a Python-based tool for performing ARP spoofing and network scanning. It utilizes the Scapy library for packet crafting and sniffing, as well as threading to run multiple tasks simultaneously.

## Features

- **Network Scanning**: Identifies active hosts in a given network range by sending ARP requests and logging responses.
- **ARP Spoofing**: Spoofs ARP tables of target and gateway IPs to intercept network traffic.
- **Packet Sniffing**: Captures packets, particularly HTTP headers, from the network interface for analysis.

## How It Works

1. **Network Scan**: The tool first scans the specified network to identify active hosts.
2. **ARP Spoofing**: It then starts ARP spoofing between the target and gateway to intercept traffic.
3. **Packet Sniffing**: Captured packets are analyzed for specific information, such as HTTP headers.

## Usage

1. Run the `network_scan()` function to identify active devices on your network.
2. Input the target and gateway IP addresses when prompted.
3. The tool will initiate ARP spoofing and packet sniffing.

```sh
python mitmARPSpoof.py
