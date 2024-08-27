import sys
import time
from scapy.all import ARP, Ether, srp

def network_scan(network):
    arp_request = ARP(pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    active_hosts = {}  # Dictionary to store active hosts

    for i in range(5):
        # Display scanning message with increasing dots
        for dots in range(1, 10):
            sys.stdout.write(f"\r[*] Scanning network  {'.' * dots} ")
            sys.stdout.flush()
            time.sleep(0.15)  # Pause for a short duration

        answered = srp(arp_request_broadcast, timeout=4, verbose=False)[0]

        for sent, received in answered:
            ip = received.psrc
            mac = received.hwsrc
            # If the host is already in the dictionary, increment the count
            if ip in active_hosts:
                active_hosts[ip]['count'] += 1
            else:
                active_hosts[ip] = {'mac': mac, 'count': 1}

    # Clear the scanning message line
    sys.stdout.write("\r" + " " * 20 + "\r")
    sys.stdout.flush()

    # Print hosts that responded at least once
    for ip, info in active_hosts.items():
        if info['count'] > 0:
            print(f"Host: {ip}, MAC: {info['mac']}")
            
if __name__ == "__main__":        
    # # Example usage
    # network = "192.168.254.0/24"  # Replace with your network range
    network_scan(network)
