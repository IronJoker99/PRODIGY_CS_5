import scapy.all as scapy
import re

def get_network_interfaces():
    """
    Retrieves the list of available network interfaces.
    
    Returns:
        list: List of available network interfaces.
    """
    interfaces = scapy.get_if_list()
    return [interface for interface in interfaces if re.match(r'(eth|wlan|enp)\d+', interface)]

def sniff_packets(interface, count):
    """
    Sniffs network packets on the specified interface.
    
    Parameters:
        interface (str): The network interface to sniff packets on.
        count (int): The number of packets to sniff.
    """
    print("[*] Sniffing packets on interface {}...".format(interface))
    packets = scapy.sniff(iface=interface, count=count)
    print("[+] Sniffed {} packets:".format(len(packets)))
    print("")

    for packet in packets:
        print("Protocol: {}".format(packet[scapy.IP].proto))
        print("Source IP: {} --> Destination IP: {}".format(packet[scapy.IP].src, packet[scapy.IP].dst))
        print("Payload: {}".format(packet[scapy.Raw].load))
        print("")

def main():
    interfaces = get_network_interfaces()
    print("Available network interfaces:")
    for i, interface in enumerate(interfaces, start=1):
        print("{}. {}".format(i, interface))
    interface_index = int(input("Select the interface to sniff packets on: ")) - 1
    interface = interfaces[interface_index]
    count = int(input("Enter the number of packets to sniff: "))
    sniff_packets(interface, count)

if __name__ == "__main__":
    main()
