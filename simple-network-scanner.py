import scapy.all as scapy

def scan(ip):
    # Create an ARP request packet
    arp_request = scapy.ARP(pdst=ip)

    # Create an Ethernet frame packet
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    # Combine the ARP request packet and the Ethernet frame packet
    arp_request_broadcast = broadcast/arp_request

    # Send the packet and receive responses
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    # Initialize a list to store the results
    clients_list = []

    # Iterate over each response and extract MAC and IP addresses
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)

    return clients_list

def print_result(results_list):
    print("IP\t\t\tMAC Address")
    print("-----------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])

# Example usage
target_ip = "192.168.1.1/24"  # Adjust the target IP range as per your network configuration
scan_result = scan(target_ip)
print_result(scan_result)
