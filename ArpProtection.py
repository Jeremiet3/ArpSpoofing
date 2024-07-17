from scapy.all import *
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import ARP, getmacbyip
import threading
import subprocess

# Create a lock
lock_request = threading.Lock()
lock_reply = threading.Lock()
lock_count_replys_flag = threading.Lock()
lock_validate_mac_flag = threading.Lock()
lock_duplicates_ips_flag = threading.Lock()
lock_update = threading.Lock()
lock_permanent = threading.Lock()

request = 0
reply = 0

count_replys_flag = False
validate_mac_flag = False
duplicates_ips_flag = False

MIN_INDICATORS = 2
ARP_FAIL = "ff:ff:ff:ff:ff:ff"

def count_replys(packet):
    global request, reply, count_replys_flag


    if ARP in packet and packet[ARP].op == 2 and packet[ARP].psrc != my_ip:  # ARP reply
        with lock_reply:
            reply += 1
    elif ARP in packet and packet[ARP].op == 1 and packet[ARP].psrc == my_ip:  # ARP request from my device
        with lock_request:
            request += 1

    if reply > request:
        with lock_count_replys_flag:
            count_replys_flag = True



def validate_mac(packet):
    global validate_mac_flag

    if ARP in packet and packet[ARP].op == 2 and packet[ARP].psrc != my_ip:  # ARP reply
        source_real_mac = getmacbyip(packet[ARP].psrc)
        response_mac = packet[ARP].hwsrc
        if source_real_mac != ARP_FAIL and source_real_mac != response_mac:
            with lock_validate_mac_flag:
                validate_mac_flag = True


def duplicates_ips(packet):
    global duplicates_ips_flag

    # Run the ip n command and capture its output
    ip_output = subprocess.check_output(['ip', 'n']).decode('utf-8')
    ip_lines = ip_output.splitlines()
    # Create a dictionary to store MAC addresses and their associated IP addresses
    mac_ip_map = {}

    # Extract MAC-IP pairs and store them in the dictionary
    for line in ip_lines:
        parts = line.split()
        if len(parts) >= 5:
            mac = parts[4]
            ip = parts[0]
            # Check if the IP address is an IPv4 address
            if ':' not in ip:  # Simple check to exclude IPv6 addresses
                # the arp table is permanent
                mac_ip_map[mac] = [ip]

    if ARP in packet and packet[ARP].hwsrc in mac_ip_map and mac_ip_map[packet[ARP].hwsrc] != packet[ARP].psrc:
        with lock_duplicates_ips_flag:
            duplicates_ips_flag = True
def arp_monitor_callback(packet):
    # Each packet sniffed is processed in three different threads simultaneously
    count_replys_thread = threading.Thread(target=lambda: count_replys(packet))
    count_replys_thread.start()

    validate_mac_thread = threading.Thread(target=lambda: validate_mac(packet))
    validate_mac_thread.start()

    duplicate_thread = threading.Thread(target=lambda: duplicates_ips(packet))
    duplicate_thread.start()

    protection_thread = threading.Thread(target=lambda: warning_off(packet))
    protection_thread.start()

    permanent_thread = threading.Thread(target=lambda: update_arp_to_permanent())
    permanent_thread.start()


def get_my_ip():
    response = sr1(IP(dst="8.8.8.8") / ICMP(), verbose=False)
    # Extract source IP address from the response packet
    if response:
        return response[IP].dst
    else:
        return None


def start_sniffing():
    # Start sniffing ARP packets
    sniff(prn=arp_monitor_callback, iface="eth0", filter="arp", store=0)

def check_arp_entry(ip_address, interface):
    # Run ip neigh show to check if the IP address exists in ARP table
    arp_cmd = ['ip', 'neigh', 'show', 'to', ip_address, 'dev', interface]
    result = subprocess.run(arp_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    # Check if the IP exists in ARP table
    return result.returncode == 0

def update_static_arp(ip_address, new_mac_address, interface):
    with lock_update:
        try:
            if check_arp_entry(ip_address, interface):
                # Delete existing ARP entry
                delete_cmd = ['sudo', 'ip', 'neigh', 'delete', ip_address, 'dev', interface]
                subprocess.run(delete_cmd, check=True)

            # Add updated ARP entry
            add_cmd = ['sudo', 'ip', 'neigh', 'add', ip_address, 'lladdr', new_mac_address, 'nud', 'permanent', 'dev', interface]
            subprocess.run(add_cmd, check=True)
        except subprocess.CalledProcessError as e:
            return


def warning_off(pkt):
    global count_replys_flag, validate_mac_flag, duplicates_ips_flag, reply, request
    counter = 0

    with lock_count_replys_flag:
        if count_replys_flag:
            counter += 1
    with lock_validate_mac_flag:
        if validate_mac_flag:
            counter += 1
    with lock_duplicates_ips_flag:
        if duplicates_ips_flag:
            counter += 1

    if counter < MIN_INDICATORS:
        if ARP in pkt and pkt[ARP].op == 2:
            # Extract IP, MAC, and interface
            ip_address = pkt[ARP].psrc
            if ip_address != my_ip:
                mac_address = pkt[ARP].hwsrc
                interface = pkt.sniffed_on
                update_static_arp(ip_address, mac_address, interface)

        with lock_count_replys_flag:
            count_replys_flag = False
        with lock_reply:
            reply = 0
        with lock_request:
            request = 0

        with lock_validate_mac_flag:
            validate_mac_flag = False

        with lock_duplicates_ips_flag:
            duplicates_ips_flag = False

def update_arp_to_permanent():
    with lock_permanent:
        # Get the ARP table entries
        arp_cmd = ['ip', 'neigh', 'show']
        result = subprocess.run(arp_cmd, stdout=subprocess.PIPE, text=True)

        # Split the output into lines and iterate over each line
        for line in result.stdout.splitlines():
            # Split the line to extract IP, MAC, and interface
            parts = line.split()
            if len(parts) >= 5 and ':' not in parts[0]:
                ip_address = parts[0]
                mac_address = parts[4]
                interface = parts[2]
                # Update ARP entry to permanent
                update_cmd = ['sudo', 'ip', 'neigh', 'replace', ip_address, 'lladdr', mac_address, 'nud', 'permanent', 'dev', interface]
                subprocess.run(update_cmd, check=True)

my_ip = get_my_ip()

if my_ip:
    update_arp_to_permanent()
    start_sniffing()
else:
    print("Failed to retrieve IP address.")
