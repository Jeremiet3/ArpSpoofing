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

request = 0
reply = 0

count_replys_flag = False
validate_mac_flag = False
duplicates_ips_flag = False

WARNING = "Warning! You are under attack!"
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


def duplicates_ips():
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
                if mac in mac_ip_map:
                    with lock_duplicates_ips_flag:
                        duplicates_ips_flag = True
                        return
                else:
                    mac_ip_map[mac] = [ip]


def arp_monitor_callback(packet):
    # Each packet sniffed is processed in three different threads simultaneously
    count_replys_thread = threading.Thread(target=lambda: count_replys(packet))
    count_replys_thread.start()

    validate_mac_thread = threading.Thread(target=lambda: validate_mac(packet))
    validate_mac_thread.start()

    duplicate_thread = threading.Thread(target=lambda: duplicates_ips())
    duplicate_thread.start()


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

def warning_off():
    global count_replys_flag, validate_mac_flag, duplicates_ips_flag, reply, request
    counter = 0

    while True:
        with lock_count_replys_flag:
            if count_replys_flag:
                counter += 1
        with lock_validate_mac_flag:
            if validate_mac_flag:
                counter += 1
        with lock_duplicates_ips_flag:
            if duplicates_ips_flag:
                counter += 1

        if counter >= MIN_INDICATORS:
            print(WARNING)
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

            counter = 0

my_ip = get_my_ip()

if my_ip:
    warning_alarm_thread = threading.Thread(target=lambda: warning_off())
    warning_alarm_thread.start()
    start_sniffing()
else:
    print("Failed to retrieve IP address.")
