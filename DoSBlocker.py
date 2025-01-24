import os
import sys
import time
from collections import defaultdict # used to store and manage packet count for each ip address
from scapy.all import sniff, IP # allows us to analyze network packets 

THRESHHOLD = 40 # represets the maximum allowed packet rate per second for an ip address
print(f"Threshold: {THRESHHOLD}")

"""
Counts the amount of packets coming from an ip, therefore establishing a packet rate, 
which is then compared to the threshold, 
and if the threshold is broken then the ip will get blocked.
"""
def packet_callback(packet):
    src_ip = packet[IP].src
    packet_count[src_ip] += 1
    current_time = time.time()
    time_interval = current_time - start_time[0] # finding the time interval by subtracting the current time with the start time.

    if time_interval >= 1:
        for ip, count in packet_count.items():
            packet_rate = count / time_interval # finding packet rate by dividing the count by the interval
            print(f"IP: {ip}, Packet Rate: {packet_rate}") # for debugging purposes
            if packet_rate > THRESHHOLD and ip not in blocked_ips: # checking if packet rate exceeds threshold the threshhold and checks if ip already is blocked.
                print(f"Blocking IP: {ip}, packet rate: {packet_rate}")
                os.system(f"iptables -A input -s {ip} -j DROP") # this uses the iptables command to block the specific ip
                blocked_ips.add(ip) # adds to the blocked ip sets to keep track of blocked IPs
        
        packet_count.clear() # clears the packets
        start_time[0] = current_time # restarts the time_interval
    
    """
    Main function:
    Checking root privileges, 
    initializing packet count, 
    start_time variables, 
    start packet sniffing with specified callback function.
    """
    if __name__ == "__main__":
        if os.geteuid() != 0: # checks if the script is running with root privileges, we need root to access raw network traffic and we need to modify the systems firewall to actually block the IP
            print("This script requires root privileges.")
            sys.exit(1)

            packet_count = defaultdict(int)
            start_time = [time.time()]
            blocked_ips = set()

            print("Monitoring network traffic...")
            sniff(filter="ip", prn=packet_callback) # sniffing ip packets and passing them to the callback function for analysis