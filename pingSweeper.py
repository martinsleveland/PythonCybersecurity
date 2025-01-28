import sys # interact with the command line
from scapy.all import ICMP, IP, sr1
from netaddr import IPNetwork # handle ip address manipulation

def ping_sweep(network, netmask):
    live_hosts = [] # initialize an empty list to store live hosts
    total_hosts = 0
    scanned_hosts = 0

    ip_network = IPNetwork(network + '/' + netmask) # determens the actual ips on the subnet
    for host in ip_network.iter_hosts(): # .inter helps us loop through the ips using a for loop
        total_hosts += 1
    
    """
    Here we run a for loop which creates an iter object for all the ip's
    and checks if they respond to ICMP echo request.
    If a response is received, it's considered live and added to the live_hosts list.
    The progress is displayed using the print function.
    Finally, it returns the list of live hosts.

    sr1 is a scapy function that sends a packet and waits for a single response
    """
    for host in ip_network.iter_hosts():
        scanned_hosts += 1
        print(f"Scanning: {scanned_hosts}/{total_hosts}", end="\r")
        response = sr1(IP(dst=str(host))//ICMP(), timeout=1, verbose=0) # verbosity is adjusted for speed
        if response is not None: # only print if the response has any value
            live_hosts.append(str(host)) 
            print(f"Host {host} is online!")
    
    return live_hosts # returns the list of all the ips and return them back to the main fucntion

if __name__ == "__main__":
    network = sys.argv[1] # defining the subnett
    netmask = sys.argv[2] # defining the netmask

    live_hosts = ping_sweep(network, netmask)
    print("Completed!")
    print(f"Live hosts: {live_hosts}") # prints all the live hosts to the screen