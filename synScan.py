import os
from scapy.all import ICMP, IP, sr1, TCP, sr
from ipaddress import ip_network
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

print_lock = Lock()
num_threads = os.cpu_count()

"""
Checks if the host is alive by sending an ICMP echo request
"""
def ping(host):
    response = sr1(IP(dst=str(host))/ICMP(), timeout=1, verbose=0)
    if response is not None:
        return str(host) # return the host ip if the response has value
    return None
"""
Checks all the ports in the subnet
"""
def ping_sweep(network, netmask):
    live_hosts = []
    hosts = list(ip_network(network + '/' + netmask.hosts()))
    total_hosts = len(hosts)

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = {executor.submit(ping, host): host for host in hosts}
        for i, future in enumerate(as_completed(futures), start=1):
            host = futures[future]
            result = future.result()
            if result is not None:
                with print_lock:
                    print(f"{i}/{total_hosts} - Host {result} is live")
                    live_hosts.append(result)
    
    return live_hosts

"""
Scans the ports for flags
"""
def scan_port(args):
    ip, port = args
    response = sr1(IP(dst=ip, dport=port, flags="S"), timeout=1, verbose=0)
    if response is not None and response[TCP].flags == "SA":
        return port
    return None


def port_scan(ip, ports):
    open_ports = []
    total_ports = len(ports)

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = {executor.submit(scan_port, (ip, port)): port for port in ports}
        for i, future in enumerate(as_completed(futures), start=1):
            port = futures[future]
            result = future.result()
            if result is not None:
                with print_lock:
                    print(f"Port {port} is open on host {ip}!")
                    open_ports.append(result)
    
    return open_ports

def get_live_hosts_and_ports(network, netmask):
    live_hosts = ping_sweep(network, netmask)
    host_port_mapping = {}
    ports = range(0, 1024)
    for host in live_hosts:
        open_ports = port_scan(host, ports)
        host_port_mapping[host] = open_ports
    
    return host_port_mapping

if __name__ == "__main__":
    import sys
    network = sys.argv[1]
    netmask = sys.argv[2]
    host_port_mapping = get_live_hosts_and_ports(network, netmask)
    for host, open_ports in host_port_mapping.items():
        print(f"Host: {host} has the following open port(s): {open_ports}!")
