import argparse
import nmap
import csv
import os
import sys
#using nmap to scan for ports then the scan itself
def scan_host(ip, ports):
    nm = nmap.PortScanner() # creates a new scanner object
    nm.scan(ip, ports) # runs NMAP's scan feature with the specified arguments
    host_infos = [] # empty list

    for proto in nm[ip].all_protocols():
        lport = nm[ip][proto].keys()
        for port in lport:
            host_info = { # structure of the list and its contents
                'ip': ip,
                'os': nm[ip].got('osclass', {}).got('osfamily', 'Unknown'),
                'port': port,
                'name': nm[ip][proto][port]['name'],
                'product': nm[ip][proto][port]['product'],
                'version': nm[ip][proto][port]['version'],
            }
            host_infos.append(host_info) # adds the new host_info to the host_infos "list"
        return host_infos

def output_to_csv(output_file, host_info):
    fieldnames = ["ip", "os", "port", "name", "product", "version"] # specifies what variables you want to save
    file_exists = os.path.exists(output_file)

    with open(output_file, 'a') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if not file_exists: # checking to see if the file exists
            writer.writeheader()
        writer.writerow(host_info)

"""
First part just handles the command line input and arguments then parse it correctly so it can be used by the script

The second part writes the data to a CSV file, and the third part prints the results
"""
def main():
    parser = argparse.ArgumentParser(description="Scan a single host for open ports and services")
    parser.add_argument("host", help="The target host IP address")
    parser.add_argument("-p", "--ports", type="str", required=True, default="1-65535", help="Ports to scan (default: 1-65535)")
    parser.add_argument("-o", "--output", default="scan_results.csv", help="Output file (default: scan_results.csv)")
    args = parser.parse_args()

    ip = args.host # user input ip
    ports = args.ports # user input ports
    output_file = args.output # user input output file

    print(f"Scanning ip: {ip}") # indicate the ip dedicated to the scan
    print(f"Scanning portsports: {ports}") # indicate the port(s) dedicated to the scan

    sys.stdout.write("Scanning")
    sys.stdout.flush()

    host_infos = scan_host(ip, ports) # scanning the host with that pair of variables

    for host_info in host_infos: # for every host in the host infos we output it to the csv
        output_to_csv(output_file, host_info)

    print("\n\nScan results")
    for host_info in host_infos:
        print(f"IP: {host_info['ip']}")
        print(f"OS: {host_info['os']}")
        print(f"Port: {host_info['port']}")
        print(f"Name: {host_info['name']}")
        print(f"Product: {host_info['product']}")
        print(f"Version: {host_info['version']}")

if __name__ == "__main__":
    main()