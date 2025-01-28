import sys
import get_service_banner
import os_fingerprint
import synScan
import pingSweeper
from FirstPart import DoSBlocker
from FirstPart import PacketFlooder
from FirstPart import StringDetectionFirewall


def main():
    if len(sys.argv) != 3:
        print("Usage: python service_banner_scanner.py <subnet> <mask>")
        sys.exit(1)
    
    subnet = sys.argv[1]
    mask = sys.argv[2]

    live_hosts = pingSweeper.ping_sweep(subnet, str(mask))
    print("Ping sweep completed!")

    for host in live_hosts:
        open_ports = synScan.port_scan(host, list(range(1, 1024)))
        print(f"Open ports on host {host}: {open_ports}\n")
        
        for port in open_ports:
            host_infos = pingSweeper.scan_host(host, str(port))
            for host_info in host_infos:
                get_service_banner.output_to_csv("scan_results.csv", host_info)
                print("\nScan results:")
                for k, v in get_service_banner.items():
                    print(f"{k}: {v}")
                print()

if __name__ == "__main__":
    main()