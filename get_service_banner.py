import sys # interact with the command line
import argparse # parsing of the command line arguments
import socket # handle network communication

# socket is basically just a combination of a ip and port

def get_service_banner(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # first we create a socket object
        sock.settimeout(3)
        sock.connect((ip, int(port))) # connects through the ip and port we specify in the arguments
        sock.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n") # send GET request to specific socket
        banner = sock.recv(1024) # recive reponse and save as a string
        sock.close()

        return banner.decode('utf-8', errors='ignore')
    except Exception:
        return None
    
def main():
    parser = argparse.ArgumentParser(description='Service banner')
    parser.add_argument('ip', help='IP address to scan')
    parser.add_argument('-p', '--ports', required=True, help='Ports to scan (Comma seperated)')

    args = parser.parse_args()

    ip = args.ip # the argument for the ip
    ports = [port.strip() for port in args.ports.split(',')] # allows to add multiple ports seperated by commas

    print(f"Scanning IP: {ip}!")

    for port in ports:
        print(f"Scanning Port: {port} on IP: {ip}!")
        banner = get_service_banner(ip, port)
        if banner:
            print(f"Service banner for port {port} on IP {ip}:\n{banner}\n")
        else:
            print(f"No service banner found for port {port} on IP {ip}\n")

if __name__ == "__main__":
    main()