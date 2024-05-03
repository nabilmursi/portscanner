import socket
import sys
import re
from datetime import datetime

def is_ip_reachable(ip_address, timeout=1):
    """ Check if the IP is reachable by attempting to connect to a common port. """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip_address, 80))
        return True
    except (socket.timeout, socket.error):
        return False

def get_banner(ip_address, port, timeout=3):
    """ Attempt to grab the banner from the specified port. """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip_address, port))
            banner = sock.recv(1024).decode().strip()  # Receive a small amount of data
            return banner
    except Exception as e:
        print(f"Error: {e}")
        return "No banner available or connection closed by host."

def extract_info_from_banner(banner):
    """ Extract architecture, software, and version information from the banner. """
    architecture = ""
    software = ""
    version = ""

    # Extract architecture information
    if "64-bit" in banner:
        architecture = "64-bit"
    elif "32-bit" in banner:
        architecture = "32-bit"

    # Extract software and version information using regular expressions
    software_match = re.search(r'Server: (.+)', banner)
    version_match = re.search(r'Version: (.+)', banner)
    
    if software_match:
        software = software_match.group(1)
    if version_match:
        version = version_match.group(1)
    
    if not software and not version:
        # If banner doesn't contain Server and Version information, try to parse the banner
        parts = banner.split('\n')
        for part in parts:
            if 'Server:' in part:
                software = part.split(':')[-1].strip()
            elif 'Version:' in part:
                version = part.split(':')[-1].strip()
    
    return architecture, software, version

def adjust_timeout(port, banner_timeout):
    """ Adjust timeout dynamically based on the specified port. """
    if banner_timeout:
        return banner_timeout
    else:
        return 3  # Triple the timeout for banner grabbing

def scan_ports(ip_address, start_port=1, end_port=65535, silent=False, fast=False, grab_banner=False, banner_timeout=None):
    """ Scans the specified range of ports on a given IP address. """
    open_ports = []
    if not silent:
        print(f"{'Fast' if fast else 'Normal'} scan starting on {ip_address} from port {start_port} to {end_port}")
    
    timeout = 0.05 if fast else 0.2  # Adjusted timeouts for fast and normal modes
    if grab_banner and start_port == end_port:
        timeout = adjust_timeout(start_port, banner_timeout)  # Set timeout for banner grabbing
    for port in range(start_port, end_port + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((ip_address, port))
                if result == 0:
                    open_ports.append(port)
                    if grab_banner and start_port == end_port:
                        print(f"Port {port} is open")
                        banner = get_banner(ip_address, port, banner_timeout)
                        print(f"Retrieved banner from port {port}: {banner}")
                        architecture, software, version = extract_info_from_banner(banner)
                        if architecture:
                            print(f"Architecture: {architecture}")
                        if software:
                            print(f"Software: {software}")
                        if version:
                            print(f"Version: {version}")
                    elif not silent:
                        print(f"Port {port} is open")
        except KeyboardInterrupt:
            print("Scan aborted by user.")
            sys.exit()
        except socket.error:
            continue

    return open_ports

def main():
    """ Main function to process command line arguments and control the port scanning. """
    if len(sys.argv) < 2 or '-h' in sys.argv:
        print("Usage: python3 portscanner.py <IP_address> [start_port end_port] [-s for silent] [-f for fast scan] [-b <port_number> for banner grabbing] [-t <timeout> for banner grabbing]")
        return

    ip_address = sys.argv[1]
    start_port = 1
    end_port = 65535
    silent = '-s' in sys.argv
    fast = '-f' in sys.argv
    grab_banner = '-b' in sys.argv
    banner_timeout = None

    # Checking for port range arguments
    if len(sys.argv) >= 4 and sys.argv[2].isdigit():
        start_port = int(sys.argv[2])
        try:
            end_port = int(sys.argv[3])
        except ValueError:
            pass

    # Check if banner grabbing is requested and if it's applicable
    if grab_banner and '-b' in sys.argv:
        index_b = sys.argv.index('-b')
        if index_b < len(sys.argv) - 1:
            port_to_scan = int(sys.argv[index_b + 1])
            start_port = port_to_scan
            end_port = port_to_scan
            grab_banner = True  # Ensure banner grabbing is enabled
        else:
            print("Error: No port number provided with -b option.")
            return

    # Check if banner timeout is specified
    if '-t' in sys.argv:
        index_t = sys.argv.index('-t')
        if index_t < len(sys.argv) - 1:
            banner_timeout = int(sys.argv[index_t + 1])
        else:
            print("Error: No timeout value provided with -t option.")
            return

    if silent:
        print("Running in silent mode...")

    start_time = datetime.now()
    open_ports = scan_ports(ip_address, start_port, end_port, silent, fast, grab_banner, banner_timeout)
    end_time = datetime.now()
    time_taken = end_time - start_time

    if not silent:
        if open_ports:
            print("Open Ports:")
            for port in open_ports:
                print(port)
        else:
            print("No open ports found.")
        print(f"Time taken: {time_taken}")
    else:
        for port in open_ports:
            print(port)

if __name__ == "__main__":
    main()
