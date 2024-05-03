# Port Scanner

Port Scanner is a Python script designed to help users scan ports on a specified IP address. Its primary function is to identify open ports and optionally gather banner information from services running on those ports. The script offers several features, including the ability to scan a range of ports, display open ports, perform banner grabbing for additional service details, adjust scan speed and timeout options, and run in silent mode for minimal output.

## Installation

To use the port scanner, follow these steps:

1. Clone the repository:

$ git clone https://github.com/your_username/port-scanner.git

2. Navigate to the directory:

3. Run the script:

$ python3 portscanner.py <IP_address> [start_port end_port] [-s] [-f] [-b <port_number>] [-t <timeout>]


## Available Functions

- `is_ip_reachable(ip_address, timeout)`: Checks if the IP is reachable by attempting to connect to a common port.
- `get_banner(ip_address, port, timeout)`: Attempts to grab the banner from the specified port.
- `extract_info_from_banner(banner)`: Extracts architecture, software, and version information from the banner.
- `scan_ports(ip_address, start_port, end_port, silent, fast, grab_banner, banner_timeout)`: Scans the specified range of ports on a given IP address.
- `main()`: Main function to process command-line arguments and control the port scanning.

## Usage

To use the port scanner, execute the script `portscanner.py` with various command-line arguments:

- `<IP_address>`: The IP address of the target server.
- `[start_port end_port]`: Optional. Specify a range of ports to scan. If not provided, the scanner will scan ports 1 to 65535.
- `-s`: Optional. Run the scanner in silent mode. In this mode, only open ports will be displayed without additional information.
- `-f`: Optional. Enable fast scan mode to reduce scan time. This mode uses shorter timeouts for faster scanning.
- `-b <port_number>`: Optional. Perform banner grabbing on the specified port to gather additional information about the service running on that port.
- `-t <timeout>`: Optional. Specify the timeout value (in seconds) for banner grabbing. If not provided, the default timeout is used.

## Examples

1. Scan ports 1 to 100 on the target server `192.168.1.1`:

python3 portscanner.py 192.168.1.1 1 100

2. Perform a fast scan on ports 1 to 100 on the target server `192.168.1.1`:

$ python3 portscanner.py 192.168.1.1 1 100 -f

3. Scan port 80 on the target server `example.com` and perform banner grabbing:

$ python3 portscanner.py example.com -b 80

4. Scan ports 1 to 100 on the target server `192.168.1.1` silently:

$ python3 portscanner.py 192.168.1.1 1 100 -s

5. Scan port 443 on the target server `example.com` with a custom timeout of 5 seconds:

$ python3 portscanner.py example.com -b 443 -t 5


## Dependencies

- Python 3.x

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Acknowledgments

This script is inspired by various port scanning tools and tutorials available online, with special thanks to the developers and contributors of the Python socket module.

This README file provides comprehensive installation instructions, details about available functions, usage examples, dependencies, license information, and acknowledgments. Feel free to customize it further to suit your preferences or provide additional information!


