"""
Network Port Scanner Utility.

This script scans a given CIDR block to detect open ports on active hosts. It can
either scan specified ports or default to scanning the most commonly used ports.
Port ranges can be specified using a dash (e.g., 20-25). The results are displayed
graphically using Matplotlib.

Usage:
    python main.py <CIDR block> [ports]

Examples:
    python main.py 192.168.0.0/24 22,80,443
    python main.py 192.168.0.0/24 20-25
    python main.py 127.0.0.1/32
"""

import sys
import ipaddress
import socket
import threading
import time
import matplotlib.pyplot as plot

def ipformat(ip, ports):
    """
    Validate the IP address and ports list.

    Args:
        ip (str): The IP address to validate.
        ports (list): A list of ports as integers.

    Returns:
        bool: True if the IP address and ports are valid, False otherwise.
    """
    try:
        ipaddress.ip_address(ip)
        for port in ports:
            if port < 0 or port > 65535:
                return False
        return True
    except ValueError:
        return False

def get_ip_addresses(cidr_block):
    """
    Generate a list of host IPs from a CIDR block.

    Args:
        cidr_block (str): The CIDR block to parse.

    Returns:
        list: A list of host IP addresses as strings.
    """
    try:
        network = ipaddress.ip_network(cidr_block, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        print("Invalid CIDR block.")
        sys.exit(1)

def parse_ports(port_arg):
    """
    Parse the ports argument, handling ranges and individual ports.

    Args:
        port_arg (str): The ports string (e.g., "80,443,20-25").

    Returns:
        list: A list of individual ports as integers.
    """
    ports = []
    try:
        for part in port_arg.split(","):
            if "-" in part:
                start, end = map(int, part.split("-"))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
    except ValueError:
        print("Invalid port format.")
        sys.exit(1)
    return ports

def is_port_open(ip, port, timeout=1):
    """
    Check if a given port on an IP address is open.

    Args:
        ip (str): The target IP address.
        port (int): The target port.
        timeout (int, optional): Timeout for the connection attempt. Defaults to 1 second.

    Returns:
        bool: True if the port is open, False otherwise.
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (socket.timeout, socket.error):
        return False

def display_results(results):
    """
    Display scan results as a horizontal bar chart using Matplotlib.

    Args:
        results (list): A list of tuples where each tuple contains an IP and an open port.
    """
    services = [f"{ip}:{port}" for ip, port in results]
    counts = [1] * len(results)

    plot.barh(services, counts, color="gold")
    plot.xlabel("open ports")
    plot.title("open ports")
    plot.tight_layout()
    plot.show()

def thread_scan(ips, ports, results, start, end):
    """
    Perform a port scan on a range of IPs using threads.

    Args:
        ips (list): List of IP addresses.
        ports (list): List of ports to scan.
        results (list): Shared list to store scan results.
        start (int): Start index for the range of IPs.
        end (int): End index for the range of IPs.
    """
    for ip in ips[start:end]:
        for port in ports:
            if is_port_open(ip, port):
                results.append((ip, port))

def scan(ips, ports):
    """
    Perform a threaded scan on the provided IPs and ports.

    Args:
        ips (list): List of IP addresses.
        ports (list): List of ports to scan.

    Returns:
        list: A list of tuples containing IPs and their open ports.
    """
    results = []
    threads = []
    num_threads = min(10, len(ips))
    chunk_size = len(ips) // num_threads

    for i in range(num_threads):
        start = i * chunk_size
        end = (i + 1) * chunk_size if i != num_threads - 1 else len(ips)
        thread = threading.Thread(target=thread_scan, args=(ips, ports, results, start, end))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    return results

def __main__(argv):
    if len(argv) < 2:
        print("example usage: python main.py <ip> [ports]")
        return 0

    try:
        ip = argv[1]
        ports = parse_ports(argv[2]) if len(argv) > 2 else [80, 443, 22, 445]

        ips = get_ip_addresses(ip)
        print(ips, ports)

        start_time = time.time()
        results = scan(ips, ports)
        elapsed_time = time.time() - start_time

        if results:
            print("open ports:")
            service_map = {80: "HTTP", 443: "HTTPS", 22: "SSH", 445: "SMB"}
            for ip, port in results:
                service = service_map.get(port, "unknown service")
                print(f"{ip}:{port} ({service})")

            display_results(results)
        else:
            print("no open ports found")

        print(f"time: {elapsed_time:.2f} seconds")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if threading.active_count() == 1:
        __main__(sys.argv)
        # python -m http.server 8000 for server
        # python main.py 127.0.0.1/32 7999-8001,80
