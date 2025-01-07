import sys
import ipaddress
import socket
import threading
import time
import matplotlib.pyplot as plot

def ipformat(ip, ports):
    if(ipaddress.ip_address(ip)):
        for port in ports:
            if(not port.isdigit()):
                return False
            if(int(port) < 0 or int(port) > 65535):
                return False
        return True
    return False

def get_ip_addresses(cidr_block):
    network = ipaddress.ip_network(cidr_block, strict=False)
    return [str(ip) for ip in network.hosts()]

def is_port_open(ip, port, timeout=1):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (socket.timeout, socket.error):
        return False
    
def display_results(results):
    #dummy data
    results.append(("192.168.0.254", 1234))

    services = [f"{ip}:{port}" for ip, port in results]
    counts = [1] * len(results)
    
    plot.barh(services, counts, color="gold")
    plot.xlabel("open ports")
    plot.title("open ports")
    plot.tight_layout()
    plot.show()

def thread_scan(ips, ports, results, start, end):
    for ip in ips[start:end]:
        for port in ports:
            if is_port_open(ip, port):
                results.append((ip, port))

def scan(ips, ports):
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
    if(len(argv) < 2):
        print("example usage: python main.py <ip> [ports]")
        return 0

    ip = argv[1]
    ports = argv[2].split(",") if len(argv) > 2 else ["80", "443", "22", "445"]

    ips = get_ip_addresses(ip)
    print(ips, ports)

    start_time = time.time()
    results = scan(ips, ports)
    elapsed_time = time.time() - start_time

    if results:
        print("open ports:")
        service_map = {80: "HTTP", 443: "HTTPS", 22: "SSH", 445: "SMB"}
        for ip, port in results:
            service = service_map.get(int(port), "unkown service")
            print(f"{ip}:{port} ({service})")

        display_results(results)
    else:
        print("no open ports found")

    print(f"time: {elapsed_time:.2f} seconds")


if __name__ == "__main__":
    if threading.active_count() == 1:
        __main__(sys.argv)
        # python -m http.server 8000 for server
        # python main.py 127.0.0.1/32 8000