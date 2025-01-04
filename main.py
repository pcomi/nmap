import sys
import ipaddress
import socket
import threading
import time

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

def thread_scan(ips, ports, results, start, end):
    for ip in ips[start:end]:
        for port in ports:
            if is_port_open(ip, port):
                results.append((ip, port))

def __main__(argv):
    if(len(argv) != 3):
        print("example usage: python main.py <ip> <ports>")
        return 0
    
    start_time = time.time()

    ip = argv[1]
    ports = argv[2].split(",")

    ips = get_ip_addresses(ip)
    print(ips, ports)

    elapsed_time = time.time() - start_time
    print(f"Elapsed time: {elapsed_time:.2f} seconds")

    # results = []
    # threads = []
    # ips = get_ip_addresses(ip)
    # num_threads = 10
    # chunk_size = len(ips) // num_threads

    # for i in range(num_threads):
    #     start = i * chunk_size
    #     end = (i + 1) * chunk_size if i != num_threads - 1 else len(ips)
    #     thread = threading.Thread(target=thread_scan, args=(ips, ports, results, start, end))
    #     thread.start()
    #     threads.append(thread)

    # for thread in threads:
    #     thread.join()

    # if results:
    #     print("Open ports:")
    #     for ip, port in results:
    #         service = {80: "HTTP", 443: "HTTPS", 22: "SSH", 445: "SMB"}.get(int(port), "")
    #         print(f"{ip}:{port} ({service})")
    # else:
    #     print("No open ports found.")

if __name__ == "__main__":
    __main__(sys.argv)