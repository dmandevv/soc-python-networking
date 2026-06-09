"""
TCP Connect Port Scanner
Uses socket.connect_ex() — returns 0 on open, non-zero on closed/filtered.
Threads the scan so it doesn't take forever.

Usage:
    python port_scanner.py                    # scan localhost 1-1024
    python port_scanner.py 192.168.1.1 1 65535
"""
import os
import socket
import sys
import threading
import argparse
import struct
import json, csv
from queue import Queue


TIMEOUT = 0.5
THREAD_COUNT = 150
PROTOCOLS = {"tcp", "udp"}

# ordered from most to least common
COMMON_SERVICES = {
    80: "http",
    443: "https",
    22: "ssh",
    53: "dns",
    25: "smtp",
    3389: "rdp",
    445: "smb",
    3306: "mysql",
    8080: "http-alt",
    21: "ftp",
    23: "telnet",
    110: "pop3",
    143: "imap",
    5432: "postgres",
    6379: "redis",
    8443: "https-alt",
    27017: "mongodb",
    6443: "kubernetes-api",
    9200: "elasticsearch",
    1433: "mssql",
}
TOP_20_PORTS = list(COMMON_SERVICES.keys())


def scan_port_tcp(host: str, port: int, results: list, lock: threading.Lock) -> None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            if s.connect_ex((host, port)) == 0:
                banner = ""
                try:
                    banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                except (socket.timeout, OSError):
                    pass # service doesn't send banner but port is open
                with lock:
                    results.append((port, banner))
    except (socket.error, OSError):
        pass

def scan_port_udp(host: str, port: int, results: list, lock: threading.Lock) -> None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(TIMEOUT)
            # minimal DNS query for google.com A record
            DNS_QUERY = b'\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01'
            s.sendto(DNS_QUERY, (host, port))
            try:
                banner = s.recvfrom(1024)[0].hex()
                with lock:
                    results.append((port, banner))
            except (socket.timeout, OSError):
                # silence = open | filtered
                with lock:
                    results.append((port, "open|filtered"))
    except ConnectionRefusedError:
        pass # ICMP port unreachable = closed
    except (socket.error, OSError):
        pass

def worker(host: str, queue: Queue, results: list, lock: threading.Lock, scan_fn) -> None:
    while True:
        port = queue.get()
        if port is None:
            break
        scan_fn(host, port, results, lock)
        queue.task_done()


def scan_tcp(host: str, ports: list[int]) -> list[(int, str)]:
    queue: Queue = Queue()
    results: list = []
    lock = threading.Lock()

    threads = []
    for _ in range(min(THREAD_COUNT, len(ports))):
        t = threading.Thread(target=worker, args=(host, queue, results, lock, scan_port_tcp), daemon=True)
        t.start()
        threads.append(t)

    for port in ports:
        queue.put(port)

    queue.join()

    for _ in threads:
        queue.put(None)  # poison pill — shut down workers
    for t in threads:
        t.join()

    return sorted(results)

def scan_udp(host: str, ports: list[int]) -> list[(int, str)]:
    queue: Queue = Queue()
    results: list = []
    lock = threading.Lock()

    threads = []
    for _ in range(min(THREAD_COUNT, len(ports))):
        t = threading.Thread(target=worker, args=(host, queue, results, lock, scan_port_udp), daemon=True)
        t.start()
        threads.append(t)

    for port in ports:
        queue.put(port)

    queue.join()

    for _ in threads:
        queue.put(None)  # poison pill — shut down workers
    for t in threads:
        t.join()

    return sorted(results)

def detect_os(host) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:            
            icmp_type = 8 # 8 = echo request
            icmp_code = 0 # 0 = echo reply
            icmp_checksum = 0 # calculated over header and payload, but initially 0
            icmp_id = os.getpid() & 0xFFFF # use current process ID as Identifier
            icmp_seq = 1 # increment for every packet sent
            header_format = "!BBHHH"

            dummy_packet = struct.pack(header_format, icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)

            total = 0
            for i in range(0, len(dummy_packet), 2):
                total += (dummy_packet[i] << 8) + dummy_packet[i + 1]

            # fold overflow back into 16 bits
            while total > 0xFFFF: # 65535
                total = (total & 0xFFFF) + (total >> 16)

            checksum = ~total & 0xFFFF # bitwise NOT, keep lower 16 bits

            packet = struct.pack(header_format, icmp_type, icmp_code, checksum, icmp_id, icmp_seq)

            s.sendto(packet, (host, 0))
            s.settimeout(2)
            try:
                response = s.recv(1024)
            except socket.timeout:
                print("[!] No response = packet may be malformed or host unreachable")
                return None
            
            ttl = response[8]
            if ttl <= 64:
                return (ttl, "linux/android/mac/ios")
            if ttl <= 128:
                return (ttl, "windows")
            # 255 or less
            return (ttl, "network infrastructure")

    except PermissionError:
        print("Error: You must run this script with root/admin priveleges.")

def output_result(results: list, output_type: str):
    if output_type == None:
        return
    if output_type == "json":
        with open("output.json", "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        return
    if output_type == "csv":
        headers = list(results[0].keys())
        with open("output.csv", "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            writer.writerows(results)
        return
    print(f"Invalid output type: '{output_type}'")
    

SCAN_FUNCTIONS = {
    "tcp": scan_tcp,
    "udp": scan_udp,
}

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument( "-H", "--host", type=str, default="127.0.0.1") 
    parser.add_argument( "-s", "--start", type=int, default=0)
    parser.add_argument( "-e", "--end", type=int, default=65535)
    parser.add_argument( "-p", "--protocol", type=str, default="tcp")
    parser.add_argument("--top-ports", action="store_true")
    parser.add_argument("--detect-os", action="store_true")
    parser.add_argument("--output", type=str)

    args = parser.parse_args()

    host = args.host
    start = args.start
    end = args.end
    protocol = args.protocol
    top_20_ports_only = args.top_ports
    output_type = args.output

    try:
        resolved = socket.gethostbyname(host)
    except socket.gaierror:
        print(f"[!] Could not resolve {host}")
        sys.exit(1)
    
    if args.detect_os:
        result = detect_os(host)
        if result:
            ttl, host_os = result
        print(f"{host} ({resolved}) is running {host_os} (ttl of {ttl})")

    if protocol not in PROTOCOLS:
        print(f"Unknown protocol '{protocol}'. Choose from: {', '.join(sorted(PROTOCOLS))}")
        sys.exit(1)

    if top_20_ports_only:
        print(f"[*] Scanning {host} ({resolved}) — 20 most common ports")
        ports = TOP_20_PORTS
    else:
        print(f"[*] Scanning {host} ({resolved}) — ports {start}-{end}")
        ports = list(range(start, end + 1))

    open_ports = SCAN_FUNCTIONS[protocol](host, ports)
    if not open_ports:
        print("[-] No open ports found")
        return

    print(f"\n{'PORT':<10}{'SERVICE'}")
    print("-" * 22)
    results = []
    for port, banner in open_ports:
        service = COMMON_SERVICES.get(port, "unknown")
        print(f"{port}/{protocol}{'':<6}{service} {banner}")
        results.append({"port": port, "protocol": protocol, "service": service, "banner": banner})

    print(f"\n[*] {len(open_ports)} open port(s)")

    output_result(results, output_type)
    


if __name__ == "__main__":
    main()


# --- Challenges ---
# 1. Add a banner-grab: after finding an open port, connect and recv() a few bytes.
#    Many services (SSH, FTP, SMTP) send a banner immediately on connect.
# 2. Add UDP scanning. UDP is connectionless — you send a packet and wait for an
#    ICMP "port unreachable" response (or silence). Hint: socket.SOCK_DGRAM.
# 3. Add a --top-ports flag that only scans the 20 most common ports.
# 4. Detect the OS via TCP fingerprinting: look at TTL from ICMP ping responses
#    (64 = Linux, 128 = Windows, 255 = network device).
# 5. Output results as JSON or CSV for piping into other tools.
