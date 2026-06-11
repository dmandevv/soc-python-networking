from scapy.all import IP, TCP, sr1
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


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

def print_os(ttl):
    if ttl is None:
        return "OS: Unknown"
    if ttl <= 64:
        return "OS: Linux / macOS"
    if ttl <= 128:
        return "Windows"
    return "OS: Cisco / network device"

def print_banner(banner):
    if banner is None:
        return ""
    return f"Banner: {banner}"

def port_info(port):
    return f"Port: '{port}' OPEN --- Service: '{get_service_name(port)}'"

def get_service_name(port):
    return COMMON_SERVICES.get(port, "Unknown")

def grab_banner(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(3.0)
        try:
            s.connect((host, port))
            if port == 80: #http needs something sent before it responds
                s.send("GET / HTTP/1.0\r\n\r\n".encode('utf-8'))
            response = s.recv(1024).decode('utf-8', errors='replace').strip()
            return response
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None

def syn_scan_for_open(host, port, iface = "eth0"):
    packet = IP(dst=host) / TCP(dport=port, flags='S')
    reply = sr1(packet, timeout=5, verbose=False)
    if reply and reply.haslayer(TCP) and reply[TCP].flags == 0x12:
        return {"port": port, "ttl": reply[IP].ttl}
    return {}

def scan_and_grab_banner(host, port):
    result = syn_scan_for_open(host, port)
    if result:
        result['banner'] = grab_banner(host, port)
    return result


def syn_scan(host, port, iface = "eth0"):
    packet = IP(dst=host) / TCP(dport=port, flags='S')
    reply = sr1(packet, timeout=5, verbose=False, iface=iface)
    if reply:
        if reply.haslayer(TCP) and reply[TCP].flags == 0x12:
            print(f"[+] Port {port} is open")
        elif reply.haslayer(TCP) and reply[TCP].flags == 0x14:
            print(f"[-] Port {port} is closed")
    else:
        print(f"[-] Port {port} is filtered")


def main():
    ports = list(range(0, 100))
    with ThreadPoolExecutor(max_workers=20) as e:
        tasks = {e.submit(scan_and_grab_banner, "scanme.nmap.org", port): port for port in ports}
        for future in as_completed(tasks):
            task_id = tasks[future]
            try:
                if result := future.result():
                    port, ttl, banner = result["port"], result["ttl"], result["banner"]
                    print(f"{port_info(port)} {print_os(ttl)} {print_banner(banner)}")
            except Exception as exc:
                print(f"Task {task_id} generated an exception: {exc}")

    #syn_scan("127.0.0.1", 9999, "lo")
    #[syn_scan("scanme.nmap.org", p) for p in range(0, 1024)]

if __name__ == "__main__":
    main()