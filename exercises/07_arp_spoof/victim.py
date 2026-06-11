from scapy.all import IP, TCP, sr1, send, sniff
import sys
import random
import threading
import time


HOST = "127.0.0.1"  # Listen on all interfaces
MY_PORT = 8001
SERVER_PORT = 8002

def send_SYN():
    print(f"[*] Sending SYN to {HOST}:{SERVER_PORT}")
    ip_layer = IP(dst=HOST)
    syn_layer = TCP(sport=MY_PORT, dport=SERVER_PORT, flags="S", seq=random.randint(100, 100000))
    syn_ack_packet = sr1(ip_layer/syn_layer, timeout=5, iface="lo")

    # wait for syn ack

    if syn_ack_packet and syn_ack_packet.haslayer(TCP):
        if syn_ack_packet[TCP].flags == "SA":
            print(f"[+] Received SYN-ACK from {syn_ack_packet[IP].src}:{syn_ack_packet[TCP].sport}")
            SERVER_ISN = syn_ack_packet[TCP].seq
            print(f"Server ISN: {SERVER_ISN}")
            print(f"Server Ack: {syn_ack_packet[TCP].ack}")

            ack_layer = TCP(
                sport=MY_PORT,
                dport=SERVER_PORT,
                flags="A",
                seq=syn_ack_packet[TCP].ack,
                ack=SERVER_ISN+1
            )

            send(ip_layer / ack_layer)
            print("TCP handshake complete")

def send_SYN_ACK(packet):
    print(f"[*] Sending SYN-ACK to {packet[IP].src}:{packet[IP].sport}")
    ip_layer = IP(src=packet[IP].dst, dst=packet[IP].src)
    tcp_layer = TCP(
        sport=packet[TCP].dport,
        dport=packet[TCP].sport,
        flags="SA",
        seq=random.randint(100, 100000),
        ack=packet[TCP].seq + 1
    )
    syn_ack_packet = ip_layer / tcp_layer
    send(syn_ack_packet)

def handle_packet(packet):
    if packet.haslayer(IP):      
        if packet[TCP].flags == 'S':
            print(f"Received SYN from {packet[IP].src}:{packet[IP].sport}")
            send_SYN_ACK(packet)

def main():
    MY_PORT = sys.argv[1] if len(sys.argv) > 1 else 8050
    SERVER_PORT = sys.argv[2] if len(sys.argv) > 2 else 8051
    INITIATE_CONN = sys.argv[3] if len(sys.argv) > 3 else False

    thread = threading.Thread(target=sniff, kwargs={"prn":handle_packet, "iface":"lo", "filter":f"tcp dst port {MY_PORT}"}) # testing on localhost so iface='lo'
    thread.start()
    time.sleep(2.0)
    if INITIATE_CONN:
        send_SYN()
    thread.join()

if __name__ == "__main__":
    main()