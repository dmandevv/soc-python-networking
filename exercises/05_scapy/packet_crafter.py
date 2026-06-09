from scapy.all import *

def packet_callback(packet):
    print(packet.summary())

def sniff_packet():
    sniff(
        prn=packet_callback,
        iface="eth0",
        count=5,
        timeout=10
    )

def send_raw_icmp_ping():
    packet = IP(dst="8.8.8.8") / ICMP()
    reply = sr1(packet, timeout=2, verbose=False)
    if reply:
        print(f"Reply received!")
        print(f"IP: {reply[IP].src}")
        print(f"Type: {reply[ICMP].type}")
    else:
        print(f"No reply or timed out")

def tcp_syn_scan(target, port):
    packet = IP(dst=target) / TCP(dport=port, flags="S") # 'S' = SYN
    reply = sr1(packet, timeout=2, verbose=False)
    if reply:
        print(reply[TCP].flags)
        if reply[TCP].flags & 0x12 == 0x12:
            print(f'port is open')
        elif reply[TCP].flags & 0x04 == 0x04:
            print(f'port is closed')
        else:
            print(f'Unknown')
    else:
        print(f"No reply, likely dropped by firewall")

def arp_scan(target_ip):
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip)
    answered, unanswered = srp(packet, timeout=2, iface="eth0", verbose=False)
    for sent, received in answered:
        print(f"Sent to '{sent}' and received '{received}'")

def dns_via_scapy():
    packet = IP(dst="8.8.8.8") / UDP() / DNS(rd=1, qd=DNSQR(qname="google.com"))
    reply = sr1(packet, timeout=2, verbose=False)
    if reply:
        for answer in reply[DNS].an:
            print(f"{answer.rrname}\n{answer.type}\n{answer.rdata}")
    else:
        print(f"No reply")

def main():
    #[tcp_syn_scan("scanme.nmap.org", port=p) for p in range(20, 25)]
    #arp_scan("172.30.128.0/24")
    dns_via_scapy()

if __name__ == "__main__":
    main()