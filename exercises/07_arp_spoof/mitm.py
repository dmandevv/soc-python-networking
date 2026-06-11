from scapy.all import *
import subprocess

def set_iptables(action):
    rule = ["iptables", "-p", "tcp", "--tcp-flags", "RST", "RST", "-j", "DROP"]
    exists = subprocess.run(["sudo", "iptables", "-C", "OUTPUT"] + rule[1:],
                            stderr=subprocess.DEVNULL).returncode == 0
    
    if action == "-A" and not exists:
        subprocess.run(["sudo", "iptables", "-A", "OUTPUT"] + rule[1:])
    elif action == "-D" and exists:
        subprocess.run(["sudo", "iptables", "-D", "OUTPUT"] + rule[1:])

seen = set()

def intercept(p):
    if TCP in p and Raw in p and p[TCP].dport == 8051:
        seq = p[TCP].seq
        if seq not in seen:
            seen.add(seq)
            print(p[Raw].load.decode('utf-8', errors='replace'))

def mitm():
    sniff(
        prn=intercept,
        lfilter=lambda p: TCP in p and Raw in p and (p[TCP].dport == 8051 or p[TCP].sport == 8051),
        iface="lo"
    )

def main():
    set_iptables("-A")
    try:
        mitm()
    finally:
        set_iptables("-D")

if __name__ == "__main__":
    main()