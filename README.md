# Networking with Python

Step 2 of my [red team journey](https://github.com/dmandevv/redteam-python-journey).

Building networking fundamentals from scratch — sockets, TCP/IP, port scanning, DNS, and packet analysis.

---

## Exercises

| # | Exercise | File |
|---|----------|------|
| 01 | TCP echo server + interactive client | [exercises/01_sockets/](exercises/01_sockets/) |
| 02 | Threaded TCP port scanner | [exercises/02_port_scanner/](exercises/02_port_scanner/) |
| 03 | Raw HTTP GET over a socket | [exercises/03_http_from_scratch/](exercises/03_http_from_scratch/) |
| 04 | DNS client from scratch | [exercises/04_dns/](exercises/04_dns/) |
| 05 | Scapy — packet sniffing, ICMP, SYN scan, ARP scan, DNS | [exercises/05_scapy/](exercises/05_scapy/) |
| 06 | Packet injection — forged ICMP/UDP, TCP RST injection | [exercises/06_packet_injection/](exercises/06_packet_injection/) |
| 07 | ARP spoofing + MITM | [exercises/07_arp_spoof/](exercises/07_arp_spoof/) |
| 08 | Scapy port scanner — SYN scan, OS fingerprint, banner grab | [exercises/08_port_scanner/](exercises/08_port_scanner/) |

---

## Topics covered

- [x] How TCP/IP works at the code level
- [x] Sockets — raw connections, client/server programs
- [x] HTTP from scratch (before using libraries)
- [x] Port scanning
- [x] Reading and parsing network data
- [x] DNS lookups
- [x] Libraries: `socket`, `requests`, `scapy`
- [x] Packet crafting and injection
- [x] ARP spoofing and man-in-the-middle
- [x] SYN scanning and service fingerprinting
