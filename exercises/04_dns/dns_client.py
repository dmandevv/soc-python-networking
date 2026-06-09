"""
DNS Client from scratch
Builds and sends raw DNS queries over UDP, parses the response.

DNS runs on port 53, UDP by default.
Every query is: header + question section.
Every response is: header + question + answer + authority + additional sections.

Usage:
    python3 dns_client.py                          # A record for google.com
    python3 dns_client.py google.com A
    python3 dns_client.py google.com MX
    python3 dns_client.py google.com TXT
"""
import socket
import struct
import sys
import random

DNS_SERVER = "8.8.8.8"
DNS_PORT   = 53

RECORD_TYPES = {
    "A":     1,   # IPv4 address
    "NS":    2,   # name server
    "CNAME": 5,   # canonical name (alias)
    "SOA":   6,   # start of authority
    "PTR":   12,  # reverse lookup
    "MX":    15,  # mail exchange
    "TXT":   16,  # text record
    "AAAA":  28,  # IPv6 address
    "AXFR":  252, # zone transfer 
}

def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf

def skip_name(raw, pos):
    while True:
        length = raw[pos]
        if length == 0:
            return pos + 1
        if length & 0xC0 == 0xC0:
            return pos + 2  # pointer is always 2 bytes
        pos += 1 + length


def send_axfr(zone, ip) -> list[bytes]:

    ID = struct.pack("!H", random.getrandbits(16))
    FLAGS = struct.pack("!H", 0b0000_0001_0000_0000)
    QDCOUNT = struct.pack("!H", 1)
    ANCOUNT = struct.pack("!H", 0)
    NSCOUNT = struct.pack("!H", 0)
    ARCOUNT = struct.pack("!H", 0)
    HEADER = ID + FLAGS + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT

    QNAME = bytes()
    for part in zone.split("."):
        QNAME += struct.pack("!B", len(part)) + part.encode('utf-8')
    QNAME += b'\x00'
    
    QTYPE = struct.pack("!H", RECORD_TYPES["AXFR"])
    QCLASS = struct.pack("!H", 0x0001)

    PACKET = HEADER + QNAME + QTYPE + QCLASS

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.settimeout(0.5)
            s.connect((ip, DNS_PORT))
            s.sendall(struct.pack("!H", len(PACKET)) + PACKET)

            responses = []
            try:
                while True:
                    length = recv_exact(s, 2)
                    if not length:
                        break
                    length = struct.unpack("!H", length)[0]
                    message = recv_exact(s, length)
                    if not message:
                        break
                    responses.append(message)
            except socket.timeout:
                print(f"Timed out - returning what was received")
            return responses
        except socket.timeout:
            print(f"Timed out sending/receiving from: {ip}:{DNS_PORT}")

def send_raw_rec(host, record_type) -> bytes:

    ID = struct.pack("!H", random.getrandbits(16))
    FLAGS = struct.pack("!H", 0b0000_0001_0000_0000)
    QDCOUNT = struct.pack("!H", 1)
    ANCOUNT = struct.pack("!H", 0)
    NSCOUNT = struct.pack("!H", 0)
    ARCOUNT = struct.pack("!H", 0)
    HEADER = ID + FLAGS + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT

    QNAME = bytes()
    for part in host.split("."):
        QNAME += struct.pack("!B", len(part)) + part.encode('utf-8')
    QNAME += b'\x00'
    
    QTYPE = struct.pack("!H", RECORD_TYPES[record_type])
    QCLASS = struct.pack("!H", 0x0001)

    PACKET = HEADER + QNAME + QTYPE + QCLASS

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(5)
        try:
            while True:
                s.sendto(PACKET, (DNS_SERVER, DNS_PORT))
                data, _ = s.recvfrom(4096)
                return data
        except socket.timeout:
            print(f"Timed out sending/receiving from: {DNS_SERVER}:{DNS_PORT}")

def decode_name(raw: bytes, pos: int) -> tuple[str, int]:
    labels = []
    jumped = False
    jump_pos = 0

    while True:
        length = raw[pos]

        if length == 0:
            pos += 1
            break

        if length & 0xC0 == 0xC0:  # pointer — top 2 bits are 11
            if not jumped:
                jump_pos = pos + 2  # save where to resume after the pointer
            offset = ((length & 0x3F) << 8) | raw[pos + 1]
            pos = offset
            jumped = True
        else:
            pos += 1
            labels.append(raw[pos:pos + length].decode('utf-8', errors='replace'))
            pos += length

    return ".".join(labels), (jump_pos if jumped else pos)

def check_answers(response):

    ID, FLAGS, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT = struct.unpack("!HHHHHH", response[:12])
    print(f"ID: {ID}")
    print(f"FLAGS: {FLAGS:016b}")
    print(f"QDCOUNT: {QDCOUNT}")
    print(f"ANCOUNT: {ANCOUNT}")
    print(f"NSCOUNT: {NSCOUNT}")
    print(f"ARCOUNT: {ARCOUNT}")

    print(f"[DEBUG] Message length: {len(response)}, ANCOUNT: {ANCOUNT}")

    offset = 12
    if QDCOUNT > 0:
        offset = skip_name(response, offset) + 4  # skip QNAME + QTYPE + QCLASS
    RECORD_TYPE_NAMES = {v: k for k, v in RECORD_TYPES.items()}

    while offset < len(response) - 12:  # -12 ensures enough bytes for a full record header

        type_offset = skip_name(response, offset)
        TYPE = int.from_bytes(response[type_offset: type_offset + 2], byteorder='big')
        rdlength = int.from_bytes(response[type_offset + 8: type_offset + 10], byteorder='big')
        rdata_start = type_offset + 10

        if TYPE in RECORD_TYPES.values():
            print(f"Answer is {RECORD_TYPE_NAMES.get(TYPE, f"unknown({TYPE})")} record")

        if TYPE == RECORD_TYPES["MX"]:
            data, _ = decode_name(response, rdata_start + 2)
            print(data)
        elif TYPE == RECORD_TYPES["PTR"]:
            data, _ = decode_name(response, rdata_start)
            print(data)
        elif TYPE == RECORD_TYPES["NS"]:
            data, _ = decode_name(response, rdata_start)
            print(data)
        elif TYPE == RECORD_TYPES["TXT"]:
            text = ""
            pos = rdata_start
            consumed = 0
            while consumed < rdlength:
                text_len = response[pos]
                pos += 1
                consumed += 1
                text += response[pos:pos + text_len].decode('utf-8', errors='replace')
                pos += text_len
                consumed += text_len
            print(text)
        elif TYPE == RECORD_TYPES["A"]:
            print(socket.inet_ntoa(response[rdata_start:rdata_start + 4]))
        else:
            print(f"Skipping type {TYPE} at offset {offset}, rdlength={rdlength}")

        offset = rdata_start + rdlength


         

def reverse_ip(ip) -> str:
    parts = ".".join(reversed(ip.split(".")))
    return parts + ".in-addr.arpa"

def main():
    messages = send_axfr("zonetransfer.me", "81.4.108.41")

    print(f"Received {len(messages)} messages")
    for i, msg in enumerate(messages):
        print(f"Message {i}: {len(msg)} bytes")

    for msg in messages:
        check_answers(msg)
    

if __name__ == "__main__":
    main()

# --- Challenges ---
# 1. Send a raw A record query for a domain and parse the IP from the response.
# 2. Support MX records — the response includes a preference number + mail server name.
# 3. Support TXT records — used for SPF, DKIM, domain verification.
# 4. Reverse DNS lookup: query PTR record for an IP (format: reversed IP + .in-addr.arpa).
# 5. Try a zone transfer (AXFR) against a DNS server that allows it:
#    zonetransfer.me is a server specifically set up for this — it exposes all DNS records.
#    This is a classic recon technique: one query dumps every subdomain.
