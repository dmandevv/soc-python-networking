import socket

HOST = "127.0.0.1"
PORT = 8051
MESSAGE = "Hello from victim A — secret message"

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    print(f"[*] Connected to {HOST}:{PORT}")
    s.sendall(MESSAGE.encode())
    print(f"[>] Sent: {MESSAGE}")
