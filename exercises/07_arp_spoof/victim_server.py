import socket

HOST = "127.0.0.1"
PORT = 8051

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(1)
    print(f"[*] Listening on {HOST}:{PORT}")
    conn, addr = s.accept()
    with conn:
        print(f"[+] Connection from {addr}")
        data = conn.recv(1024)
        print(f"[+] Received: {data.decode()}")
