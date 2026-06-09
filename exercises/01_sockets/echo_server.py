"""
TCP Echo Server
Run this first, then run tcp_client.py in a separate terminal.
"""
import socket
import threading
import logging
from datetime import datetime

current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
log_filename = f"connection_{current_time}.log"

logging.basicConfig(
    filename=f'./logs/{log_filename}',
    filemode='a',
    level=logging.INFO,
    format='%(asctime)s - [IP: %(ip)s] - %(levelname)s - %(message)s',
)

HOST = "127.0.0.1"
PORT = 9999


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen()
        print(f"[*] Listening on {HOST}:{PORT} — waiting for connection")

        while True:
            conn, addr = server.accept()
            thread = threading.Thread(
                target=handle_client,
                args=(conn, addr)
            )        
            thread.daemon = True
            thread.start()
            print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")

def connection_log(status: str, ip_address: str):
    logging.info(f"Connection attempt: {status}", extra={'ip': ip_address})


def handle_client(conn, addr):
    with conn:
        print(f"[+] Connected: {addr}")
        connection_log("CONNECTED", addr[0])
        while True:
            data = conn.recv(1024)
            if not data:
                print(f"[-] {addr} lost connection")
                connection_log("LOST CONNECTION", addr[0])
                break
            message = data.decode()

            if message.startswith("file "):
                filename = message[5:].strip()
                conn.sendall(b"READY")
                receive_file(conn, addr, filename)
                conn.sendall(b"DONE")
            elif message == 'quit':
                conn.shutdown(socket.SHUT_WR)
                conn.close()
                print(f"[-] {addr} disconnected")
                connection_log("DISCONNECTED", addr[0])
                break
            else:
                print(f"[>] Received: {message!r}")
                conn.sendall(message.upper().encode())  # echo it straight back

def receive_file(conn, addr, filename):
    save_path = f"./files/server/{filename}"
    with open(save_path, "wb") as f:
        while True:
            chunk = conn.recv(4096)
            if not chunk or chunk == b"EOF":
                break
            f.write(chunk)
    logging.info(f"Saved file: {filename}", extra={"ip": addr[0]})


if __name__ == "__main__":
    main()


# --- Challenges ---
# 1. Make the server handle multiple clients by spawning a thread per connection.
# 2. Instead of echoing raw bytes, uppercase the message before sending it back.
# 3. Add a "quit" command: if the client sends "quit\n", close the connection gracefully.
# 4. Log each connection to a file with timestamp and client IP.
