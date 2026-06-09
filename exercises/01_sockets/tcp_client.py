"""
TCP Client
Connect to the echo server and send messages interactively.
Make sure echo_server.py is running first.
"""
import socket
import time
from contextlib import contextmanager
import argparse

@contextmanager
def rtt_timer():
    start_time = time.perf_counter()
    yield
    elapsed = (time.perf_counter() - start_time) * 1000
    print(f"RTT: {elapsed:.2f}ms")

def main():
    parser = argparse.ArgumentParser(
        description="Host and Port optional arguments"
    )
    parser.add_argument(
        '-H', '--host',
        type=str,
        default="127.0.0.1",
        help="Host you want to connect to (defaults to 127.0.0.1)"
    )
    parser.add_argument(
        '-p', '--port',
        type=int,
        default=9999,
        help="Port number of host server you want to connect to (defaults to 9999)"
    )
    args = parser.parse_args()
    HOST = args.host
    PORT = args.port

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print(f"[+] Connected to {HOST}:{PORT}")
        print("[*] Type messages and press Enter. Enter 'quit' to close.\n")

        while True:
            try:
                message = input("> ")
            except (KeyboardInterrupt, EOFError):
                print("\n[-] Closing connection")
                break

            if not message:
                continue

            if message.startswith("file "):
                filename = message[5:].strip()
                if not filename:
                    print("FILENAME can't be empty")
                    continue
                with rtt_timer():                
                    s.sendall(f"file {filename}".encode())
                    ack = s.recv(1024)
                if ack == b"READY":
                    try:
                        read_path = f"./files/client/{filename}"
                        with rtt_timer():
                            with open(read_path, "rb") as file:
                                while chunk := file.read(4096):
                                    s.sendall(chunk)
                            s.sendall(b"EOF")
                            response = s.recv(1024)
                            if response == b"DONE":
                                print("File sent")
                            else:
                                print(f"[!] File not sent: {response}")
                    except FileNotFoundError:
                        print(f"[!] File not found: {read_path}")
                else:
                    print("Server couldn't receive file - sorry :()")
                continue
             
            with rtt_timer():
                s.sendall(message.encode())
                response = s.recv(1024)
                if not response:
                    print("Received disconnect signal from server. Closing local socket.")
                    break
                print(f"[<] Echo: {response.decode()!r}")



if __name__ == "__main__":
    main()


# --- Challenges ---
# 1. Send a file's contents to the server byte by byte (open a file, read chunks, sendall).
# 2. Measure round-trip time for each message using time.perf_counter().
# 3. Connect to a real service instead of the echo server:
#    - HOST = "towel.blinkenlights.nl", PORT = 23  (ASCII Star Wars!)
#    - HOST = "time.nist.gov", PORT = 13            (daytime protocol)
# 4. Add a --host and --port argument using argparse.
