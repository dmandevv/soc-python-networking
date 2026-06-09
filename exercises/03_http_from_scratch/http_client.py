"""
HTTP/1.1 GET from scratch — no requests, no urllib, just a raw socket.

What this shows you: every HTTP library sends exactly this over the wire.
The request is plain text. The response is headers + blank line + body.

Usage:
    python http_client.py                          # GET http://example.com/
    python http_client.py example.com /index.html
"""
import socket
import sys
import http
import re
from urllib.parse import urlparse, urlunparse
import json
import ssl

def is_redirect(status) -> bool:
    codes = [int(code) for code in re.findall(r"\b\d{3}\b", status)]
    return any(300 <= code < 400 for code in codes)

def decode_chunked(body: bytes) -> bytes:
    result = b""
    pos = 0

    while pos < len(body):
        # find the end of the size line
        end = body.index(b"\r\n", pos)
        size = int(body[pos:end], 16)   # hex string → int

        if size == 0:
            break

        # data starts after the \r\n following the size line
        data_start = end + 2
        result += body[data_start:data_start + size]

        # skip past data + its trailing \r\n
        pos = data_start + size + 2

    return result

def http_get(host: str, path: str = "/", port: int = 80, _redirects = 0, extra_headers: dict = {}) -> tuple[str, dict, bytes]:
    if _redirects > 10:
        print(f"[!] Max redirects reached")
        return
    
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: raw-socket/1.0\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n"
        f"{"".join(f"{k}: {v}\r\n" for k, v in extra_headers.items())}"
        f"\r\n"
    )

    print(f"[*] Connecting to {host}:{port}")
    print(f"[>] Sending request:\n{'—'*40}")
    print(request.strip())
    print("—" * 40)

    context = ssl.create_default_context()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(10)
        s.connect((socket.gethostbyname(host), port))
        s.sendall(request.encode())

        raw = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            raw += chunk

    # HTTP response: headers end at the first blank line (\r\n\r\n)
    header_bytes, _, body = raw.partition(b"\r\n\r\n")
    header_lines = header_bytes.decode(errors="replace").splitlines()

    status_line = header_lines[0]  # e.g. "HTTP/1.1 200 OK"
    headers = {}
    for line in header_lines[1:]:
        if ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip().lower()] = value.strip()

    print(f"\n[<] Response:\n{'—'*40}")
    print(f"Status : {status_line}")
    for k, v in headers.items():
        print(f"{k}: {v}")
    print("—" * 40)
    print(f"\n[<] Body ({len(body)} bytes):\n")

    if headers.get('transfer-encoding') == 'chunked':
        print(decode_chunked(body).decode('utf-8'))
    else:   
        print(body[:1000].decode(errors="replace"))
        if len(body) > 1000:
            print(f"... [{len(body) - 1000} more bytes]")

    if is_redirect(status_line):
        location = headers.get('location')
        if location:
            parsed = urlparse(location)
            redirect_scheme = parsed.scheme or "http"
            redirect_host = parsed.hostname or host
            redirect_path = parsed.path or '/'
            redirect_port = 443 if parsed.scheme == 'https' else 80
            url = f"{redirect_scheme}://{redirect_host}{redirect_path}"
            print(f"\nREDIRECTING TO: {url}\n")
            https_get(redirect_host, redirect_path, redirect_port, _redirects + 1)

    return status_line, headers, body

def https_get(host: str, path: str = "/", port: int = 443, _redirects = 0, extra_headers: dict = {}) -> tuple[str, dict, bytes]:
    if _redirects > 10:
        print(f"[!] Max redirects reached")
        return
    
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: raw-socket/1.0\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n"
        f"{"".join(f"{k}: {v}\r\n" for k, v in extra_headers.items())}"
        f"\r\n"
    )

    print(f"[*] Connecting to {host}:{port}")
    print(f"[>] Sending request:\n{'—'*40}")
    print(request.strip())
    print("—" * 40)

    context = ssl.create_default_context()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(10)
        s.connect((socket.gethostbyname(host), port))
        wrapped = context.wrap_socket(s, server_hostname=host)
        wrapped.sendall(request.encode())

        raw = b""
        while True:
            chunk = wrapped.recv(4096)
            if not chunk:
                break
            raw += chunk

    # HTTP response: headers end at the first blank line (\r\n\r\n)
    header_bytes, _, body = raw.partition(b"\r\n\r\n")
    header_lines = header_bytes.decode(errors="replace").splitlines()

    status_line = header_lines[0]  # e.g. "HTTP/1.1 200 OK"
    headers = {}
    for line in header_lines[1:]:
        if ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip().lower()] = value.strip()

    print(f"\n[<] Response:\n{'—'*40}")
    print(f"Status : {status_line}")
    for k, v in headers.items():
        print(f"{k}: {v}")
    print("—" * 40)
    print(f"\n[<] Body ({len(body)} bytes):\n")

    if headers.get('transfer-encoding') == 'chunked':
        print(decode_chunked(body).decode('utf-8'))
    else:   
        print(body[:1000].decode(errors="replace"))
        if len(body) > 1000:
            print(f"... [{len(body) - 1000} more bytes]")

    if is_redirect(status_line):
        location = headers.get('location')
        if location:
            parsed = urlparse(location)
            redirect_scheme = parsed.scheme or "http"
            redirect_host = parsed.hostname or host
            redirect_path = parsed.path or '/'
            redirect_port = 443 if parsed.scheme == 'https' else 80
            url = f"{redirect_scheme}://{redirect_host}{redirect_path}"
            print(f"\nREDIRECTING TO: {url}\n")
            https_get(redirect_host, redirect_path, redirect_port, _redirects + 1)

    return status_line, headers, body

def http_post(host: str, body: str, path: str = "/", port: int = 80, _redirects = 0) -> tuple[str, dict, bytes]:
    if _redirects > 10:
        print(f"[!] Max redirects reached")
        return

    try:
        json.loads(body)
    except json.JSONDecodeError as e:
        print(f"[!] Invalid JSON body: {e}")
        return

    request = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body.encode('utf-8'))}\r\n"
        f"User-Agent: raw-socket/1.0\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n"
        f"\r\n"
        f"{body}"
        f"\r\n"
    )

    print(f"[*] Connecting to {host}:{port}")
    print(f"[>] Sending request:\n{'—'*40}")
    print(request.strip())
    print("—" * 40)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(10)
        s.connect((socket.gethostbyname(host), port))
        s.sendall(request.encode())

        raw = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            raw += chunk

    # HTTP response: headers end at the first blank line (\r\n\r\n)
    header_bytes, _, res_body = raw.partition(b"\r\n\r\n")
    header_lines = header_bytes.decode(errors="replace").splitlines()

    status_line = header_lines[0]  # e.g. "HTTP/1.1 200 OK"
    headers = {}
    for line in header_lines[1:]:
        if ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip().lower()] = value.strip()

    print(f"\n[<] Response:\n{'—'*40}")
    print(f"Status : {status_line}")
    for k, v in headers.items():
        print(f"{k}: {v}")
    print("—" * 40)
    print(f"\n[<] Body ({len(res_body)} bytes):\n")
    print(res_body[:1000].decode(errors="replace"))
    if len(res_body) > 1000:
        print(f"... [{len(res_body) - 1000} more bytes]")

    if is_redirect(status_line):
        location = headers.get('location')
        if location:
            parsed = urlparse(location)
            redirect_scheme = parsed.scheme or "http"
            redirect_host = parsed.hostname or host
            redirect_path = parsed.path or '/'
            redirect_port = 443 if parsed.scheme == 'https' else 80
            url = f"{redirect_scheme}://{redirect_host}{redirect_path}"
            print(f"\nREDIRECTING TO: {url}\n")
            http_get(redirect_host, redirect_path, redirect_port, _redirects + 1)

    return status_line, headers, res_body




def main() -> None:
    host = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    path = sys.argv[2] if len(sys.argv) > 2 else "/"
    port = sys.argv[3] if len(sys.argv) > 3 else 443

    http_get(host, path, port)
    https_get(host, path, port)
    #http_post("httpbin.org", '{"username": "test", "password": "1234"}', "/post")
    #https_get("httpbin.org", "/basic-auth/user/pass", extra_headers={"Authorization": "Basic dXNlcjpwYXNz"})
    #https_get("httpbin.org", "/basic-auth/user/pass", extra_headers={"Authorization": "Basic hacker"})

    


if __name__ == "__main__":
    main()


# --- Challenges ---
# 1. Follow redirects: if status is 301/302, parse the "location" header and
#    make a second request to the new URL.
# 2. Send a POST request with a body (e.g. form data or JSON).
#    Add "Content-Type" and "Content-Length" headers.
# 3. Parse chunked transfer encoding: when Transfer-Encoding: chunked,
#    the body arrives as hex-size\r\ndata\r\n blocks ending with 0\r\n\r\n.
# 4. Add basic HTTP auth: base64-encode "user:pass" and send it as
#    Authorization: Basic <encoded> header.
# 5. Upgrade to HTTPS: wrap the socket with ssl.wrap_socket() before sending.
#    You'll need to pass server_hostname for SNI.
