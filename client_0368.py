#!/usr/bin/env python3
"""
IE2102 - Network Programming Assignment
Student : IT24100368
Client  : client_0368.py
Server  : localhost:50161
"""
import socket
import sys

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 50368


def send_framed(sock: socket.socket, payload: str) -> None:
    """Send a LEN-framed message to the server."""
    data = payload.encode()
    header = f"LEN:{len(data)}\n".encode()
    sock.sendall(header + data)


def recv_response(sock: socket.socket) -> str:
    """Receive a newline-terminated response from the server."""
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf.decode(errors="replace").strip()


def print_banner():
    print("=" * 55)
    print("  IE2102 Network Programming Client — IT24100368")
    print(f"  Server: {SERVER_HOST}:{SERVER_PORT}")
    print("=" * 55)
    print("Commands: REGISTER <user> <pass>")
    print("          LOGIN <user> <pass>")
    print("          LOGOUT")
    print("          QUIT")
    print("=" * 55)


def main():
    print_banner()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((SERVER_HOST, SERVER_PORT))
        print(f"[+] Connected to {SERVER_HOST}:{SERVER_PORT}\n")
    except ConnectionRefusedError:
        print(f"[!] Cannot connect to {SERVER_HOST}:{SERVER_PORT}")
        print("    Make sure the server is running.")
        sys.exit(1)

    try:
        while True:
            try:
                cmd = input("client> ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n[*] Disconnecting…")
                break

            if not cmd:
                continue

            # Validate payload size before sending
            if len(cmd.encode()) > 4096:
                print("[!] Payload too large (max 4096 bytes). Not sent.")
                continue

            send_framed(sock, cmd)
            response = recv_response(sock)
            print(f"server> {response}")

            # Exit on QUIT/EXIT
            if cmd.upper() in ("QUIT", "EXIT"):
                break

    finally:
        sock.close()
        print("[*] Connection closed.")


if __name__ == "__main__":
    main()
