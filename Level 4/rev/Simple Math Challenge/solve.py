import socket

with socket.create_connection(('host1.dreamhack.games', 19547)) as s:
    s.sendall(b"1601 -78 2\n")
    print(s.recv(4096).decode())