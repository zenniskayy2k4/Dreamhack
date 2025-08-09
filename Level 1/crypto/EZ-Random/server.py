import socket
import threading
import time
import os
from custom_random_2048 import CustomRandom2048

HOST = "0.0.0.0"
PORT = 9000

SEED_SIZE = 256  
SESSION_TIMEOUT = 10  

with open("flag.txt", "r") as f:
    FLAG = f.read().strip()

INIT_SEED = int.from_bytes(os.urandom(SEED_SIZE), "big")
SESSION_COUNTER = 0
SESSION_LOCK = threading.Lock()

BANNER = b"""\
Type your guess (as a decimal number), or type 'giveup' to forfeit.
Type 'reset' to reset server state 
You have 10 seconds per session.
"""

def handle_client(conn, addr):
    global SESSION_COUNTER, INIT_SEED
    try:
        with SESSION_LOCK:
            session_id = SESSION_COUNTER
            SESSION_COUNTER += 1

        current_seed = INIT_SEED + session_id
        rng = CustomRandom2048(current_seed)
        answer = rng.getrandbits(2048)

        conn.sendall(BANNER)
        conn.sendall(f"You are session #{session_id}\n".encode())
        prompt = b"Guess the 2048-bit number: "

        conn.sendall(prompt)
        conn.settimeout(SESSION_TIMEOUT)

        try:
            data = b""
            while not data.endswith(b"\n"):
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            conn.sendall(b"\n!!!Timeout!!!\n")
            conn.sendall(f"The answer was:\n{answer}\n".encode())
            return

        guess = data.decode(errors="ignore").strip()

        if guess.lower() == "giveup":
            conn.sendall(f"You gave up. The answer was:\n{answer}\n".encode())
            return

        if guess.lower() == "reset":
            with SESSION_LOCK:
                SESSION_COUNTER = 0
                INIT_SEED = int.from_bytes(os.urandom(SEED_SIZE), "big")
            conn.sendall(b"!!!Server has been reset!!!\n")
            return

        try:
            guess_val = int(guess)
        except:
            conn.sendall(b"Invalid input! Session closed.\n")
            conn.sendall(f"The answer was:\n{answer}\n".encode())
            return

        if guess_val == answer:
            conn.sendall(f"Correct! FLAG: {FLAG}\n".encode())
        else:
            conn.sendall(b"Wrong!\n")
            conn.sendall(f"The answer was:\n{answer}\n".encode())

    except Exception as e:
        try:
            conn.sendall(f"\nInternal error: {e}\n".encode())
        except:
            pass
    finally:
        conn.close()

def main():
    print(f"Listening on {HOST}:{PORT}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()

if __name__ == "__main__":
    main()
