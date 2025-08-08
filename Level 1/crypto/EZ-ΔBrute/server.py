import socketserver
import random
from misty1 import Misty1
from secret_info import k, k_prime, FLAG_BLOCK, REAL_FLAG

misty1_k = Misty1(k)
misty1_kprime = Misty1(k_prime)


def ecb_encrypt(pt16: bytes, engine: Misty1) -> bytes:
    assert len(pt16) == 16
    c0 = engine.encrypt_block(pt16[:8])
    c1 = engine.encrypt_block(pt16[8:])
    return c0 + c1


class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    def send(self, msg: str):
        self.request.sendall(msg.encode())

    def recv_line(self, maxlen=256):
        data = b""
        while not data.endswith(b"\n") and len(data) < maxlen:
            chunk = self.request.recv(1)
            if not chunk:
                break
            data += chunk
        return data.decode(errors="ignore").strip()

    def handle(self):
        down = random.randint(0x01, 0x60)
        up = down + 31
        delta0 = random.randint(down, up)
        delta1 = random.randint(down, up)
        DELTA_P = bytes([delta0, delta1] + [0] * 6)

        WELCOME = (
            "=== Welcome to the Advanced MISTY1 ECB Oracle Service (2-block) ===\n"
            f"For this session, DELTA_P has two non-zero bytes at positions 0 and 1.\n"
            f"Both are between 0x{down:02x} and 0x{up:02x} (32-byte range each).\n"
            "Only the FIRST block is masked by DELTA_P under Oracle 2.\n"
            "Type 'help' for menu and details.\n"
            "-------------------------------------------------------------------\n"
        )

        HELP = f"""
======================[ MENU ]=======================
This service gives you two encryption oracles (ECB, 2 blocks = 16 bytes):
  1. Oracle 1: E_k                (with restrictions)
  2. Oracle 2: E_k((pt0 XOR Delta_P) || pt1)   # mask applies to FIRST block only

Commands:
  oracle1 <hex_plaintext_16B>   Encrypt under Oracle 1 (ECB)
  oracle2 <hex_plaintext_16B>   Encrypt under Oracle 2 (ECB, first block XOR Delta_P)
  flag <hex_ciphertext_8B>      Submit target ciphertext (must equal E_k(FLAG_BLOCK))
  help                          Show this menu
  exit                          Disconnect

Constraints:
  - Plaintexts for oracles must be exactly 16 bytes (32 hex chars).
  - DELTA_P: two non-zero bytes at indices 0 and 1, each in 0x{down:02x}~0x{up:02x}; others are 0x00.
  - Oracle 1 restriction: inputs whose SECOND block equals FLAG_BLOCK are FORBIDDEN.
  - You MUST use BOTH oracles to pass. See Goal.

Goal:
  - Submit the ciphertext of b'FAKEFLAG' (8 bytes) under E_k, i.e., E_k(FLAG_BLOCK).
  - Acceptance additionally REQUIRES that you have:
      (A) Queried oracle1 at least once with FIRST block == (FLAG_BLOCK XOR Delta_P), SECOND block arbitrary (but not FLAG_BLOCK).
      (B) Queried oracle2 at least once with input == ( (FLAG_BLOCK XOR Delta_P) || FLAG_BLOCK ).
=======================================================
"""

        self.send(WELCOME)

        query_count = 0
        MAX_QUERY = 2000
        pt_cache = dict()
        MAX_REPEAT = 8

        self.triggers = set()

        def split_blocks(x: bytes):
            return x[:8], x[8:]

        while True:
            self.send("> ")
            cmd = self.recv_line()
            if not cmd:
                break
            parts = cmd.split()
            if len(parts) == 0:
                continue
            try:
                if parts[0] == 'help':
                    self.send(HELP)
                    continue

                if parts[0] == 'exit':
                    self.send("Bye!\n")
                    break

                elif parts[0] in ['oracle1', 'oracle2']:
                    if len(parts) != 2:
                        self.send(f"Usage: {parts[0]} <hex_plaintext_16B>\n")
                        continue
                    if query_count >= MAX_QUERY:
                        self.send("Query limit reached!\n")
                        continue

                    try:
                        pt = bytes.fromhex(parts[1])
                    except Exception:
                        self.send("Invalid hex input.\n")
                        continue
                    if len(pt) != 16:
                        self.send("Plaintext must be exactly 16 bytes!\n")
                        continue

                    oracle_name = parts[0]
                    cache_key = (oracle_name, pt)
                    pt_cache.setdefault(cache_key, 0)
                    if pt_cache[cache_key] >= MAX_REPEAT:
                        self.send("This plaintext is overused. Try another!\n")
                        continue
                    pt_cache[cache_key] += 1

                    pt0, pt1 = split_blocks(pt)

                    if oracle_name == 'oracle1' and pt1 == FLAG_BLOCK:
                        self.send(
                            "Second block equals FLAG_BLOCK: forbidden on oracle1.\n")
                        continue

                    if oracle_name == 'oracle1':
                        ct = ecb_encrypt(pt, misty1_k)
                    else:
                        pt0_x = bytes([pt0[i] ^ DELTA_P[i] for i in range(8)])
                        pt_xored = pt0_x + pt1
                        ct = ecb_encrypt(pt_xored, misty1_k)

                    self.triggers.add((oracle_name, pt))

                    self.send(f"Ciphertext: {ct.hex()}\n")
                    query_count += 1

                elif parts[0] == 'flag':
                    if len(parts) != 2:
                        self.send("Usage: flag <hex_ciphertext_8B>\n")
                        continue
                    try:
                        ct_attempt = bytes.fromhex(parts[1])
                    except Exception:
                        self.send("Invalid hex input.\n")
                        continue
                    if len(ct_attempt) != 8:
                        self.send("Ciphertext must be exactly 8 bytes!\n")
                        continue

                    correct_block = misty1_k.encrypt_block(FLAG_BLOCK)

                    oracle1_required_first = bytes([FLAG_BLOCK[0] ^ delta0,
                                                   FLAG_BLOCK[1] ^ delta1]) + FLAG_BLOCK[2:]

                    def triggerA_ok():
                        for (name, pt16) in self.triggers:
                            if name != 'oracle1':
                                continue
                            p0, p1 = pt16[:8], pt16[8:]
                            if p0 == oracle1_required_first and p1 != FLAG_BLOCK:
                                return True
                        return False

                    oracle2_required = oracle1_required_first + FLAG_BLOCK

                    triggerA = triggerA_ok()
                    triggerB = ('oracle2', oracle2_required) in self.triggers

                    if ct_attempt == correct_block and triggerA and triggerB:
                        self.send(f"Correct! Flag: {REAL_FLAG.decode()}\n")
                    else:
                        self.send("Incorrect! Try again.\n")

                else:
                    self.send("Unknown command. Use help for menu.\n")

            except Exception as e:
                self.send(f"Error: {str(e)}\n")


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    HOST, PORT = "0.0.0.0", 9000
    with ThreadedTCPServer((HOST, PORT), ThreadedTCPRequestHandler) as server:
        print(f"MISTY1 Advanced ECB Oracle Service started on port {PORT}")
        server.serve_forever()
