import socketserver
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes

RSA_BITS = 256
P_BITS = RSA_BITS // 2
E = 65537
FLAG = b"DH{L0C4L_}"  # Flag = 10 Bytes


def pkcs1_v1_5_pad(data: bytes, k: int) -> bytes:
    pad_len = k - len(data) - 3
    return b"\x00\x02" + b"\xff" * pad_len + b"\x00" + data


def pkcs1_v1_5_check(m_bytes: bytes, k: int):
    if not m_bytes.startswith(b"\x00\x02"):
        return (1, None)
    try:
        idx = m_bytes.index(b"\x00", 2)
    except ValueError:
        return (2, None)
    pad_len = idx - 2
    return (0, pad_len)


p = getPrime(P_BITS)
q = getPrime(P_BITS)
n = p * q
phi = (p - 1) * (q - 1)
d = inverse(E, phi)

k = (n.bit_length() + 7) // 8
padded_flag = pkcs1_v1_5_pad(FLAG, k)
flag_c = pow(bytes_to_long(padded_flag), E, n)


class Handler(socketserver.BaseRequestHandler):
    def send(self, msg: str, end: bool = True):
        data = msg + ("\n" if end else "")
        self.request.sendall(data.encode())

    def recvline(self) -> bytes:
        buf = b""
        while True:
            c = self.request.recv(1)
            if not c or c == b"\n":
                break
            buf += c
        return buf

    def handle(self):
        self.send(f"n : {n}")
        self.send(f"e : {E}")
        self.send(f"ciphertext : {flag_c}")
        self.send(
            '--- Commands: oracle <int> [up to 10000 args], submit <hex>, exit ---')

        while True:
            self.send('> ', end=False)
            line = self.recvline()
            if not line:
                break
            parts = line.strip().split()
            if not parts:
                self.send("Error: invalid input format")
                continue
            cmd, *args = parts

            if cmd == b'oracle':
                if len(args) < 1 or len(args) > 10000:
                    self.send("Error: oracle takes 1~10000 arguments")
                    continue
                outputs = []
                for tok in args:
                    try:
                        c = int(tok)
                        m = pow(c, d, n)
                        m_bytes = long_to_bytes(m, k)
                        code, pad_len = pkcs1_v1_5_check(m_bytes, k)
                        if code == 0:
                            outputs.append(f"OK len={pad_len}")
                        elif code == 1:
                            outputs.append("ERR_HEADER")
                        elif code == 2:
                            outputs.append("ERR_NUL")
                        else:
                            outputs.append("NO")
                    except Exception:
                        outputs.append("ERR")
                self.send(" ".join(outputs))
                continue

            elif cmd == b'submit' and len(args) == 1:
                try:
                    userflag = bytes.fromhex(args[0].decode())
                    if userflag == FLAG:
                        self.send("Padding is Correct")
                    else:
                        self.send("Padding is Incorrect")
                except Exception:
                    self.send(
                        "Error: Please enter only hexadecimal flags for the submit command")
                continue

            elif cmd == b'exit':
                self.send("Bye!")
                break

            else:
                self.send("Error: Unsupported command or argument count error")
                continue


class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    HOST, PORT = "localhost", 12345
    print(f"[*] Starting server on {HOST}:{PORT}")
    print(f"[*] Local Flag is: {FLAG.decode()} ({len(FLAG)} bytes)")
    print("[*] Waiting for connections...")
    with Server((HOST, PORT), Handler) as server:
        server.serve_forever()
