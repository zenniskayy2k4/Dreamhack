from Crypto.Cipher import AES
from Crypto.Util.number import getPrime, long_to_bytes
from Crypto.Util.Padding import pad
from secrets import randbelow
import hashlib

class SafeLCG:
    def __init__(self):
        self.n = 256
        self.m = 96
        self.p = getPrime(self.n + self.m)
        self.a = randbelow(self.p)
        self.b = randbelow(self.p)
        self.x = randbelow(self.p)

    def next(self):
        # self.x = (self.a * self.x + self.b) % self.p
        # Ok, this must be safe... wait, it's not LCG anymore
        self.x = (self.a * pow(self.x, -1, self.p) + self.b) % self.p
        return self.x & ((1 << self.n) - 1)
    

lcg = SafeLCG()

for _ in range(10):
    print(lcg.next())

with open("flag", "rb") as f:
    flag = f.read()

key = hashlib.sha256(long_to_bytes(lcg.next())).digest()
cipher = AES.new(key, AES.MODE_ECB)
ct = cipher.encrypt(pad(flag, 16))

print(f"{lcg.p = }")
print(f"{lcg.a = }")
print(f"{lcg.b = }")
print(f"ct = {ct.hex()}")