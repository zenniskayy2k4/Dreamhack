import os
import random

def clock():
    h, m = 0, 0
    H = list(range(8))
    M = list(range(8))
    random.shuffle(H)
    random.shuffle(M)

    while True:
        cal=8*H[h]+M[m]
        m+=1
        if m>=8:
            h+=1; h%=8; m=0
        yield cal


with open("flag.txt", "rb") as f:
    data = f.read()

# Assume that all bytes in flag.txt are printable ASCII letters, with given format.
assert all(((0x41 <= x <= 0x5a) or (0x61<= x <= 0x7a) or (x==0x5f)) for x in data[3:63])
assert data[:3]==b'DH{'
assert data[63]==ord('}')

with open("flag.txt.enc", "wb") as f:
    for a, b in zip(data, clock()):
        f.write(bytes([a ^ b]))

os.remove("flag.txt")