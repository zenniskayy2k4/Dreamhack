def nxt(x):
    x ^= (x << 13) & 0xFFFFFFFF
    x ^=  x >> 17
    x ^= (x <<  5) & 0xFFFFFFFF
    return x & 0xFFFFFFFF

def ks(s, n):
    _ = nxt(s)
    for _ in range(n):
        s = nxt(s)
        yield (s >> 8) & 0xFF

CT = b'\xa8\xd7Mp7\xf8W\x02*\xa0\xbc\x94\x8c<\xccO\x89\xee\t\xf8\xb3`\xbe\x8b'

for seed in range(2**24):  # 2^24 = 16,777,216
    flag = bytes(ct ^ k for ct, k in zip(CT, ks(seed, len(CT))))
    
    if flag.startswith(b'DH{'):
        print(f"Seed: {seed}")
        print(f"Flag: {flag.decode()}")
        break
        
    if (seed + 1) % 1000000 == 0:
        print(f"Checked {seed + 1:,} seeds...")