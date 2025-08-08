import os

F = b'DH{fake_flag}'
SEED = int.from_bytes(os.urandom(3), 'big')

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

CT = bytes(f ^ k for f, k in zip(F, ks(SEED, len(F))))
print(repr(CT)) # b'\xa8\xd7Mp7\xf8W\x02*\xa0\xbc\x94\x8c<\xccO\x89\xee\t\xf8\xb3`\xbe\x8b'
