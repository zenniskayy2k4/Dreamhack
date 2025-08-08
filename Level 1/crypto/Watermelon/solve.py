import json
from Crypto.Util.number import *

with open("output.txt", "r") as f:
    data = json.load(f)
    
inst1 = data["instance1"]
n1 = int(inst1["n"])
a1 = int(inst1["a"])
c1_1 = int(inst1["c1"])

p1 = a1
q1 = n1 // p1

phi1 = (p1 - 1) * (q1 - 1)
e = 157
d1 = inverse(e, phi1)

m1 = pow(c1_1, d1, n1)
flag = long_to_bytes(m1)

print(f"Flag: {flag.decode()}")