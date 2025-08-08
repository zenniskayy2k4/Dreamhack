from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
import hashlib

from sympy import GF, ZZ, Matrix

def solve(p, a, b, outputs, bits, trunc):
    count = len(outputs)
    M = 2^(bits - trunc)

    mat = [
        [0 for _ in range(count + count - 1 + count - 1 + 1)]
        for _ in range(count + count - 1 + count - 1 + 1)
    ]

    MUL = 2^trunc
    MUL2 = 2^1024

    for i in range(count - 1):
        t0 = int((outputs[i] * (outputs[i + 1] - b) - a) % p)   
        t1 = int((M * (outputs[i + 1] - b)) % p)
        t2 = int((M * outputs[i]) % p)
        t3 = int(M^2 % p)

        mat[i][2 * count - 1 + i] = MUL2 * t1
        mat[i + 1][2 * count - 1 + i] = MUL2 * t2
        mat[count + i][2 * count - 1 + i] = MUL2 * t3
        mat[-1][2 * count - 1 + i] = MUL2 * t0

    for i in range(count - 1):
        mat[count + i][count + i] = 1
        mat[2 * count - 1 + i][2 * count - 1 + i] = MUL2 * p
        mat[-1][count + i] = -MUL^2 // 2

    for i in range(count):
        mat[i][i] = MUL
        mat[-1][i] = -MUL^2 // 2

    mat[-1][-1] = MUL^2

    mat = Matrix(ZZ, mat)

    res = mat.LLL()
    for row in res:
        if row[-1] in [MUL^2, -MUL^2]:
            row = row / (row[-1] // MUL^2)
            es = [ row[i] // MUL + MUL // 2 for i in range(count) ]
            flag = True

            for i in range(count - 1):
                mul = row[count + i] + MUL^2 // 2
                if es[i] * es[i + 1] % p != mul % p:
                    flag = False
                    break

            if flag:
                cur = int(es[-1] * M + outputs[-1])
                nxt = int( (GF(p)(a) / cur + b) )
                return nxt & (M - 1)

with open("output.txt", "r") as f:
    outputs = []
    for _ in range(10):
        outputs.append(int(f.readline().strip()))
    
    lcg = []
    for _ in range(3):
        lcg.append(int(f.readline().strip().split(" = ")[-1]))
    p, a, b = lcg

    ct = bytes.fromhex(f.readline().strip().split(" = ")[-1])
    out = solve(p, a, b, outputs, 256 + 96, 96)
 
    key = hashlib.sha256(long_to_bytes(out)).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    print(cipher.decrypt(ct))