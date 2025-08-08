from Crypto.Util.number import *
import random
import json
import secrets

FLAG = b'DH{????????????????????????????????}'
m1 = bytes_to_long(FLAG)
e = 157


def one_instance():
    p = getPrime(320)
    q = getPrime(1728)
    n = p * q

    a = p
    b = random.randrange(2, 2**128)
    c = random.randrange(2, 2**128)
    d = random.randrange(2, 2**128)

    m3 = (a*pow(m1, 3, n) + b*pow(m1, 2, n) + c*m1 + d) % n

    c1 = pow(m1, e, n)
    c2 = pow(m3, e, n)

    return {
        "n":  str(n),
        "a":  str(a),
        "e":  e,
        "c1": str(c1),
        "c2": str(c2),
        "b":  str(b),
        "c":  str(c),
        "d":  str(d)
    }


inst1 = one_instance()
inst2 = one_instance()

hint = FLAG[:5].decode()

json.dump({"instance1": inst1,
           "instance2": inst2,
           "hint": hint},
          open("output.txt", "w"), indent=2)
