def xgcd(a, b): 
    if b == 0:
        return a, 1, 0

    g, x1, y1 = xgcd(b, a % b)
    x = y1
    y = (g - a * x) // b 
    assert a * x + b * y == g

    return g, x, y

def crt(rem, mod):
    a, b = rem
    p, q = mod
    g, alpha, beta = xgcd(p, q)
    assert g == 1

    c = a * q * beta + b * p * alpha
    final_mod = p * q
    c %= final_mod

    assert c % p == a
    assert c % q == b

    return c, final_mod

def crt_multi(rem, mod):
    c = 0
    final_mod = 1
    for a, p in zip(rem, mod):
        c, final_mod = crt([c, a], [final_mod, p])

    for a, p in zip(rem, mod):
        assert c % p == a

    return c, final_mod

if __name__ == "__main__":
    print(crt([2, 3], [6, 5]))
    print(crt_multi([2, 3, 11], [6, 5, 13]))

