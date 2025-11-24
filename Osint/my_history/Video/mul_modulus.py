def xgcd(a, b): 
    if b == 0:
        return a, 1, 0

    g, x1, y1 = xgcd(b, a % b)
    x = y1
    y = (g - a * x) // b 
    assert a * x + b * y == g

    return g, x, y
def inverse(a, m):
    g, x, y = xgcd(a, m)

    if g != 1:
        return None
    return x

if __name__ == "__main__":
    a, m = 7, 26
    a_inverse = inverse(a, m)
    print(a_inverse)

    assert (a**7 * a_inverse**3) % m == (a**4) % m
    assert inverse(8, m) == None