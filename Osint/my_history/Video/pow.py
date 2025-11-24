def gcd(a, b):
    if b == 0:
        return a
    return gcd(b, a % b)

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

def mypow(n, e, m):
    if e < 0:
        if gcd(n, m) == 1:
            return mypow(inverse(n, m), -e, m)
        else:
            return None

    elif e == 0:
        return 1

    elif e % 2 == 0:
        return mypow(n, e // 2, m)**2 % m

    else:
        return n * mypow(n, (e - 1) // 2, m)**2 % m


if __name__ == "__main__":
    n, e, m = 217835871253, -127835781912349, 12757812

    print(f"{pow(n, e, m) = }")
    print(f"{mypow(n, e, m) = }")
    print("DH{s????????.m?????.m???????}")