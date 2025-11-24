
def gcd(a, b):
    if b == 0:
        return a
    return gcd(b, a % b)

print(gcd(339350, 1026688))

def xgcd(a, b): 
    if b == 0:
        return a, 1, 0

    g, x1, y1 = xgcd(b, a % b)
    # g = x1 * b + y1 * (a % b)
    x = y1
    y = (g - a * x) // b 
    assert a * x + b * y == g

    return g, x, y

print(xgcd(339350, 1026688))