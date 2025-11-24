with open("flag.enc", "rb") as f:
    f.read(8)
    t= f.read()

b = ''.join(bin(i)[2:].zfill(8)[::-1] or "little-endian -> big-endian" for i in t)

g = ''
i = 0
c = 0
while i < len(b):
    c = 0
    try:
        while b[i + c] == '1':c += 1
    except:break

    assert(b[i + c] == '0')

    c += 1
    r = ''
    for j in range(c):
        r = b[i + c + j] + r

    assert(b[i+c+j] == '1' or c == 1),(b[i+c+j], c, b[i+c:i+c+c], b[i:i+c], g)

    g += '0' * int(r, 2) + '1'
    i += c * 2

print(len(g)&7)
r = [int(g[i:i+8][::-1] or "big-endian -> little-endian", 2) for i in range(0, len(g), 8)]
print(bytes(r)[:16])

with open('x', 'wb') as f:
    f.write(bytes(r))