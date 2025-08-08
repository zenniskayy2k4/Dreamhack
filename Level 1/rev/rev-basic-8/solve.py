from Crypto.Util.number import inverse
a = [0xac, 0xf3, 0x0c, 0x25, 0xa3, 0x10, 0xb7, 0x25, 0x16, 0xc6, 0xb7, 0xbc, 0x07, 0x25, 0x02, 0xd5, 0xc6, 0x11, 0x07, 0xc5, 0x00]

flag = []

# Tính toán giá trị nghịch đảo của -5 modulo 256
inverse = inverse(-5, 256)

for i in range(len(a)):
    # Áp dụng công thức đảo ngược: C = (S * inverse) % 256
    original_char_code = (a[i] * inverse) % 256
    
    # Chuyển mã ASCII thành ký tự
    flag.append(chr(original_char_code))
    
# Nối các ký tự để tạo thành flag
flag = ''.join(flag)
print(f"Input: {flag}")
print(f"Flag: DH{{{flag}}}")