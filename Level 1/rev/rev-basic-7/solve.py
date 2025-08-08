a = [0x52, 0xdf, 0xb3, 0x60, 0xf1, 0x8b, 0x1c, 0xb5,
     0x57, 0xd1, 0x9f, 0x38, 0x4b, 0x29, 0xd9, 0x26,
     0x7f, 0xc9, 0xa3, 0xe9, 0x53, 0x18, 0x4f, 0xb8,
     0x6a, 0xcb, 0x87, 0x58, 0x5b, 0x39, 0x1e]

def ror(byte, shift):
    shift &= 7 # Đảm bảo shift_amount luôn trong khoảng 0-7, tương đương i % 8
    # Dịch phải `shift` bit, và OR với phần bị đẩy ra được dịch trái `8-shift` bit
    return ((byte >> shift) | (byte << (8 - shift))) & 0xFF

flag = []

for i in range(len(a)):
    shift_amount = i % 8
    
    # Bước 1: Đảo ngược phép XOR
    temp_value = a[i] ^ i
    
    # Bước 2: Đảo ngược phép ROL bằng ROR
    original_byte = ror(temp_value, shift_amount)
    
    # Chuyển mã ASCII sang ký tự
    flag.append(chr(original_byte))
    
res = ''.join(flag)

print(f"Input: {res}")
print(f"Flag: DH{{{res}}}")