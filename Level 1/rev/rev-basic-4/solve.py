# Dữ liệu 28 bytes được trích xuất từ địa chỉ 0x140003000
secret_data = [
    0x24, 0x27, 0x13, 0xc6, 0xc6, 0x13, 0x16, 0xe6,
    0x47, 0xf5, 0x26, 0x96, 0x47, 0xf5, 0x46, 0x27,
    0x13, 0x26, 0x26, 0xc6, 0x56, 0xf5, 0xc3, 0xc3,
    0xf5, 0xe3, 0xe3, 0x00
]

# Hàm để hoán đổi nibble của một byte
def swap_nibbles(b):
    high_nibble = (b >> 4)
    low_nibble = (b & 0x0F)
    return (low_nibble << 4) | high_nibble

flag_chars = []

# Vòng lặp chạy 28 lần (từ 0 đến 27)
for i in range(28):
    secret_byte = secret_data[i]
    
    # Áp dụng phép hoán đổi nibble để tìm ký tự gốc
    original_char_code = swap_nibbles(secret_byte)
    
    # Chuyển mã số thành ký tự
    flag_chars.append(chr(original_char_code))

# Nối các ký tự lại
result = "".join(flag_chars)

print(f"Input cần tìm là: {result}")
print(f"Flag hoàn chỉnh: DH{{{result}}}")