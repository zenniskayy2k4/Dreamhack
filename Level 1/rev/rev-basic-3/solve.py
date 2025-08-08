secret_data = [
    0x49, 0x60, 0x67, 0x74, 0x63, 0x67, 0x42, 0x66,
    0x80, 0x78, 0x69, 0x69, 0x7b, 0x99, 0x6d, 0x88,
    0x68, 0x94, 0x9f, 0x8d, 0x4d, 0xa5, 0x9d, 0x45
]

flag_chars = []

for i in range(len(secret_data)):
    secret_byte = secret_data[i]
    
    # Áp dụng công thức đảo ngược
    # temp = secret_byte - (i * 2)
    # original_char_code = temp ^ i
    # (Tất cả tính toán sẽ được xử lý trong phạm vi byte 0-255)
    
    original_char_code = (secret_byte - (i * 2)) ^ i
    
    # Python xử lý số âm, cần đảm bảo kết quả nằm trong khoảng 0-255
    # bằng cách & 0xFF (and với 255)
    flag_chars.append(chr(original_char_code & 0xFF))

# Nối các ký tự lại để tạo thành chuỗi kết quả
result = "".join(flag_chars)

print(f"Input cần tìm là: {result}")
print(f"Flag hoàn chỉnh: DH{{{result}}}")