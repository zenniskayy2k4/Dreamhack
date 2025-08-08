# Dữ liệu 24 bytes đầy đủ (index 0 đến 23)
secret_data = [
    0xad, 0xd8, 0xcb, 0xcb, 0x9d, 0x97, 0xcb, 0xc4,
    0x92, 0xa1, 0xd2, 0xd7, 0xd2, 0xd6, 0xa8, 0xa5,
    0xdc, 0xc7, 0xad, 0xa3, 0xa1, 0x98, 0x4c, 0x00
]

# Flag có 25 ký tự (index 0 đến 24), khởi tạo với giá trị 0
flag_codes = [0] * 25

# Chúng ta biết chắc chắn ký tự thứ 24 (index 23) phải là 0
# do Secret[23] == 0. Ký tự thứ 25 (index 24) cũng phải là 0.
flag_codes[24] = 0
flag_codes[23] = 0

# Bắt đầu làm ngược từ i = 22 về 0
# Công thức: Input[i] = Secret[i] - Input[i+1]
for i in range(len(secret_data) - 2, -1, -1):
    # flag_codes[i+1] chính là Input[i+1]
    prev_char_code = (secret_data[i] - flag_codes[i+1]) & 0xFF
    flag_codes[i] = prev_char_code

# Lấy ra chuỗi flag có độ dài 23 ký tự (bỏ ký tự NULL cuối cùng)
result = "".join(chr(c) for c in flag_codes[:23])

print(f"Flag tìm được: {result}")
print(f"Flag hoàn chỉnh: DH{{{result}}}")