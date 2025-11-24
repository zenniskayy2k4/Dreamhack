# CHÚ Ý: Hàm calculate này vẫn cần được xác minh bằng debugger!
# Logic có thể đã bị thay đổi lúc runtime.
def calculate(param_1):
    param_1 = param_1 & 0xFF
    bVar1 = (param_1 >> 6 | (param_1 ^ 0x3c) * 4) & 0xFF
    bVar1 = (bVar1 * 5 + 0x7d) & 0xFF
    bVar1 = ((bVar1 * 32) | (bVar1 >> 3)) & 0xFF
    bVar1 = (bVar1 ^ 0xb2) & 0xFF
    bVar1 = ((bVar1 >> 4) | (bVar1 << 4)) & 0xFF
    bVar1 = (bVar1 * 3 - 0x2f) & 0xFF
    local_e = ((bVar1 >> 7) | (bVar1 * 2)) & 0xFF
    local_e = (local_e ^ 0xd4) & 0xFF
    
    result = 0
    for i in range(8):
        result = (result << 1) | (local_e & 1)
        local_e >>= 1
    return result

# Mảng này bạn phải tự điền bằng cách trace các hàm verify_func_x
# BẮT ĐẦU TỪ verify_func_28.
# Các giá trị âm phải được chuyển thành byte không dấu bằng cách `& 0xFF`
# Ví dụ: -0x69 & 0xFF = 0x97
encrypted_values = [
    0x97, 0xB9, 0xb1, 0xee, 0xca, 0xe3, 0xb1, 0x19, 0x65, 0xc3, 0xb7, 0xc1, 0xe3, 0x3b, 0xe8, 0xb7, 0xb9, 0x3b, 0xb9, 0x62, 0xe8, 0xbd, 0xb7, 0xb9, 0x65, 0xcd, 0xb9, 0x19, 0xc1, 0x3b, 0xcd, 0xb1, 0xb7, 0xc3, 0xee, 0xc1, 0xc3, 0xee, 0xb7, 0xca, 0xe8, 0xc3, 0xc1, 0xb1, 0x3b, 0x19, 0xee, 0xcd, 0xe8, 0x97, 0xbd, 0xcd, 0x65, 0x62, 0x65, 0xbd, 0xb1, 0x3b, 0x65, 0x97, 0xee, 0xbd, 0xb7, 0xcd
]
flag = ""
# Giả sử bạn đã điền đủ 64 giá trị vào mảng trên
for target_val in encrypted_values:
    found = False
    # Thử tất cả các ký tự có thể (0-255)
    for char_code in range(256):
        if calculate(char_code) == target_val:
            flag += chr(char_code)
            found = True
            break
    if not found:
        flag += "?" # Đánh dấu nếu không tìm thấy

print("Flag: DH{" + flag + "}")