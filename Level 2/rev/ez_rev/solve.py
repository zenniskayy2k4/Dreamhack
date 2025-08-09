# Dữ liệu đã biết từ file thực thi
encrypted_flag = "|l|GHyRrsfwxmsIrietznhIhj"
key = "qksrkqs"

def rotate_string(s, n):
    """
    Xoay chuỗi s đi n vị trí.
    Nếu n > 0, xoay trái.
    Nếu n < 0, xoay phải.
    """
    return s[n:] + s[:n]

def xor_with_key(text, key):
    """
    Thực hiện phép toán Repeating Key XOR.
    """
    result = ""
    for i, char in enumerate(text):
        key_char = key[i % len(key)]
        decrypted_char_code = ord(char) ^ ord(key_char)
        result += chr(decrypted_char_code)
    return result

# Quá trình giải mã ngược
# 1. Đảo ngược phép ROTATE RIGHT 3 cuối cùng -> ROTATE LEFT 3
current_string = rotate_string(encrypted_flag, 3)

# 2. Đảo ngược phép XOR thứ hai
current_string = xor_with_key(current_string, key)

# 3. Đảo ngược phép ROTATE LEFT 3 -> ROTATE RIGHT 3
current_string = rotate_string(current_string, -3)

# 4. Đảo ngược phép XOR đầu tiên
current_string = xor_with_key(current_string, key)

# 5. Đảo ngược phép ROTATE RIGHT 3 đầu tiên -> ROTATE LEFT 3
flag = rotate_string(current_string, 3)

print("The flag is: " + flag)