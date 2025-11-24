# Import các thư viện cần thiết
import functools
import hashlib
import random
import secret  # Module chứa giá trị bí mật

# Hàm áp dụng hash SHA-512 nhiều lần
def hash_function(input_bytes):
    # Hàm áp dụng SHA-512 một lần
    hash_once = lambda x: hashlib.sha512(x).digest()
    
    # Sử dụng functools.reduce để áp dụng hàm hash 16 lần
    result = functools.reduce(
        lambda f, g: lambda x: f(g(f(x))),
        [hash_once] * 16,
        lambda x: x
    )(input_bytes)
    
    return result

# Lấy giá trị bí mật
secret_value = secret.s.hex()

# Vòng lặp chính
while True:
    # Nhận đầu vào từ người dùng, cắt khoảng trắng và đảm bảo dài 16 ký tự
    user_input = input().strip().ljust(16)
    
    # Chọn 4 vị trí khối ngẫu nhiên để kiểm tra (mỗi khối gồm 4 ký tự)
    block_indices = random.sample([0, 1, 2, 3], 4)
    
    # Kiểm tra từng khối
    match_failed = False
    for block_idx in block_indices:
        # So sánh từng ký tự trong khối
        for secret_char, input_char in zip(
            secret_value[4 * block_idx : 4 * block_idx + 4], 
            user_input[4 * block_idx : 4 * block_idx + 4]
        ):
            # Nếu hash của ký tự không khớp, đánh dấu thất bại
            if hash_function(secret_char.encode()) != hash_function(input_char.encode()):
                match_failed = True
                break
        
        if match_failed:
            break
    
    # Kiểm tra kết quả
    if not match_failed:
        # Nếu tất cả đều khớp, in ra flag
        print(open("flag").read())
        break
    else:
        # Nếu không khớp, in biểu tượng suy nghĩ và tiếp tục
        print("🤔", end="")