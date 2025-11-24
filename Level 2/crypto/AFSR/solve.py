from Crypto.Util.number import bytes_to_long, long_to_bytes
from AFSR import AFSR

# Dữ liệu từ file output.txt
hex_output = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003bfc4bf526d43ebf96ff37cd060ee98c64cc5d97abf89c4e668378ccfc9484a00fda30c8d455c3c2c8c6141272fc8ffb2c5c0c1ac6fb51dc15650ac621e8e978b928957a3f6b36c5312b76d7394e3f34248a5b828ce634d19a4e07ac27ba57ead12b18dff1f1851f266827f5b051f6533c2ed55a0dce683e3b840d0a82b07776dbfd50ab7"

# 1. Chuyển đổi output về dạng bytes và số nguyên
leaked_bytes = bytes.fromhex(hex_output)
leaked_int = bytes_to_long(leaked_bytes)

# 2. Xác định số lượng bit đã được tạo ra
num_bytes = len(leaked_bytes)
num_bits = num_bytes * 8
print(f"[*] Phân tích {num_bytes} bytes = {num_bits} bits.")

# 3. Tính toán giá trị gần đúng của FLAG
# 1/FLAG ≈ leaked_int / 2^num_bits
# => FLAG ≈ 2^num_bits / leaked_int
# Do sai số làm tròn, giá trị thực có thể là kết quả chia nguyên hoặc lân cận.
candidate_F = (2**num_bits) // leaked_int

print(f"[*] Giá trị FLAG ứng viên: {candidate_F}")

# 4. Kiểm tra các ứng viên xung quanh giá trị vừa tính
for i in range(-5, 6):
    test_F = candidate_F + i
    print(f"[*] Đang thử với F = {test_F}...")
    
    # 5. Tái tạo output với giá trị F đang thử
    test_afsr = AFSR(test_F)
    generated_bytes = test_afsr.getNbytes(num_bytes)
    
    # So sánh với output đã cho
    if generated_bytes == leaked_bytes:
        print("\n[+] TÌM THẤY FLAG!")
        print(f"[*] Giá trị nguyên của flag là: {test_F}")
        
        # 6. Chuyển đổi số nguyên trở lại bytes để đọc flag
        flag = long_to_bytes(test_F)
        print(f"[*] Flag: {flag.decode()}")

        # Kiểm tra độ dài bit
        print(f"[*] Độ dài bit của flag: {test_F.bit_length()} (dự đoán là 263)")
        break