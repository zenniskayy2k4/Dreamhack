# Đây là "Plaintext Stub" mà script trước của bạn đã tính toán ra.
# Nó được tạo ra bằng cách tính Hash C rồi XOR với 0xab.
# Đây chính là KEY GIẢI MÃ CUỐI CÙNG, không phải mã máy.
FINAL_DECRYPTION_KEY_HEX = "644477e12a1f818e56488ce266452df0aa730ba474b2e06c716fff54d2e0cc35"
final_key = bytes.fromhex(FINAL_DECRYPTION_KEY_HEX)

# Flag giả từ trong file binary
fake_flag = b"DH{this_is_a_fake_flag}"

# Thuật toán cuối cùng: XOR đơn giản giữa flag giả và key cuối cùng
real_flag = bytearray()

for i in range(len(fake_flag)):
    decrypted_char = fake_flag[i] ^ final_key[i]
    real_flag.append(decrypted_char)

# In kết quả cuối cùng
print("\n" + "="*50)
print("🎉 FLAG THẬT CỦA BẠN LÀ: 🎉")
print(real_flag.decode())
print("="*50)