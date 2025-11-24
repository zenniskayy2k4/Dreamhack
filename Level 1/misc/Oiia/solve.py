# Khóa giải mã thực sự chính là tên của thử thách
key = "OIIA"

# Mở và đọc file chứa 36 byte mã hóa
with open("encrypted_flag.bin", "rb") as f:
    encrypted_data = f.read()

# Chuẩn bị để lưu kết quả giải mã
decrypted_data = bytearray()

# Thực hiện giải mã Repeating Key XOR
for i in range(len(encrypted_data)):
    encrypted_byte = encrypted_data[i]
    key_char = key[i % len(key)]
    key_byte = ord(key_char)
    
    decrypted_byte = encrypted_byte ^ key_byte
    decrypted_data.append(decrypted_byte)

# In flag đã được giải mã ra màn hình
# Lần này nó sẽ là một chuỗi văn bản đọc được
print(decrypted_data.decode())