import itertools

# Các hằng số không đổi
key = b"PaRsT5vW8iJkL=n_1"
elf_magic = b"\x7fELF"

# Tên file
input_file = "quiz.zrq"
output_file = "quiz_recovered.elf"

print("[*] Đang đọc file mã hóa...")
try:
    with open(input_file, "rb") as f:
        encrypted_data = f.read()
except FileNotFoundError:
    print(f"[!] Lỗi: Không tìm thấy file '{input_file}'")
    exit()

found = False
found_data_offset = -1
found_key_offset = -1

print("[*] Bắt đầu tìm kiếm data offset và key offset...")

# Lặp qua các data offset khả thi (ví dụ: 256 byte đầu)
for data_offset in range(256):
    if data_offset + 4 > len(encrypted_data):
        break

    # Lặp qua tất cả các key offset khả thi (từ 0 đến độ dài key - 1)
    for key_offset in range(len(key)):
        # Thử giải mã 4 byte header
        decrypted_header = bytearray(4)
        for i in range(4):
            key_char = key[(key_offset + i) % len(key)]
            encrypted_char = encrypted_data[data_offset + i]
            decrypted_header[i] = encrypted_char ^ key_char

        # So sánh với magic bytes của ELF
        if bytes(decrypted_header) == elf_magic:
            found_data_offset = data_offset
            found_key_offset = key_offset
            found = True
            break
    if found:
        break

if found:
    print(f"\n[+] TÌM THẤY!")
    print(f"    -> Data Offset (vị trí bắt đầu mã hóa trong file): {found_data_offset}")
    print(f"    -> Key Offset (vị trí bắt đầu trong key): {found_key_offset} (ký tự: '{key[found_key_offset:found_key_offset+1].decode()}')")

    # Tách phần prefix không mã hóa
    unencrypted_prefix = encrypted_data[:found_data_offset]

    # Lấy phần dữ liệu cần giải mã
    data_to_decrypt = encrypted_data[found_data_offset:]

    # "Xoay" key để bắt đầu từ đúng vị trí
    rotated_key = key[found_key_offset:] + key[:found_key_offset]
    print(f"    -> Key được sử dụng để giải mã (đã xoay): {rotated_key.decode()}")

    # Giải mã toàn bộ phần thân bằng key đã xoay
    decrypted_body = bytes([b ^ k for b, k in zip(data_to_decrypt, itertools.cycle(rotated_key))])

    # Ghép lại
    final_data = unencrypted_prefix + decrypted_body

    # Lưu file
    with open(output_file, "wb") as f:
        f.write(final_data)

    print(f"\n[*] Đã khôi phục file thành công và lưu vào '{output_file}'")
    print("[*] Bước tiếp theo: Hãy thử chạy file này trên Linux/WSL (`chmod +x quiz_recovered.elf && ./quiz_recovered.elf`) hoặc mở nó trong Ghidra.")

else:
    print("\n[!] Không tìm thấy sự kết hợp data/key offset nào hợp lệ.")
    print("[!] Có thể giả thuyết về XOR không đúng, hoặc key đã bị biến đổi theo cách khác.")