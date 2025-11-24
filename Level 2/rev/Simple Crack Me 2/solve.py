# Dữ liệu tại PTR_DAT_00404050 (kết quả cuối cùng cần đạt được)
target_bytes = bytearray.fromhex("f8e0e69e7f32683105dca1aaaa09b3d841f0368ccec7ac66914c32ff05e0d991")

# Dữ liệu tại DAT_00402068
key1 = bytes.fromhex("deadbeef")

# Dữ liệu tại DAT_0040206d
key2 = bytes.fromhex("efbeadde")

# Dữ liệu tại DAT_00402072
key3 = bytes.fromhex("1133557799bbdd")

# --- Các hàm biến đổi và hàm ngược của chúng ---

def xor_with_key(data, key):
    """Phép XOR lặp khóa. Phép toán ngược của nó là chính nó."""
    key_len = len(key)
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = data[i] ^ key[i % key_len]
    return result

def add_value(data, value):
    """Cộng một hằng số vào mỗi byte."""
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = (data[i] + value) & 0xFF # & 0xFF để đảm bảo byte không bị tràn
    return result

def sub_value(data, value):
    """Trừ một hằng số khỏi mỗi byte."""
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = (data[i] - value) & 0xFF # & 0xFF để đảm bảo byte không bị tràn
    return result

# --- BƯỚC 2: Thực hiện giải mã theo thứ tự ngược lại ---

# Ban đầu là chuỗi mục tiêu
current_data = target_bytes

# Bước 1 (Ngược của bước 7: XOR)
current_data = xor_with_key(current_data, key3)

# Bước 2 (Ngược của bước 6: ADD 0xf3 -> SUB 0xf3)
current_data = sub_value(current_data, 0xf3)

# Bước 3 (Ngược của bước 5: SUB 0x4d -> ADD 0x4d)
current_data = add_value(current_data, 0x4d)

# Bước 4 (Ngược của bước 4: XOR)
current_data = xor_with_key(current_data, key2)

# Bước 5 (Ngược của bước 3: SUB 0x5a -> ADD 0x5a)
current_data = add_value(current_data, 0x5a)

# Bước 6 (Ngược của bước 2: ADD 0x1f -> SUB 0x1f)
current_data = sub_value(current_data, 0x1f)

# Bước 7 (Ngược của bước 1: XOR)
final_bytes = xor_with_key(current_data, key1)


# --- BƯỚC 3: In kết quả cuối cùng ---
try:
    final_input = final_bytes.decode('ascii')
    print("\n=============================================")
    print(f"INPUT DUNG LA: {final_input}")
    print(f"FLAG: DH{{{final_input}}}")
    print("=============================================")
except UnicodeDecodeError:
    print("\n[!] Khong the decode ket qua sang ASCII. Co the co loi trong du lieu ban dau.")
    print(f"Ket qua dang byte: {final_bytes}")