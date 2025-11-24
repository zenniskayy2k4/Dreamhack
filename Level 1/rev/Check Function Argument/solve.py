# --- BƯỚC 1: Dữ liệu đã trích xuất từ Ghidra (ĐÃ HOÀN CHỈNH) ---

# Dữ liệu ban đầu (param_1) từ DAT_00404080
initial_data_hex = (
    "f4b654aef380724897f0b49904396b44"
    "b44b474a5648bb4f2c48e7ebab51ae33"
    "ad4497e22ca84e2d357cb5b898dea05e"
    "47237e9cbabbeea855153a5a9cc999de"
    "a08144398a6d"
)
initial_data = bytearray.fromhex(initial_data_hex)

# Key XOR tại DAT_0040200f
xor_key = b"\x73\x31\xde\xad\xbe\xef\x37\x33\x10"

# Bảng thay thế từ FUN_0040138d
substitution_table = [
    '', '', '3', '0', '4', '5', '1', 'b', 'c', '2', 'd', '9', '8', '7', 'e', 'f', 'a', '6'
]

# --- BƯỚC 2: Mô phỏng lại các hàm biến đổi ---

def step1_sub(data):
    """Mô phỏng FUN_004012b7(data, 0xb)"""
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = (data[i] - 0xb) & 0xFF
    return result

def step2_xor(data, key):
    """Mô phỏng FUN_004011f6(data, key)"""
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = data[i] ^ key[i % len(key)]
    return result

def step3_add(data):
    """Mô phỏng FUN_0040126a(data, 99)"""
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = (data[i] + 99) & 0xFF
    return result

def step4_to_hex(data):
    """Mô phỏng FUN_00401301(data)"""
    return data.hex()

def step5_substitute(hex_string):
    """Mô phỏng FUN_0040138d(hex_string)"""
    result = ""
    for char in hex_string:
        val = int(char, 16)
        result += substitution_table[val + 2]
    return result

def step6_from_hex(hex_string):
    """Mô phỏng FUN_00401449(hex_string)"""
    # Hàm gốc dùng strtol, nên nó có thể chuyển đổi chuỗi hexa bình thường.
    # Vì vậy, chúng ta chỉ cần dùng hàm fromhex của Python.
    return bytes.fromhex(hex_string)

# --- BƯỚC 3: Chạy toàn bộ quy trình mô phỏng ---

print(f"[*] Dữ liệu ban đầu (70 bytes): {initial_data.hex()}")

# Thực hiện từng bước biến đổi
data = step1_sub(initial_data)
data = step2_xor(data, xor_key)
data = step3_add(data)
hex_str = step4_to_hex(data)
sub_hex_str = step5_substitute(hex_str)
final_bytes = step6_from_hex(sub_hex_str)

# --- BƯỚC 4: In Flag ---
try:
    # Decode kết quả và loại bỏ các byte null ở cuối
    flag = final_bytes.decode('ascii').rstrip('\x00')
    print("\n========================================================")
    print(f"FLAG: {flag}")
    print("========================================================")
except UnicodeDecodeError:
    print("\n[!] Không thể decode kết quả cuối cùng sang ASCII.")
    print(f"Dữ liệu cuối dạng hex: {final_bytes.hex()}")