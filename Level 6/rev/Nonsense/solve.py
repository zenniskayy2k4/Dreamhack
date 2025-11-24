import struct
import QUARK          # Sử dụng file QUARK.py
from bitstring import BitArray
import numpy as np    # QUARK.py cần numpy

def p16(x):
    """Đóng gói số nguyên thành 2 bytes little-endian."""
    return struct.pack("<H", x)

def bytes_to_bits(byte_data):
    """Chuyển đổi bytes thành một list các bit [0, 1]."""
    return [int(c) for c in BitArray(byte_data).bin]

# --- Dữ liệu dump từ binary (giữ nguyên) ---
hex_dump = """
71 f1 1f ab 00 00 00 00 ce 37 64 11 00 00 00 00
c0 9f 04 e6 00 00 00 00 d1 29 29 45 00 00 00 00
eb 47 a4 75 00 00 00 00 a8 cd e8 c9 00 00 00 00
44 01 db 1c 00 00 00 00 9c ea d4 f6 00 00 00 00
44 01 db 1c 00 00 00 00 b3 19 43 c6 00 00 00 00
54 3c d0 f2 00 00 00 00 34 62 be ca 00 00 00 00
ab a6 95 11 00 00 00 00 04 56 8a dc 00 00 00 00
1b 07 dc a7 00 00 00 00 d4 16 d2 3e 00 00 00 00
c0 24 54 d0 00 00 00 00 d9 d5 13 1a 00 00 00 00
64 e4 a2 e8 00 00 00 00 2d b4 69 84 00 00 00 00
9c ea d4 f6 00 00 00 00 d1 29 29 45 00 00 00 00
b0 bc eb ba 00 00 00 00 56 70 b5 eb 00 00 00 00
"""

byte_data = bytes.fromhex(hex_dump.replace('\n', '').replace(' ', ''))
enc_arr = list(struct.unpack('<24Q', byte_data))

print("Đã load mảng hash mục tiêu.")

# --- Bruteforce d-Quark (phiên bản Python thuần, hãy kiên nhẫn) ---
d_quark = QUARK.D_Quark() # Khởi tạo d-Quark từ file QUARK.py
dec_dict = {}

print("\nBắt đầu bruteforce hash. Việc này sẽ mất vài phút, xin hãy kiên nhẫn...")
for i in range(0x10000):
    input_bytes = p16(i)
    input_bits = bytes_to_bits(input_bytes)
    
    hashed_output_hex = d_quark.keyed_hash([], input_bits, output_type="hex")
    hashed_value_hex = hashed_output_hex[:16]
    hashed_bytes_big_endian = bytes.fromhex(hashed_value_hex)
    hashed_value_int_le = struct.unpack('<Q', hashed_bytes_big_endian)[0]
    
    dec_dict[hashed_value_int_le] = input_bytes
    
    if (i + 1) % 1024 == 0: # In ra tiến trình để bạn biết nó không bị treo
        print(f"  Đã xử lý {i+1}/{0x10000} giá trị...")

print("Bruteforce hoàn tất!")

# --- Giải mã flag ---
flag = b""
found_count = 0
for enc_value in enc_arr:
    if enc_value in dec_dict:
        flag += dec_dict[enc_value]
        found_count += 1
    else:
        print(f"Lỗi: không tìm thấy hash {hex(enc_value)} trong từ điển!")
        flag += b'??'

print("\n-------------------------------------------------")
if found_count == len(enc_arr):
    print("THÀNH CÔNG! Đã tìm thấy tất cả các hash.")
else:
    print(f"CẢNH BÁO: Chỉ tìm thấy {found_count}/{len(enc_arr)} hash. Flag có thể không đầy đủ.")

print(f"FLAG: {flag.decode(errors='ignore')}")
print("-------------------------------------------------")