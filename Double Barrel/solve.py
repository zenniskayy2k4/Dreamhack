#!/usr/bin/env python3
from pwn import *
from tqdm import trange
import os
import json

# ---- BƯỚC 1: IMPORT TỪ CÁC FILE ĐỀ BÀI ----
# Đảm bảo các file này ở cùng thư mục
from utils import *
from cipher import sbox, GHOST # Chỉ import những gì cần thiết

# ---- Cài đặt môi trường ----
LOCAL = True # Đặt là False khi chạy với server thật

HOST = "your.server.ip"  # Thay đổi khi cần
PORT = 1337

# Các hàm tấn công vẫn cần được định nghĩa ở đây vì chúng không có trong file đề
def substitution(bit32: list[int]) -> list[int]:
    res: list[int] = []
    for i, j in enumerate(range(0, 32, 4)):
        res += int_to_bits(sbox[7 - i][bits_to_int(bit32[j:j + 4])], 4)
    return res

def find_feedback_index(seeds_hex):
    seeds_bin = bin(int(seeds_hex, 16))[2:].zfill(2048)
    # Tìm 47 bit 0 liên tiếp
    substring = '0' * 47
    idx = seeds_bin.find(substring)
    if idx == -1:
        return -1
    # Chuyển đổi từ index của chuỗi bit (MSB-first) sang index của phép dịch phải
    return 2048 - (idx + 47)

def get_basis_rks(poly):
    # Tối ưu hóa: lưu và tải lại basis đã tính
    if os.path.exists("rk_basis.json"):
        with open("rk_basis.json", "r") as f:
            return json.load(f)

    basis_rks = []
    print("Pre-computing RK basis...")
    for i in trange(48):
        seed = 1 << i
        os.system(f"./key {poly} {seed} > rk.txt")
        rks = []
        with open("rk.txt", "r") as f:
            for line in f.readlines():
                rks.append(int(line.strip()))
        basis_rks.append(rks)
    
    with open("rk_basis.json", "w") as f:
        json.dump(basis_rks, f)

    os.remove("rk.txt")
    return basis_rks

def get_rks_from_key(key, basis_rks):
    final_rks = [0] * 32
    for i in range(48):
        if (key >> i) & 1:
            for j in range(32):
                final_rks[j] ^= basis_rks[i][j]
    # Chuyển các khóa vòng về dạng list[int] bit
    return [int_to_bits(rk, 32) for rk in final_rks]

def encrypt_16(pt_bytes, rks_bits):
    state = bytes_to_bits(pt_bytes)
    for i in range(16):
        state_hi = state[:32]
        state_lo = state[32:]
        
        state_lo = add_mod_2_32(state_lo, rks_bits[i])
        state_lo = substitution(state_lo)
        state_lo = rol11(state_lo)
        state_lo = xor_lst(state_lo, state_hi)

        state[:32] = state[32:]
        state[32:] = state_lo
    
    return bits_to_int(state)

def decrypt_16(ct_bytes, rks_bits):
    state = bytes_to_bits(ct_bytes)
    # Trạng thái đầu vào của decrypt_16 là (R16, L16), nhưng encrypt_16
    # trả về (L17, R17) = (R16, L16 ^ F(R16, K16)).
    # Vì thế ta cần hoán vị lại trước khi bắt đầu giải mã ngược
    state = state[32:] + state[:32]

    for i in range(15, -1, -1):
        # Trạng thái hiện tại là L_{i+1} || R_{i+1}
        state_hi = state[:32] # L_{i+1} = R_i
        state_lo = state[32:] # R_{i+1} = L_i ^ F(R_i, K_i)

        round_key_bits = rks_bits[i]
        
        # F(R_i, K_i) = F(L_{i+1}, K_i)
        temp = add_mod_2_32(state_hi, round_key_bits)
        temp = substitution(temp)
        temp = rol11(temp)
        
        # L_i = R_{i+1} ^ F(R_i, K_i)
        L_prev = xor_lst(state_lo, temp)
        # R_i = L_{i+1}
        R_prev = state_hi
        
        # Trạng thái mới là L_i || R_i
        state = L_prev + R_prev
        
    return bits_to_int(state)

# ---- Main script ----
if LOCAL:
    # Chạy script test cục bộ
    r = process(["python", "local_prob.py"])
else:
    # Kết nối tới server thật
    r = remote(HOST, PORT)

r.recvuntil("🌱 = ".encode())
seeds_hex = r.recvline().strip().decode()

# 1. First Barrel: Find weak feedback polynomial
print("Finding weak feedback index...")
feedback_idx = find_feedback_index(seeds_hex)
if feedback_idx == -1:
    print("[-] Could not find a suitable feedback index (47 consecutive zeros).")
    exit()

print(f"Found index: {feedback_idx}")
r.sendlineafter(b">> ", str(feedback_idx).encode())

poly = 2**47

# 2. Second Barrel: Pre-compute basis and use linearity
basis_rks = get_basis_rks(poly)

# 3. Meet-in-the-Middle attack
print("Starting Meet-in-the-Middle attack...")
pt = b'\x00' * 8
r.sendlineafter(b">> ", b"1")
r.sendlineafter(b">> ", pt.hex().encode())
r.recvuntil(b'>> ')
ct_hex = r.recvline().strip().decode()
ct = bytes.fromhex(ct_hex)

# Forward table
forward_map = {}
print("Building forward map (2^24 entries)...")
for key_lo in trange(1 << 24):
    rks_bits = get_rks_from_key(key_lo, basis_rks)
    mid_state = encrypt_16(pt, rks_bits[:16])
    forward_map[mid_state] = key_lo

# Backward search
print("Searching in backward map (2^24 entries)...")
found_key = -1
for key_hi in trange(1 << 24):
    key_hi_full = key_hi << 24
    rks_bits = get_rks_from_key(key_hi_full, basis_rks)
    
    mid_state_prime = decrypt_16(ct, rks_bits[16:])
    
    if mid_state_prime in forward_map:
        key_lo = forward_map[mid_state_prime]
        found_key = key_hi_full | key_lo
        print(f"\n[+] Found secret key: {hex(found_key)}")
        break

if found_key == -1:
    print("[-] Could not find key. Exiting.")
    exit()

# 4. Solve the challenge
# Sử dụng lớp GHOST đã import để giải mã, an toàn và chính xác hơn
final_rks_int_list = [bits_to_int(rk) for rk in get_rks_from_key(found_key, basis_rks)]
# Tạo một instance GHOST giả lập với key đã tìm được
# Chúng ta không thể tạo trực tiếp vì không có key 6 byte, nhưng có thể monkey-patch
# Hoặc đơn giản là dùng hàm giải mã đã có
solver_cipher = GHOST(b'\x00'*6, feedback_idx) # key và feedback là dummy
solver_cipher._round_keys = [int_to_bits(rk) for rk in final_rks_int_list] # Ghi đè khóa vòng

r.sendlineafter(b">> ", b"3")
r.recvuntil(b'>> ')
ct_chal_hex = r.recvline().strip().decode()
ct_chal = bytes.fromhex(ct_chal_hex)

pt_guess = solver_cipher.decrypt(ct_chal)

r.sendlineafter(b">> ", pt_guess.hex().encode())
r.interactive()