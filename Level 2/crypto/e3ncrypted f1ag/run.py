import requests
from Crypto.Util.number import bytes_to_long, long_to_bytes
import struct

# Tham số LCG
A = 0x41C64E6D
C = 0x6073
MOD = 0xFFFFFFFF

def reverse_round(L, R, state):
    """Đảo ngược 1 vòng mã hóa"""
    prev_R = L
    # Công thức đảo ngược chính xác
    prev_L = R ^ ((state ^ L) + (L * prev_R)) & MOD
    return prev_L, prev_R

def decrypt_block(cipher_block, key):
    """Giải mã 1 block 8 byte với key đã biết"""
    L = bytes_to_long(cipher_block[:4])
    R = bytes_to_long(cipher_block[4:])
    
    # Khởi tạo LCG và sinh toàn bộ state
    seed = bytes_to_long(key)
    states = []
    s = seed
    for _ in range(16):
        s = (s * A + C) & MOD
        states.append((s >> 16) & 0xFF)
    states.reverse()  # Đảo ngược thứ tự state để giải mã

    # Giải mã ngược 16 vòng
    for i in range(16):
        L, R = reverse_round(L, R, states[i])
    
    return long_to_bytes(L, 4) + long_to_bytes(R, 4)

def find_valid_key(cipher_block):
    """Tìm key hợp lệ bằng cách kiểm tra định dạng flag"""
    # Brute-force key 4 byte (32-bit)
    for key_int in range(0x100000000):
        key = long_to_bytes(key_int, 4)
        
        try:
            # Thử giải mã
            plain = decrypt_block(cipher_block, key)
            
            # Kiểm tra định dạng flag
            if plain.startswith(b'DH{') and plain[3] != 0 and plain.endswith(b'}'):
                # Kiểm tra ASCII printable
                if all(32 <= b < 127 for b in plain[4:-1]):
                    return key, plain
        except:
            continue
    
    return None, None

# Lấy ciphertext từ server
SERVER_URL = "http://localhost:1337/oracle"
response = requests.get(SERVER_URL)
cipher_hex = response.json()['cipher']
ciphertext = bytes.fromhex(cipher_hex)
print(f"Ciphertext: {cipher_hex}")

# Tách thành các block 8 byte
block_size = 8
blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]

# Giải mã từng block với key tìm được từ block đầu
flag = b''
found_key = None

for i, block in enumerate(blocks):
    if i == 0:
        # Tìm key từ block đầu dùng định dạng flag
        found_key, decrypted = find_valid_key(block)
        if not found_key:
            print("Không tìm thấy key phù hợp!")
            exit()
        flag += decrypted
        print(f"Found key: 0x{bytes_to_long(found_key):08x}")
    else:
        # Giải mã các block sau với key đã biết
        decrypted = decrypt_block(block, found_key)
        flag += decrypted

# In kết quả
try:
    print(f"Flag: {flag.decode()}")
except UnicodeDecodeError:
    print(f"Raw flag bytes: {flag}")
    # Tìm thủ công phần flag
    start = flag.find(b'DH{')
    end = flag.find(b'}', start)
    if start != -1 and end != -1:
        flag = flag[start:end+1]
        print(f"Probable flag: {flag.decode()}")