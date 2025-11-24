import requests
import string
import itertools
from Crypto.Util.number import bytes_to_long, long_to_bytes
import time

SERVER_URL = "http://127.0.0.1:1337/oracle"

# --- Logic mã hóa chính xác ---
def real_encrypt(key_bytes, plaintext_bytes):
    v0 = bytes_to_long(key_bytes[:4])
    v1 = bytes_to_long(plaintext_bytes[4:])
    p_long = bytes_to_long(plaintext_bytes)
    for r in range(16):
        p_byte_slice = (p_long >> r) & 0xff
        f_val = ((v1 ^ p_byte_slice) + (r * 0x1234)) & 0xffffffff
        v0, v1 = v1, v0 ^ f_val
    return long_to_bytes(v0, 4) + long_to_bytes(v1, 4)

# --- Các hàm LCG để tìm key ---
class LCG:
    def __init__(self, seed): self.state = seed & 0xffffffff
    def next(self):
        self.state = (self.state * 0x41C64E6D + 0x6073) & 0xffffffff
        return (self.state >> 16) & 0x7fff
    def next_byte(self): return self.next() & 0xff

# --- Tấn công ---
def find_key(cipher_padding_block):
    print("[*] Bắt đầu brute-force seed để tìm key...")
    target_v0_final = cipher_padding_block[:4]
    for seed in range(1 << 25):
        if seed > 0 and seed % (1 << 21) == 0:
            print(f"    -> Đã thử seed đến {seed / (1 << 20):.0f} triệu...")
        rng = LCG(seed)
        key = bytes([rng.next_byte() for _ in range(8)])
        # Chỉ cần tính nửa đầu của cipher, vì nửa sau không phụ thuộc key
        encrypted_v0 = real_encrypt(key, b'\x00' * 8)[:4]
        if encrypted_v0 == target_v0_final:
            print(f"\n[+] KEY ĐÃ TÌM THẤY! Seed = {seed}, Key = {key.hex()}\n")
            return key
    return None

def solve():
    # Bước 1: Lấy ciphertext và tìm key
    key = None
    full_ciphertext = None
    while not key:
        print("\n" + "="*50)
        print("[*] Đang thử một lần giải mới để tìm key...")
        try:
            response = requests.get(SERVER_URL, timeout=10)
            data = response.json()
            full_ciphertext = bytes.fromhex(data['cipher'])
            print(f"[*] Lấy thành công ciphertext: {full_ciphertext.hex()[:64]}...")
        except requests.exceptions.RequestException as e:
            print(f"[!] Lỗi khi kết nối tới server: {e}")
            time.sleep(2)
            continue
        
        cipher_padding_block = full_ciphertext[-8:]
        key = find_key(cipher_padding_block)
        if not key:
            print("[-] Không tìm thấy key, thử lại...")
            time.sleep(1)

    # Bước 2: Giải mã từng khối khi đã có key
    print("[*] Key đã được tìm thấy. Bắt đầu giải mã các khối...")
    flag = b''
    charset = string.ascii_letters + string.digits + "{}_-!?"
    num_blocks = len(full_ciphertext) // 8
    
    # Tạo bảng tra cứu: 4 byte cuối plaintext -> 4 byte cuối ciphertext
    print("[*] Tạo bảng tra cứu cho 4 byte cuối (khoảng 10-20s)...")
    lookup_table = {}
    # Chỉ cần brute-force 24 bit vì 1 byte đầu có thể là null
    for i in range(1 << 24):
        p_last_4_bytes = long_to_bytes(i, 4)
        p_block = b'\x00\x00\x00\x00' + p_last_4_bytes
        c_last_4_bytes = real_encrypt(b'\x00'*8, p_block)[4:] # key không ảnh hưởng
        lookup_table[c_last_4_bytes] = p_last_4_bytes
    print("[+] Bảng tra cứu đã hoàn tất.")

    for i in range(num_blocks - 1): # Bỏ qua khối padding
        cipher_block = full_ciphertext[i*8 : (i+1)*8]
        print(f"\n[*] Đang giải mã khối {i+1}...")
        
        # Tìm 4 byte cuối của plaintext
        target_c_last_4 = cipher_block[4:]
        if target_c_last_4 not in lookup_table:
            print(f"    [-] Lỗi: Không tìm thấy 4 byte cuối của cipher trong bảng tra cứu.")
            # Mở rộng bảng tra cứu nếu cần
            # ...
            continue
        
        p_last_4_bytes = lookup_table[target_c_last_4]
        print(f"    [+] Đã tìm thấy 4 byte cuối của plaintext: {p_last_4_bytes.decode('ascii','ignore')}")
        
        # Tìm 4 byte đầu của plaintext
        print(f"    [*] Brute-force 4 byte đầu của plaintext...")
        prefix = b'DH{' if i == 0 else b''
        len_to_brute = 4 - len(prefix)
        
        found = False
        for combo in itertools.product(charset, repeat=len_to_brute):
            p_first_4_bytes = prefix + "".join(combo).encode()
            plain_block = p_first_4_bytes + p_last_4_bytes
            
            if real_encrypt(key, plain_block) == cipher_block:
                print(f"    [+] Đã tìm thấy 4 byte đầu: {p_first_4_bytes.decode('ascii','ignore')}")
                flag += plain_block
                found = True
                break
        
        if not found:
            print("    [-] Không tìm thấy 4 byte đầu. Có lỗi.")
            return

    print("\n" + "="*60)
    print(f"  [SUCCESS] FLAG ĐÃ ĐƯỢC TÌM THẤY:")
    print(f"            {flag.rstrip(b'\\x00').decode(errors='ignore')}")
    print("="*60)

if __name__ == '__main__':
    solve()