from cipher import GHOST
from utils import * # GHOST class cần các hàm này

# Hàm này không thay đổi
def inp():
    return input(">> ")

# Hàm này được sửa để không cần file flag.txt
def read_flag():
    print("SUCCESS! Flag would be here.")

# ---- SỬA ĐỔI CHÍNH ----
# Sử dụng seeds và key cố định để debug
# Bạn có thể thay đổi các giá trị này nếu muốn
seeds = b'\xaa' * (2048 // 8) 
print(f"🌱 = {seeds.hex()}")
seeds = int.from_bytes(seeds,"big")

feedback_index = int(inp())
assert 0<=feedback_index<=2048-47
feedback = 2**47+((seeds>>(feedback_index))&(2**47-1))

# Sử dụng key cố định
key = b'\x11\x22\x33\x44\x55\x66'

# -------------------------

# Phần còn lại của logic server giữ nguyên
cipher = GHOST(key,feedback)

while True:
    try:
        c = int(inp())
        if c==1:
            pt = bytes.fromhex(inp())
            ct = cipher.encrypt(pt)
            print(ct.hex())
        if c==2:
            ct = bytes.fromhex(inp())
            pt = cipher.decrypt(ct)
            print(pt.hex())
        if c==3:
            # Dùng plaintext cố định để kiểm tra
            pt = b'test_pt_'
            ct = cipher.encrypt(pt)
            print(ct.hex())
            guess = bytes.fromhex(inp())
            if guess == pt:
                read_flag()
            else:
                print("You failed")
            break
    except (EOFError, ConnectionResetError):
        break