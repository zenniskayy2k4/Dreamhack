from pwn import *
from Crypto.Util.number import long_to_bytes, inverse

# --- Config ---
HOST = "host1.dreamhack.games"
PORT = 13375

p = remote(HOST, PORT)

# 1. Lấy thông tin N, e, FLAG_enc từ server
p.sendlineafter(b"Get info", b"3")
p.recvuntil(b"N: ")
N = int(p.recvline().strip())
p.recvuntil(b"e: ")
e = int(p.recvline().strip())
p.recvuntil(b"FLAG: ")
FLAG_enc = int(p.recvline().strip())

log.info(f"N = {N}")
log.info(f"e = {e}")
log.info(f"FLAG_enc = {FLAG_enc}")

# 2. Chọn một số S và tạo bản mã mới
S = 2
S_enc = pow(S, e, N)
new_ct = (FLAG_enc * S_enc) % N

# 3. Gửi bản mã mới cho oracle giải mã
p.sendlineafter(b"Decrypt", b"2")
p.sendlineafter(b"Input ciphertext (hex): ", hex(new_ct)[2:])

decrypted_new_ct = int(p.recvline().strip())

# 4. Khôi phục lại FLAG gốc
S_inv = inverse(S, N)
FLAG_long = (decrypted_new_ct * S_inv) % N

# 5. Chuyển đổi sang bytes và in ra
flag = long_to_bytes(FLAG_long)
log.success(f"FLAG: {flag.decode()}")

p.close()