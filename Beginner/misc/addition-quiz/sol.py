from pwn import *

# --- Config ---
HOST = "host8.dreamhack.games"
PORT = 14334

# Connect to the server
p = remote(HOST, PORT)

for i in range(50):
    # Dùng recvuntil để đọc chính xác hơn
    question = p.recvuntil(b'?')
    # log.info(f"Question {i + 1}: {question.decode().strip()}")

    # Bỏ dấu '?' ở cuối
    line = question.decode()[:-1]
    
    # Tách chuỗi bằng dấu '+'
    parts = line.split('+')
    num1 = int(parts[0])
    
    # Tách chuỗi thứ hai bằng dấu '=' để loại bỏ ký tự rác
    num2_str = parts[1].split('=')[0]
    num2 = int(num2_str)
    
    answer = num1 + num2
    p.sendline(str(answer).encode())

log.success("All questions answered successfully!")

# Đọc và bỏ qua mọi thứ cho đến khi gặp chuỗi "Nice!\n"
p.recvuntil(b"Nice!\n")

# Bây giờ, dòng tiếp theo chắc chắn là dòng chứa flag
flag = p.recvline().decode().strip()

# In flag ra cho đẹp bằng log.success của pwntools
log.success(f"FLAG: {flag}")

p.close()

# Flag: DH{0472d70efbc7fee1de726614d534661e0858541bf26ab992a408de549518ccaf}