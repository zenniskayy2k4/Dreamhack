import random
from pwn import *

def invert_right_shift_xor(val, shift):
    res = val
    for i in range(32): res = val ^ (res >> shift)
    return res

def invert_left_shift_xor(val, shift, mask):
    res = val
    for i in range(32): res = val ^ ((res << shift) & mask)
    return res

def untemper(y):
    # Các hằng số của MT19937
    u, s, t, l = 11, 7, 15, 18
    b, c = 0x9D2C5680, 0xEFC60000

    y = invert_right_shift_xor(y, l)
    y = invert_left_shift_xor(y, t, c)
    y = invert_left_shift_xor(y, s, b)
    y = invert_right_shift_xor(y, u) # mask d là 0xFFFFFFFF nên không cần
    return y

def solve():
    conn = remote("host8.dreamhack.games", 14952)
    
    # Hằng số
    N = 624 # Kích thước state của MT19937

    leaks_512bit = []
    log.info("Receiving 39 leaks from server...")
    for i in range(39):
        leaks_512bit.append(int(conn.recvline().strip().decode(), 16))
    log.success("Received all leaks.")

    # ======================================================================
    # PHẦN SỬA LỖI QUAN TRỌNG NHẤT
    # Tách các số 512-bit thành 624 số 32-bit theo đúng thứ tự LSB-first
    # ======================================================================
    tempered_state = []
    for num in leaks_512bit:
        # Lấy các chunk 32-bit từ phải sang trái (LSB -> MSB)
        temp_num = num
        for _ in range(16): # 512 / 32 = 16
            chunk = temp_num & 0xFFFFFFFF
            tempered_state.append(chunk)
            temp_num >>= 32
    # ======================================================================

    log.info("Untempering the state vector...")
    raw_state_list = [untemper(y) for y in tempered_state]
    
    # Server đã tạo ra 39 * 16 = 624 số 32-bit.
    # Điều này có nghĩa là state buffer đã đầy và index đang ở cuối (N).
    # Lần gọi tiếp theo sẽ kích hoạt hàm twist().
    state_to_set = (3, tuple(raw_state_list + [N]), None)

    log.info("Cloning server's PRNG state...")
    cloned_rng = random.Random()
    cloned_rng.setstate(state_to_set)

    log.info("Predicting the next 512-bit number...")
    # getrandbits() sẽ tự động gọi twist() và cho ra kết quả đúng
    predicted_ans = cloned_rng.getrandbits(512)
    
    ans_hex = f"{predicted_ans:0128x}"
    log.info(f"Sending predicted answer: {ans_hex[:16]}...")

    conn.recvuntil(b">")
    conn.sendline(ans_hex.encode())
    
    flag = conn.recvline().strip().decode()
    log.success(f"FLAG: {flag}")
    
    conn.close()

if __name__ == "__main__":
    solve()