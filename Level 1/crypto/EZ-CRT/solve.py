from pwn import *
from math import gcd

def solve():
    # Thay đổi host và port nếu cần
    # conn = remote('localhost', 8888)
    conn = remote('host8.dreamhack.games', 13863)

    # Đọc và parse dữ liệu từ server
    n = int(conn.recvline().decode().strip().split('=')[1], 16)
    e = int(conn.recvline().decode().strip().split('=')[1], 16)
    m_leak = int(conn.recvline().decode().strip().split('=')[1], 16)
    s_good = int(conn.recvline().decode().strip().split('=')[1], 16)
    s_bad = int(conn.recvline().decode().strip().split('=')[1], 16)
    m_target = int(conn.recvline().decode().strip().split('=')[1], 16)

    print(f"[+] Received n = {n}")
    print(f"[+] Received e = {e}")
    print(f"[+] Received s_good = {s_good}")
    print(f"[+] Received s_bad = {s_bad}")
    print(f"[+] Received m_target = {m_target}")

    # --- Bước 1: Phân tích n ---
    # Lỗ hổng nằm ở đây: gcd(s_good - s_bad, n) sẽ cho ra một thừa số của n
    diff = abs(s_good - s_bad)
    p = gcd(diff, n)
    
    # Đảm bảo p là một thừa số hợp lệ
    if p == 1 or p == n:
        print("[-] Failed to factor n.")
        conn.close()
        return

    q = n // p

    # Kiểm tra lại
    assert p * q == n
    print(f"\n[+] Factored n!")
    print(f"[+] p = {p}")
    print(f"[+] q = {q}")

    # --- Bước 2: Tính khóa bí mật d ---
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    print(f"\n[+] Calculated private key d = {d}")

    # --- Bước 3: Tạo chữ ký cho m_target ---
    s_target = pow(m_target, d, n)
    print(f"\n[+] Forged signature for m_target: {s_target}")

    # --- Bước 4: Gửi chữ ký và nhận flag ---
    conn.recvuntil(b'> ')
    payload = f"sig={hex(s_target)[2:]}" # Chuyển sang hex và bỏ '0x'
    conn.sendline(payload.encode())
    
    print("\n[+] Sent signature. Awaiting flag...")
    
    response = conn.recvall(timeout=2)
    print(response.decode())
    
    conn.close()

if __name__ == "__main__":
    solve()