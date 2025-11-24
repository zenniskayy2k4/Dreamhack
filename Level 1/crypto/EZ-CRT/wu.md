Đây là một bài crypto khá hay, dựa trên một lỗ hổng kinh điển liên quan đến Chinese Remainder Theorem (CRT) trong RSA, thường được gọi là "Fault Attack". Tên bài "EZ-CRT" đã gợi ý rất rõ về hướng giải quyết.

Hãy cùng phân tích và giải bài này nhé.

### Phân tích bài toán

1.  **Luồng hoạt động của server:**
    *   Server tạo ra một cặp khóa RSA (`n`, `e`, `d`) với `n` có độ dài 1024 bits.
    *   Server gửi cho chúng ta các giá trị: `n`, `e`, `m_leak`, `s_good`, `s_bad`, `m_target`.
    *   Nhiệm vụ của chúng ta là phải tính toán và gửi lại chữ ký (signature) hợp lệ cho `m_target`.
    *   Chữ ký `s` cho `m_target` được coi là hợp lệ nếu `pow(s, e, n) == m_target`.
    *   Để tạo ra chữ ký này, chúng ta cần khóa bí mật `d`, tức là `s = pow(m_target, d, n)`. Mà muốn có `d`, chúng ta phải phân tích được `n` thành các thừa số nguyên tố `p` và `q`.

2.  **Cách các giá trị được tạo ra (trong `chall.py`):**
    *   `n = p * q`
    *   `phi = (p-1)*(q-1)`
    *   `d = inv(e, phi)`
    *   `dp = d % (p-1)` và `dq = d % (q-1)` là các số mũ để ký nhanh hơn bằng CRT.
    *   `m_leak` là một thông điệp ngẫu nhiên.

    Đây là phần quan trọng nhất:
    *   `sp = pow(m_leak, dp, p)`: Chữ ký của `m_leak` theo modulo `p`.
    *   `sq = pow(m_leak, dq, q)`: Chữ ký của `m_leak` theo modulo `q`.
    *   `s_good = crt(sp, sq, p, q, qinv)`: Đây là chữ ký **đúng** của `m_leak`, được tạo bằng cách kết hợp `sp` và `sq` thông qua CRT. Nó thỏa mãn:
        *   `s_good ≡ sp (mod p)`
        *   `s_good ≡ sq (mod q)`
    *   `sq_bad = (sq ^ 1) % q`: Server tạo ra một thành phần chữ ký **sai** bằng cách XOR `sq` với 1.
    *   `s_bad = crt(sp, sq_bad, p, q, qinv)`: Đây là chữ ký **sai** của `m_leak`, được tạo bằng cách kết hợp `sp` (đúng) và `sq_bad` (sai). Nó thỏa mãn:
        *   `s_bad ≡ sp (mod p)`
        *   `s_bad ≡ sq_bad (mod q)`

### Lỗ hổng (Vulnerability)

Lỗ hổng nằm ở chính cách `s_bad` được tạo ra. Chúng ta có hai chữ ký, `s_good` và `s_bad`, và chúng ta biết chúng liên quan đến nhau như thế nào.

Hãy xét hiệu của chúng: `s_good - s_bad`.

1.  **Theo modulo `p`:**
    *   `s_good ≡ sp (mod p)`
    *   `s_bad ≡ sp (mod p)`
    *   Do đó, `s_good - s_bad ≡ sp - sp ≡ 0 (mod p)`.
    *   Điều này có nghĩa là `(s_good - s_bad)` là một bội số của `p`, hay nói cách khác `p` là một ước của `(s_good - s_bad)`.

2.  **Theo modulo `q`:**
    *   `s_good ≡ sq (mod q)`
    *   `s_bad ≡ sq_bad = (sq ^ 1) (mod q)`
    *   Do đó, `s_good - s_bad ≡ sq - (sq ^ 1) (mod q)`.
    *   Vì `sq_bad` khác `sq` (do phép XOR với 1), hiệu này sẽ **không bằng 0** (trừ trường hợp cực kỳ hiếm). Điều này có nghĩa là `(s_good - s_bad)` không chia hết cho `q`.

**Kết luận then chốt:**
*   `p` là một ước của `(s_good - s_bad)`.
*   `p` cũng là một ước của `n` (vì `n = p * q`).

Vậy, `p` là một ước chung của `(s_good - s_bad)` và `n`. Hơn nữa, vì `q` không phải là ước của `(s_good - s_bad)`, nên ước chung lớn nhất của chúng chính là `p`.

> **`gcd(abs(s_good - s_bad), n) = p`**

Khi đã tìm được `p`, chúng ta có thể dễ dàng tìm `q` bằng cách `q = n // p`. Có `p` và `q`, chúng ta có thể phá vỡ RSA và ký bất kỳ thông điệp nào.

Dòng code `if not (1<g<n and n%g==0): return gen_instance(bits,e)` trong `chall.py` chính là để đảm bảo rằng `g = gcd(abs(s_good-s_bad),n)` chắc chắn sẽ là một thừa số của `n`, xác nhận rằng đây chính là con đường giải quyết mà tác giả mong muốn.

### Các bước giải quyết

1.  Kết nối tới server và nhận các giá trị: `n`, `e`, `s_good`, `s_bad`, `m_target`.
2.  Tính `p = gcd(abs(s_good - s_bad), n)`.
3.  Tính `q = n // p`.
4.  Tính `phi = (p - 1) * (q - 1)`.
5.  Tính khóa bí mật `d = pow(e, -1, phi)`.
6.  Tạo chữ ký cho `m_target`: `s_target = pow(m_target, d, n)`.
7.  Gửi `s_target` dưới dạng hex cho server để nhận flag.

### Script giải

```python
from pwn import *
from math import gcd

def solve():
    # Thay đổi host và port nếu cần
    # conn = remote('localhost', 8888)
    conn = remote('host8.dreamhack.games', 13863) # Cập nhật host và port của challenge

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

```