### Write-up: [Crypto] EZ-Oracle

#### Tóm tắt

Đây là một thử thách về mã hóa RSA, trong đó server cung cấp các tham số công khai (`n`, `e`) và bản mã của flag (`ciphertext`). Điểm đặc biệt là server còn cung cấp một "padding oracle" cho phép kiểm tra tính hợp lệ của padding PKCS#1 v1.5. Tuy nhiên, chìa khóa để giải quyết bài toán một cách nhanh chóng lại nằm ở điểm yếu cơ bản của hệ thống: kích thước khóa RSA quá nhỏ.

*   **Tên thử thách:** EZ-Oracle
*   **Thể loại:** Cryptography
*   **Kỹ thuật chính:** Phân tích thừa số nguyên tố (Integer Factorization) trên khóa RSA yếu.

---

### Phân tích bài toán

Khi kết nối đến server, chúng ta nhận được ba thông tin quan trọng:
1.  **Modulus `n`:** Một số nguyên lớn.
2.  **Số mũ công khai `e`:** Giá trị chuẩn là 65537.
3.  **Bản mã `ciphertext`:** `flag` sau khi được đệm và mã hóa.

Đồng thời, mã nguồn phía server được cung cấp, tiết lộ các chi tiết sau:
*   **Kích thước khóa RSA:** `RSA_BITS = 256`. Đây là một kích thước **cực kỳ yếu** và là điểm mấu chốt của bài toán.
*   **Padding:** Flag được đệm theo chuẩn PKCS#1 v1.5.
    `m_padded = 0x00 || 0x02 || PS || 0x00 || FLAG`
*   **Oracle:** Server cung cấp một oracle cho phép gửi một bản mã bất kỳ. Oracle sẽ giải mã nó bằng khóa bí mật `d`, kiểm tra cấu trúc padding và trả về:
    *   `OK len={pad_len}`: Nếu padding hợp lệ, đồng thời tiết lộ độ dài của chuỗi đệm `PS`.
    *   `ERR_HEADER`: Nếu bản rõ không bắt đầu bằng `0x00 0x02`.
    *   `ERR_NUL`: Nếu thiếu byte `0x00` ngăn cách.

### Các hướng tấn công

1.  **Tấn công Padding Oracle (Bleichenbacher's Attack):** Sự tồn tại của oracle này là một lời mời gọi cho tấn công Bleichenbacher. Đây là một cuộc tấn công phức tạp, tương tác với oracle hàng ngàn lần để dần dần thu hẹp không gian khả dĩ của bản rõ. Đây có vẻ là một "cái bẫy" (red herring) mà người ra đề đặt ra để đánh lừa người chơi vào một con đường phức tạp.

2.  **Phân tích `n` ra thừa số nguyên tố:** Do kích thước khóa RSA chỉ là 256 bit, modulus `n` hoàn toàn có thể bị phân tích thành các thừa số nguyên tố `p` và `q` trong thời gian ngắn bằng các công cụ hiện đại. Một khi có `p` và `q`, chúng ta có thể tính toán khóa bí mật `d` và giải mã trực tiếp `ciphertext`.

Cái tên "EZ-Oracle" và dòng mô tả "The server is giving me too much information" gợi ý rằng hướng tấn công thứ hai (hướng "EZ") là con đường hiệu quả nhất.

### Lộ trình giải quyết (Exploitation)

#### Bước 1: Thu thập thông tin từ Server

Kết nối đến server và ghi lại các giá trị của `n`, `e`, và `ciphertext`.

Ví dụ:
```
n : 70929787651221546246158895900149623185229139014679923058082980949087340938349
e : 65537
ciphertext : 14889053448640265363340571033204909133286915392546658778020256488418616287923
```

#### Bước 2: Phân tích `n` thành thừa số nguyên tố

Với `n` là một số 256-bit, các công cụ online như FactorDB có thể gặp khó khăn hoặc mất thời gian. Chúng ta sử dụng một công cụ mạnh hơn, chuyên dụng hơn là **YAFU (Yet Another Factoring Utility)**.

Tải YAFU và chạy lệnh sau từ terminal:
```bash
./yafu-x64.exe "factor(70929787651221546246158895900149623185229139014679923058082980949087340938349)"
```

Sau một vài giây, YAFU trả về hai thừa số nguyên tố:
```
p = 325081044546230783692437741577748087939
q = 218191090625508314225420611183577178191
```

#### Bước 3: Tính toán khóa bí mật `d`

Khi đã có `p` và `q`, ta có thể dễ dàng tính `phi(n)` và khóa bí mật `d`:
*   `phi(n) = (p - 1) * (q - 1)`
*   `d = e^(-1) mod phi(n)` (Nghịch đảo modular của `e` trong vành `Z_phi(n)`)

Việc này có thể được thực hiện đơn giản bằng một vài dòng code Python.

#### Bước 4: Giải mã và trích xuất Flag

Dùng khóa bí mật `d` vừa tìm được để giải mã `ciphertext`:
`padded_message_int = pow(ciphertext, d, n)`

Kết quả là một số nguyên lớn. Chuyển nó sang dạng bytes:
`padded_message_bytes = long_to_bytes(padded_message_int, k)`
(với `k = 32` là độ dài của `n` theo byte).

Bản rõ sau khi giải mã sẽ có dạng:
`b'\x00\x02\xff\xff...\xff\x00DH{...}'`

Chúng ta chỉ cần tìm byte `0x00` cuối cùng và lấy phần dữ liệu phía sau nó để thu được flag.

### Script hoàn chỉnh (`solve.py`)

```python
import socket
from Crypto.Util.number import inverse, long_to_bytes

# --- Các hàm tiện ích để giao tiếp với server ---
def recv_until(s, delim):
    buf = b""
    while not buf.endswith(delim):
        buf += s.recv(1)
    return buf

def get_server_params(s):
    n_line = recv_until(s, b'\n').decode().strip()
    e_line = recv_until(s, b'\n').decode().strip()
    c_line = recv_until(s, b'\n').decode().strip()
    
    n = int(n_line.split(' : ')[1])
    e = int(e_line.split(' : ')[1])
    ciphertext = int(c_line.split(' : ')[1])
    
    # Đọc phần còn lại cho đến khi thấy prompt "> "
    recv_until(s, b'> ')
    
    return n, e, ciphertext

HOST, PORT = "host1.dreamhack.games", 18262

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    print(f"[*] Connecting to {HOST}:{PORT}...")
    s.connect((HOST, PORT))
    print("[*] Connected!")

    # BƯỚC 1: Lấy các tham số từ server local
    n, e, ciphertext = get_server_params(s)
    print(f"n = {n}")
    print(f"e = {e}")
    print(f"c = {ciphertext}")

    # BƯỚC 2: Phân tích n ra thừa số nguyên tố dùng yafu
    p_str = input("Enter p: ")
    q_str = input("Enter q: ")
    p = int(p_str)
    q = int(q_str)

    if p * q != n:
        print("[!] ERROR: p * q does not equal n. Please check your factors.")
        exit()
    
    print("[+] Factorization correct!")

    # BƯỚC 3: Tính khóa bí mật d
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    print(f"[*] Private key d calculated.")

    # BƯỚC 4: Giải mã và lấy flag
    padded_message_int = pow(ciphertext, d, n)
    k = (n.bit_length() + 7) // 8
    padded_message_bytes = long_to_bytes(padded_message_int, k)
    
    # Tách flag ra khỏi padding
    separator_index = padded_message_bytes.find(b'\x00', 2)
    flag = padded_message_bytes[separator_index + 1:]
    
    print(f"[*] Found Flag: {flag.decode()}")
    
    # BƯỚC 5: Gửi flag để xác nhận
    print("[*] Submitting the flag to the local server...")
    submit_command = f"submit {flag.hex()}\n".encode()
    s.sendall(submit_command)
    
    response = recv_until(s, b'\n').decode().strip()
    print(f"[*] Server response: {response}")

    if "Correct" in response:
        print("\n[SUCCESS] The script works correctly!")
    else:
        print("\n[FAILURE] Something went wrong.")
```

### Kết luận

Thử thách này là một lời nhắc nhở quan trọng: trong lĩnh vực an ninh mạng, luôn phải kiểm tra các điểm yếu cơ bản trước khi đi sâu vào các kỹ thuật tấn công phức tạp. Việc sử dụng khóa có độ dài không đủ an toàn (như RSA-256) là một lỗi nghiêm trọng, cho phép kẻ tấn công phá vỡ hoàn toàn hệ thống mã hóa mà không cần đến oracle. Cái "Oracle" ở đây chỉ là một sự đánh lạc hướng thông minh.

---