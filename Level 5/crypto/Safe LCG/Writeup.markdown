# **Write-up: Safe LCG**

**Lĩnh vực**: Mật mã học (Crypto)  
**Từ khóa**: Inversive Congruential Generator, Hệ phương trình tuyến tính, Thuật toán LLL  

---

## **Giới thiệu**

Bài toán cung cấp hai tệp: `chal.py` (mã nguồn) và `output.txt` (kết quả chạy). Trong `chal.py`, ta thấy một bộ sinh số ngẫu nhiên không phải LCG (Linear Congruential Generator) thông thường, mà là một biến thể gọi là **Inversive Congruential Generator (ICG)**. ICG sử dụng nghịch đảo modulo để cập nhật trạng thái theo công thức:

\[ x_{i+1} = (a \cdot x_i^{-1} + b) \mod p \]

- \( p \): Số nguyên tố lớn, 352 bit.
- \( x_i \): Trạng thái nội bộ (352 bit).
- Mỗi lần gọi `next()`, trả về 256 bit thấp nhất của \( x_i \).

**Mục tiêu**: Từ 10 số đầu ra (`outputs`) trong `output.txt`, dự đoán số tiếp theo (thứ 11) để tạo khóa AES và giải mã flag.

---

## **Phân tích mã nguồn**

Dưới đây là mã nguồn từ `chal.py`:

```python
from Crypto.Cipher import AES
from Crypto.Util.number import getPrime, long_to_bytes
from Crypto.Util.Padding import pad
from secrets import randbelow
import hashlib

class SafeLCG:
    def __init__(self):
        self.n = 256
        self.m = 96
        self.p = getPrime(self.n + self.m)  # 352-bit prime
        self.a = randbelow(self.p)
        self.b = randbelow(self.p)
        self.x = randbelow(self.p)

    def next(self):
        self.x = (self.a * pow(self.x, -1, self.p) + self.b) % self.p
        return self.x & ((1 << self.n) - 1)  # Trả về 256 bit thấp nhất

lcg = SafeLCG()

for _ in range(10):
    print(lcg.next())

with open("flag", "rb") as f:
    flag = f.read()

key = hashlib.sha256(long_to_bytes(lcg.next())).digest()
cipher = AES.new(key, AES.MODE_ECB)
ct = cipher.encrypt(pad(flag, 16))

print(f"{lcg.p = }")
print(f"{lcg.a = }")
print(f"{lcg.b = }")
print(f"ct = {ct.hex()}")
```

- **Đầu ra**: 10 số `o_1, o_2, ..., o_10` (256 bit mỗi số), cùng với \( p, a, b \) và bản mã `ct`.
- **Nhiệm vụ**: Dự đoán \( o_{11} \) (256 bit thấp nhất của \( x_{11} \)) để tạo khóa AES và giải mã `ct`.

---

## **Phương pháp giải**

### **1. Thiết lập phương trình**

Gọi:
- \( x_i \): Trạng thái đầy đủ (352 bit).
- \( o_i = x_i \mod 2^{256} \): 256 bit thấp nhất (được cung cấp).
- \( e_i = \frac{x_i - o_i}{2^{256}} \): 96 bit cao, với \( 0 \leq e_i < 2^{96} \).

Ta có:
\[ x_i = o_i + 2^{256} \cdot e_i \]

Công thức ICG:
\[ x_{i+1} = a \cdot x_i^{-1} + b \mod p \]

Thay \( x_i \) và \( x_{i+1} \):
\[ o_{i+1} + 2^{256} \cdot e_{i+1} = a \cdot (o_i + 2^{256} \cdot e_i)^{-1} + b \mod p \]

### **2. Biến đổi thành phương trình tuyến tính**

Để loại bỏ nghịch đảo, nhân cả hai vế với \( x_i \):
\[ (o_{i+1} + 2^{256} \cdot e_{i+1}) \cdot (o_i + 2^{256} \cdot e_i) = a + b \cdot (o_i + 2^{256} \cdot e_i) \mod p \]

Tuy nhiên, cách đơn giản hơn là biến đổi trực tiếp:
\[ (x_{i+1} - b) \cdot x_i = a \mod p \]

Thay \( x_i \) và \( x_{i+1} \):
\[ (o_{i+1} + 2^{256} \cdot e_{i+1} - b) \cdot (o_i + 2^{256} \cdot e_i) = a \mod p \]

Mở rộng:
\[ 2^{512} \cdot e_i \cdot e_{i+1} + 2^{256} \cdot (o_{i+1} - b) \cdot e_i + 2^{256} \cdot o_i \cdot e_{i+1} + (o_{i+1} - b) \cdot o_i = a \mod p \]

Chuyển vế:
\[ 2^{512} \cdot e_i \cdot e_{i+1} + 2^{256} \cdot (o_{i+1} - b) \cdot e_i + 2^{256} \cdot o_i \cdot e_{i+1} + (o_{i+1} - b) \cdot o_i - a = 0 \mod p \]

Đặt \( y_i = e_i \cdot e_{i+1} \) (với \( y_i < 2^{192} \)), ta được:
\[ 2^{512} \cdot y_i + 2^{256} \cdot (o_{i+1} - b) \cdot e_i + 2^{256} \cdot o_i \cdot e_{i+1} + (o_{i+1} - b) \cdot o_i - a = 0 \mod p \]

### **3. Xây dựng hệ phương trình**

Với 10 số \( o_1, o_2, ..., o_{10} \), ta có:
- Biến: \( e_1, e_2, ..., e_{10} \) và \( y_1, y_2, ..., y_9 \).
- 9 phương trình từ các cặp \( (o_i, o_{i+1}) \).

Ví dụ cho \( o_1, o_2 \):
\[ 2^{512} \cdot y_1 + 2^{256} \cdot (o_2 - b) \cdot e_1 + 2^{256} \cdot o_1 \cdot e_2 + (o_2 - b) \cdot o_1 - a = 0 \mod p \]

Vì \( e_i < 2^{96} \) và \( y_i < 2^{192} \) nhỏ hơn nhiều so với \( p \approx 2^{352} \), ta dùng **thuật toán LLL** để tìm nghiệm.

### **4. Xây dựng ma trận LLL**

Ta tạo ma trận để biểu diễn các phương trình và ràng buộc:
- **Hàng**: Đại diện cho \( e_i, y_i \) và các quan hệ modulo \( p \).
- **Cột**: Các biến và hằng số.

Ví dụ cho \( o_1, o_2 \):
- Biến: \( e_1, e_2, y_1 \).
- Ma trận ban đầu:
\[
\begin{bmatrix}
1 & 0 & 0 & 2^{256} (o_2 - b) \\
0 & 1 & 0 & 2^{256} o_1 \\
0 & 0 & 1 & 2^{512} \\
0 & 0 & 0 & p \\
0 & 0 & 0 & (o_2 - b) o_1 - a
\end{bmatrix}
\]

**Điều chỉnh kích thước**:
- Nhân hàng 1, 2 với \( 2^{96} \) (vì \( e_i < 2^{96} \)).
- Nhân cột 4 với \( B = 2^{1024} \) để xử lý modulo \( p \).

Ma trận sau khi điều chỉnh:
\[
\begin{bmatrix}
2^{96} & 0 & 0 & 2^{256} (o_2 - b) \cdot 2^{1024} \\
0 & 2^{96} & 0 & 2^{256} o_1 \cdot 2^{1024} \\
0 & 0 & 1 & 2^{512} \cdot 2^{1024} \\
0 & 0 & 0 & p \cdot 2^{1024} \\
0 & 0 & 0 & ((o_2 - b) o_1 - a) \cdot 2^{1024}
\end{bmatrix}
\]

**Kannan's Embedding và Recenter**:
- Thêm hàng cuối với \( 2^{192} \) (vì \( y_i < 2^{192} \)).
- Trừ \( 2^{191} \) (trung bình của \( 0 \) và \( 2^{192} \)) để tối ưu LLL.

Ma trận cuối:
\[
\begin{bmatrix}
2^{96} & 0 & 0 & 2^{256} (o_2 - b) \cdot 2^{1024} & 0 \\
0 & 2^{96} & 0 & 2^{256} o_1 \cdot 2^{1024} & 0 \\
0 & 0 & 1 & 2^{512} \cdot 2^{1024} & 0 \\
0 & 0 & 0 & p \cdot 2^{1024} & 0 \\
-2^{191} & -2^{191} & -2^{191} & ((o_2 - b) o_1 - a) \cdot 2^{1024} & 2^{192}
\end{bmatrix}
\]

### **5. Mở rộng và áp dụng LLL**

Với 10 output, ma trận sẽ lớn hơn (19 hàng, 20 cột), bao gồm tất cả \( e_1, ..., e_{10} \) và \( y_1, ..., y_9 \). Áp dụng LLL để tìm vector ngắn nhất, từ đó tính \( e_i \), rồi suy ra \( x_{11} \) và \( o_{11} \).

### **6. Giải mã flag**

- Tính \( o_{11} = x_{11} \mod 2^{256} \).
- Tạo khóa: `key = hashlib.sha256(long_to_bytes(o_11)).digest()`.
- Giải mã: `flag = AES.new(key, AES.MODE_ECB).decrypt(ct)`.

---

## **Giải thích đơn giản**

- **ICG là gì?**: Một cách tạo số ngẫu nhiên phức tạp hơn LCG, dùng nghịch đảo modulo để tăng độ khó.
- **LLL làm gì?**: Tìm các số "nhỏ" (\( e_i, y_i \)) trong hệ phương trình lớn modulo \( p \).
- **Recenter là gì?**: Điều chỉnh giá trị để LLL dễ tìm vector ngắn hơn.
- **Kannan's Embedding**: Biến bài toán thành dạng phù hợp cho LLL.

---

## **Kết luận**

Bài toán yêu cầu hiểu ICG và cách dùng LLL để giải hệ phương trình. Từ 10 số đầu ra, ta khôi phục trạng thái và giải mã flag. Hy vọng bạn hiểu rõ hơn sau giải thích này!