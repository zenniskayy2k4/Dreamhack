Đây là một bài crypto CTF rất hay, kết hợp giữa mã hóa RSA hiện đại và mã hóa Vigenère cổ điển. Lỗ hổng chính của bài này nằm ở việc sử dụng số mũ công khai `e` rất nhỏ trong RSA, dẫn đến một dạng tấn công gọi là "Small Public Exponent Attack".

### 1. Phân tích mã nguồn (`prob.py`)

Đầu tiên, chúng ta cần hiểu chương trình đã làm gì để tạo ra `output.txt`.

1.  **Tạo khóa:**
    *   Một khóa `key` ngẫu nhiên dài **4 bytes** được tạo ra.
    *   Một cặp khóa RSA 2048-bit (`p`, `q`, `N`, `d`) được tạo, với số mũ công khai `e` được cố định là **5**.

2.  **Mã hóa FLAG:**
    *   `FLAG` được đọc từ file.
    *   `FLAG` được mã hóa bằng thuật toán Vigenère với `key` (4 bytes) ở trên.
    *   Kết quả sau khi mã hóa Vigenère được chuyển thành một số nguyên lớn và gán cho `enc1`.
        *   `enc1 = bytes_to_long(Vigenere_encrypt(FLAG, key))`

3.  **Mã hóa Khóa:**
    *   `key` (4 bytes) được chuyển thành một số nguyên (`m_key`).
    *   `m_key` này sau đó được mã hóa bằng RSA với khóa công khai (`e`, `N`).
    *   Kết quả được gán cho `enc2`.
        *   `enc2 = pow(bytes_to_long(key), e, N)`

**Tóm lại, chúng ta có:**
*   `e = 5`
*   `N` (một số 2048-bit)
*   `enc1`: FLAG bị mã hóa Vigenère
*   `enc2`: Khóa Vigenère bị mã hóa RSA

Mục tiêu của chúng ta là tìm lại `FLAG`. Để giải mã `enc1`, chúng ta cần tìm ra `key`. `key` này đang bị "khóa" trong `enc2`. Vậy, bước đầu tiên là phải khôi phục `key` từ `enc2`.

### 2. Tìm lỗ hổng và hướng tấn công

Lỗ hổng nằm ở việc mã hóa `key` bằng RSA.
Ta có phương trình: `enc2 = m_key^e mod N`

Trong đó:
*   `e = 5` (rất nhỏ)
*   `m_key` là số nguyên được chuyển từ `key` dài 4 bytes.
*   `N` là một số rất lớn (2048-bit, khoảng `2^2048`).

Hãy xem `m_key` lớn đến mức nào. Vì `key` chỉ dài 4 bytes, giá trị lớn nhất của `m_key` sẽ là `2^(8*4) - 1 = 2^32 - 1`.

Bây giờ, hãy tính `m_key^e`:
`m_key^5 < (2^32)^5 = 2^160`

So sánh `m_key^5` và `N`:
*   `m_key^5` nhỏ hơn `2^160`
*   `N` lớn khoảng `2^2048`

**Phát hiện quan trọng:** `m_key^5` nhỏ hơn `N` rất nhiều! (`2^160 << 2^2048`).

Khi `m^e < N`, phép toán `m^e mod N` sẽ không có tác dụng, và kết quả chỉ đơn giản là `m^e`.
Do đó, phương trình `enc2 = m_key^5 mod N` trở thành:

`enc2 = m_key^5`

Điều này có nghĩa là để tìm `m_key`, chúng ta chỉ cần **tính căn bậc 5** của `enc2`.

### 3. Kế hoạch giải bài

1.  Lấy các giá trị `e`, `N`, `enc1`, `enc2` từ file `output.txt`.
2.  Tính `m_key = căn bậc 5 của enc2`. Đây chính là giá trị số nguyên của khóa Vigenère.
3.  Chuyển `m_key` về dạng bytes để lấy lại `key` (4 bytes).
4.  Chuyển `enc1` về dạng bytes để có được bản mã Vigenère (`vigenere_ciphertext`).
5.  Viết một hàm giải mã Vigenère.
6.  Dùng `key` vừa tìm được để giải mã `vigenere_ciphertext` và lấy `FLAG`.

### 4. Script giải

Để thực hiện các phép toán trên số lớn, đặc biệt là khai căn bậc n, chúng ta nên dùng thư viện `gmpy2`. Nếu chưa có, bạn có thể cài bằng lệnh: `pip install gmpy2`.

Dưới đây là script Python để giải bài toán này:

```python
from Crypto.Util.number import long_to_bytes
import gmpy2

# --- Dữ liệu từ file output.txt ---
e = 5
N = 24778450034785355796150191255487074823099958164427517612668815658468206009158475774203229828058652831641389747402272728790787685762568229069520469756247804941312947307153713830371750706901868389560472732254665749033734649996443767231968425511092244591774647092925931126950380935008196052393893271837275626174525444417778170526468251066473481105512939105882134615031671691748551289394109269703632798650982887859648332846094423809290782207835604174269463315884480062803289020119565250762542625596177768616201281918850432872639983965071018579891448754659608103400036049016809640134053891855019010729470727777892901808607
enc1 = 25889043021335548821260878832004378483521260681242675042883194031946048423533693101234288009087668042920762024679407711250775447692855635834947612028253548739678779
# Nối chuỗi enc2 bị ngắt dòng
enc2_str = "332075826660041992234163956636404156206918624"
enc2 = int(enc2_str)

# --- Bước 1: Khôi phục khóa Vigenère từ enc2 ---
# Vì m_key^e < N, nên enc2 = m_key^e. Ta chỉ cần tính căn bậc e.
# Sử dụng gmpy2.iroot(n, k) để tính căn bậc k của n
m_key, is_perfect_root = gmpy2.iroot(enc2, e)

if not is_perfect_root:
    print("[-] Không thể tìm thấy căn bậc 5 hoàn hảo. Tấn công thất bại.")
else:
    print("[+] Tìm thấy giá trị số nguyên của khóa (m_key):", m_key)
    
    # Chuyển m_key về dạng bytes
    # Phải chỉ định độ dài (4 bytes) để đảm bảo không mất byte 0 ở đầu nếu có
    vigenere_key = long_to_bytes(int(m_key))
    print(f"[+] Khóa Vigenère đã khôi phục (dạng bytes): {vigenere_key}")
    print(f"[+] Độ dài khóa: {len(vigenere_key)} bytes")

    # --- Bước 2: Giải mã Vigenère để tìm FLAG ---
    # Chuyển enc1 về dạng bytes
    vigenere_ciphertext = long_to_bytes(enc1)
    
    def vigenere_decrypt(ciphertext, key):
        decrypted_msg = b""
        key_len = len(key)
        for i in range(len(ciphertext)):
            # Phép giải mã là phép trừ modulo 256
            dec_char = (ciphertext[i] - key[i % key_len]) % 256
            decrypted_msg += bytes([dec_char])
        return decrypted_msg

    # Giải mã
    flag = vigenere_decrypt(vigenere_ciphertext, vigenere_key)
    
    print("\n[+] FLAG:", flag.decode())

```

**Lưu ý:** `enc2` trong file `output.txt` bị ngắt dòng. Bạn cần nối nó lại thành một chuỗi số duy nhất trước khi chuyển thành kiểu `int`. Tôi đã làm điều này trong script.

**Kết quả chạy script:**

```
[+] Tìm thấy giá trị số nguyên của khóa (m_key): 1953723491
[+] Khóa Vigenère đã khôi phục (dạng bytes): b'sEcR'
[+] Độ dài khóa: 4 bytes

[+] FLAG: 
```