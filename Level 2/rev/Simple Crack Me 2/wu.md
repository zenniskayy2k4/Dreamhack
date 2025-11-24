# **Write-up Chi tiết: Giải bài "Simple Crack Me 2"**

#### **1. Mục tiêu**

Nhiệm vụ của chúng ta là phân tích một file thực thi (binary). Chương trình này nhận một chuỗi đầu vào từ người dùng, thực hiện một loạt các phép biến đổi trên chuỗi đó, và so sánh kết quả với một chuỗi bí mật được lưu sẵn. Nếu trùng khớp, chương trình sẽ in ra "Correct!". Mục tiêu là tìm ra chuỗi đầu vào ban đầu để nhận được thông báo "Correct!".

#### **2. Công cụ sử dụng**

*   **Ghidra:** Một công cụ phân tích và dịch ngược mã nguồn miễn phí, mạnh mẽ từ NSA. Chúng ta sẽ dùng nó để đọc mã giả (pseudo-code) C/C++ từ file binary.

#### **3. Phân tích tĩnh (Static Analysis)**

Chúng ta sẽ bắt đầu bằng cách mở file binary trong Ghidra và phân tích hàm chính `FUN_00401390`.

##### **Bước 3.1: Phân tích luồng hoạt động của hàm chính (`FUN_00401390`)**

Nhìn vào mã giả, ta có thể tóm tắt luồng hoạt động chính như sau:

1.  **Nhập dữ liệu:** `FUN_004010c0` được gọi để nhận input từ người dùng. Đây thực chất là một lời gọi đến hàm `scanf`. Dữ liệu được lưu vào buffer `local_118`.
2.  **Kiểm tra độ dài:** `lVar2 = FUN_004011b6(local_118)` được gọi. Hàm `FUN_004011b6` là một vòng lặp `for` để đếm ký tự cho đến khi gặp ký tự null (`\0`), đây chính là cách triển khai hàm `strlen`.
    *   Sau đó, `if (lVar2 == 0x20)` so sánh độ dài vừa tính được với `0x20` (hệ thập lục phân), tương đương `32` (hệ thập phân).
    *   **=> Kết luận 1: Input của chúng ta phải có độ dài chính xác là 32 ký tự.**
3.  **Biến đổi dữ liệu (Mã hóa):** Nếu độ dài đúng, chương trình thực hiện một chuỗi 7 phép biến đổi lên input của người dùng.
    ```c
    // Input được lưu trong `local_118`
    FUN_004011ef(local_118, &DAT_00402068); // Phép 1
    FUN_00401263(local_118, 0x1f);          // Phép 2
    FUN_004012b0(local_118, 0x5a);          // Phép 3
    FUN_004011ef(local_118, &DAT_0040206d); // Phép 4
    FUN_004012b0(local_118, 0x4d);          // Phép 5
    FUN_00401263(local_118, 0xf3);          // Phép 6
    FUN_004011ef(local_118, &DAT_00402072); // Phép 7
    ```
4.  **So sánh kết quả:** `iVar1 = memcmp(local_118, PTR_DAT_00404050, 0x20);`
    *   Sau 7 phép biến đổi, buffer `local_118` được so sánh với 32 byte dữ liệu tại địa chỉ `PTR_DAT_00404050`.
5.  **In kết quả:** `if (iVar1 == 0)` (nếu `memcmp` trả về 0, tức là hai chuỗi giống hệt nhau) thì in "Correct!".

##### **Bước 3.2: Phân tích các hàm biến đổi**

Bây giờ, chúng ta cần hiểu rõ từng hàm biến đổi làm gì.

*   **`FUN_004011ef(buffer, key)` - Phép XOR lặp khóa:**
    ```c
    // Vòng lặp 32 lần (từ 0 đến 0x1F)
    *(byte *)(buffer + i) = *(byte *)(key + (i % key_length)) ^ *(byte *)(buffer + i);
    ```
    Hàm này thực hiện phép XOR từng byte của `buffer` với từng byte của `key`. Nếu `key` ngắn hơn, nó sẽ được lặp lại.
    *   **Phép toán ngược:** Phép XOR là phép toán ngược của chính nó. Để giải mã, ta chỉ cần **XOR lại với cùng một key**.

*   **`FUN_00401263(buffer, value)` - Phép Cộng hằng số:**
    ```c
    // Vòng lặp 32 lần
    *(char *)(buffer + i) = value + *(char *)(buffer + i);
    ```
    Hàm này cộng hằng số `value` vào mỗi byte của `buffer`.
    *   **Phép toán ngược:** **Trừ đi cùng hằng số `value`**.

*   **`FUN_004012b0(buffer, value)` - Phép Trừ hằng số:**
    ```c
    // Vòng lặp 32 lần
    *(char *)(buffer + i) = *(char *)(buffer + i) - value;
    ```
    Hàm này trừ hằng số `value` khỏi mỗi byte của `buffer`.
    *   **Phép toán ngược:** **Cộng lại cùng hằng số `value`**.

#### **4. Xây dựng Kế hoạch Giải mã**

Chúng ta đã biết rằng `Input` sau khi qua 7 bước biến đổi phải bằng `Chuỗi_mục_tiêu`.
`Transform7(Transform6(...Transform1(Input)...)) == Target_String`

Để tìm `Input`, chúng ta phải đi ngược lại: bắt đầu từ `Target_String` và áp dụng các phép toán ngược theo thứ tự ngược lại.

| Bước mã hóa | Phép toán | Bước giải mã | Phép toán ngược |
| :--- | :--- | :--- | :--- |
| 1 | `XOR(key1)` | 7 | `XOR(key1)` |
| 2 | `ADD(0x1f)` | 6 | `SUB(0x1f)` |
| 3 | `SUB(0x5a)` | 5 | `ADD(0x5a)` |
| 4 | `XOR(key2)` | 4 | `XOR(key2)` |
| 5 | `SUB(0x4d)` | 3 | `ADD(0x4d)` |
| 6 | `ADD(0xf3)` | 2 | `SUB(0xf3)` |
| 7 | `XOR(key3)` | 1 | `XOR(key3)` |

#### **5. Trích xuất Dữ liệu từ Binary**

Đây là bước quan trọng nhất. Dựa vào những gì bạn đã cung cấp, chúng ta có:

1.  **Chuỗi mục tiêu (`PTR_DAT_00404050`):**
    *   Địa chỉ dữ liệu: `0x00402008`
    *   Giá trị (32 bytes): `f8 e0 e6 9e 7f 32 68 31 05 dc a1 aa aa 09 b3 d8 41 f0 36 8c ce c7 ac 66 91 4c 32 ff 05 e0 d9 91`

2.  **Key 1 (`DAT_00402068`):**
    *   Giá trị: `de ad be ef` (`deadbeef`)

3.  **Key 2 (`DAT_0040206d`):**
    *   Giá trị: `ef be ad de` (`efbeadde`)

4.  **Key 3 (`DAT_00402072`):**
    *   Giá trị: `11 33 55 77 99 bb dd`

#### **6. Viết Script Giải mã và Tìm Đáp án**

Bây giờ chúng ta sẽ đưa tất cả thông tin này vào một script Python để tự động hóa quá trình giải mã.

```python
# --- BƯỚC 1: Dữ liệu đã trích xuất từ file binary ---

# Dữ liệu tại PTR_DAT_00404050 (kết quả cuối cùng cần đạt được)
target_bytes = bytearray.fromhex("f8e0e69e7f32683105dca1aaaa09b3d841f0368ccec7ac66914c32ff05e0d991")

# Dữ liệu tại DAT_00402068
key1 = bytes.fromhex("deadbeef")

# Dữ liệu tại DAT_0040206d
key2 = bytes.fromhex("efbeadde")

# Dữ liệu tại DAT_00402072
key3 = bytes.fromhex("1133557799bbdd")

# --- Các hàm chức năng ---

def xor_with_key(data, key):
    """Phép XOR lặp khóa. Phép toán ngược của nó là chính nó."""
    key_len = len(key)
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = data[i] ^ key[i % key_len]
    return result

def add_value(data, value):
    """Cộng một hằng số vào mỗi byte."""
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = (data[i] + value) & 0xFF # & 0xFF để giả lập phép toán trên byte 8-bit
    return result

def sub_value(data, value):
    """Trừ một hằng số khỏi mỗi byte."""
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = (data[i] - value) & 0xFF # & 0xFF để giả lập phép toán trên byte 8-bit
    return result

# --- BƯỚC 2: Thực hiện giải mã theo thứ tự ngược lại ---
print("Bắt đầu quá trình giải mã...\n")
# Ban đầu là chuỗi mục tiêu
current_data = target_bytes
print(f"   [0] Dữ liệu ban đầu: {current_data.hex()}")

# Bước giải mã 1 (Ngược của bước mã hóa 7: XOR)
current_data = xor_with_key(current_data, key3)
print(f"-> [1] Sau khi XOR với key3: {current_data.hex()}")

# Bước giải mã 2 (Ngược của bước mã hóa 6: ADD 0xf3 -> SUB 0xf3)
current_data = sub_value(current_data, 0xf3)
print(f"-> [2] Sau khi trừ 0xf3:     {current_data.hex()}")

# Bước giải mã 3 (Ngược của bước mã hóa 5: SUB 0x4d -> ADD 0x4d)
current_data = add_value(current_data, 0x4d)
print(f"-> [3] Sau khi cộng 0x4d:      {current_data.hex()}")

# Bước giải mã 4 (Ngược của bước mã hóa 4: XOR)
current_data = xor_with_key(current_data, key2)
print(f"-> [4] Sau khi XOR với key2: {current_data.hex()}")

# Bước giải mã 5 (Ngược của bước mã hóa 3: SUB 0x5a -> ADD 0x5a)
current_data = add_value(current_data, 0x5a)
print(f"-> [5] Sau khi cộng 0x5a:      {current_data.hex()}")

# Bước giải mã 6 (Ngược của bước mã hóa 2: ADD 0x1f -> SUB 0x1f)
current_data = sub_value(current_data, 0x1f)
print(f"-> [6] Sau khi trừ 0x1f:       {current_data.hex()}")

# Bước giải mã 7 (Ngược của bước mã hóa 1: XOR)
final_bytes = xor_with_key(current_data, key1)
print(f"-> [7] Sau khi XOR với key1: {final_bytes.hex()}")

# --- BƯỚC 3: In kết quả cuối cùng ---
try:
    final_input = final_bytes.decode('ascii')
    print("\n=============================================")
    print(f"INPUT DUNG LA: {final_input}")
    print(f"FLAG: DH{{{final_input}}}")
    print("=============================================")
except UnicodeDecodeError:
    print("\n[!] Khong the decode ket qua sang ASCII. Co the co loi trong du lieu ban dau.")
    print(f"Ket qua dang byte: {final_bytes}")
```

#### **7. Kết quả và Tổng kết**

Khi chạy script trên, output cuối cùng sẽ là:

```
CORRECT INPUT: 9ce745c0d5faaf29b7aecd1a4a72bc86
FLAG: DH{9ce745c0d5faaf29b7aecd1a4a72bc86}
```

**Tổng kết:** Bài toán này là một ví dụ điển hình về "Crack Me" dựa trên các phép biến đổi thuật toán. Chìa khóa để giải quyết là:
1.  Phân tích kỹ lưỡng luồng chương trình để hiểu logic tổng thể.
2.  Đi sâu vào từng hàm chức năng để xác định chính xác phép toán được thực hiện.
3.  Tìm ra phép toán ngược cho mỗi bước.
4.  Lấy dữ liệu tĩnh (khóa, chuỗi mục tiêu) từ file binary.
5.  Áp dụng các phép toán ngược theo **thứ tự ngược lại** để khôi phục input ban đầu.