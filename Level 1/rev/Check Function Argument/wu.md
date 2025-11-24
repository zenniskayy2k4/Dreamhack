### **Write-up Chi tiết: Giải bài toán "Check Function Argument"**

#### **1. Phân tích Ban đầu (Initial Analysis)**

Bài toán cung cấp một file thực thi Linux (ELF). Mô tả gợi ý rằng flag được truyền dưới dạng tham số cho một hàm, và chúng ta cần dùng gỡ lỗi động (dynamic debugging) để tìm nó.

Khi chạy chương trình, nó chỉ in ra hai dòng chữ:
```
Below function takes the flag as an argument :)
Can you see that?
```
Điều này xác nhận rằng chương trình chạy mà không hiển thị flag. Nhiệm vụ của chúng ta là tìm ra flag ẩn này.

#### **2. Phân tích Tĩnh bằng Ghidra (Static Analysis)**

Mở file trong Ghidra và bắt đầu phân tích.

##### **2.1. Phân tích hàm `main` (`FUN_004015f1`)**

Hàm `main` có cấu trúc rất đơn giản:
```c
undefined8 FUN_004015f1(void) {
  puts("Below function takes the flag as an argument :)");
  FUN_004015e2(DAT_004040d0); // Điểm mấu chốt!
  puts("Can you see that?");
  return 0;
}
```
*   **Phát hiện:** `main` gọi hàm `FUN_004015e2` và truyền vào đó một biến toàn cục `DAT_004040d0`.
*   **Suy luận:** `DAT_004040d0` phải chứa con trỏ trỏ đến chuỗi flag. Tuy nhiên, đây là một biến toàn cục, giá trị của nó không cố định mà có thể được tính toán và gán vào trong quá trình chạy, trước khi `main` được thực thi.

##### **2.2. Tìm nơi `DAT_004040d0` được gán giá trị**

Sử dụng tính năng **Show References To** của Ghidra trên `DAT_004040d0`, ta thấy nó được ghi vào (Write) ở cuối hàm `FUN_00401535`.
```c
void FUN_00401535(...) {
  // ... một loạt các phép biến đổi phức tạp ...
  uVar1 = FUN_00401449(__ptr);
  // ...
  DAT_004040d0 = uVar1; // Gán kết quả cuối cùng vào biến toàn cục
  return;
}
```
*   **Kết luận:** Flag không có sẵn mà được **tạo ra** bởi hàm `FUN_00401535`. Để tìm flag, chúng ta phải mô phỏng lại toàn bộ quá trình tạo flag của hàm này.

##### **2.3. Phân tích hàm tạo Flag (`FUN_00401535`)**

Hàm này nhận một tham số đầu vào (`param_1`) và thực hiện một chuỗi 6 bước biến đổi:

1.  **`FUN_004012b7(data, 0xb)`:** Lặp 70 lần, trừ `0xb` khỏi mỗi byte.
2.  **`FUN_004011f6(data, key)`:** Lặp 70 lần, XOR mỗi byte với một `key` lặp lại.
3.  **`FUN_0040126a(data, 99)`:** Lặp 70 lần, cộng `99` (`0x63`) vào mỗi byte.
4.  **`FUN_00401301(data)`:** Chuyển 70 byte nhị phân thành một chuỗi 140 ký tự hexa.
5.  **`FUN_0040138d(hex_string)`:** Áp dụng phép mã hóa thay thế (substitution cipher) lên chuỗi hexa.
6.  **`FUN_00401449(hex_string)`:** Chuyển chuỗi hexa đã bị thay thế trở lại thành 70 byte nhị phân. Đây chính là buffer chứa flag cuối cùng.

#### **3. Thu thập Dữ liệu cần thiết**

Để mô phỏng lại quá trình trên, chúng ta cần ba mảnh dữ liệu quan trọng từ file binary:

##### **3.1. Dữ liệu đầu vào (`initial_data`)**

*   Sử dụng **Show References To** trên hàm `FUN_00401535`, ta thấy nó được gọi từ hàm `_INIT_1`, một hàm khởi tạo được chạy trước `main`.
    ```c
    void _INIT_1(void) {
      FUN_00401535(&DAT_00404080);
      return;
    }
    ```
*   Hàm này truyền vào địa chỉ của `DAT_00404080`. Đây chính là dữ liệu đầu vào.
*   Đi đến địa chỉ `0x404080` trong Ghidra, ta trích xuất được 70 byte dữ liệu:
    `f4b654aef3807248...8a6d`

##### **3.2. Khóa XOR (`xor_key`)**

*   Hàm `FUN_004011f6` sử dụng key tại địa chỉ `DAT_0040200f`.
*   Đi đến địa chỉ này, ta trích xuất được 9 byte key:
    `73 31 de ad be ef 37 33 10`

##### **3.3. Bảng thay thế (`substitution_table`)**

*   Mở hàm `FUN_0040138d`, ta thấy một bảng thay thế được khởi tạo:
    `local_3a[2] = '3'`, `local_3a[3] = '0'`, ...
*   Ta xây dựng lại bảng này trong Python. Logic thay thế là `new_char = table[hex_digit + 2]`.

#### **4. Viết Script Tái tạo Flag**

Với đầy đủ dữ liệu, chúng ta viết một script Python để mô phỏng lại chính xác 6 bước biến đổi.

```python
# --- BƯỚC 1: Dữ liệu đã trích xuất từ Ghidra (ĐÃ HOÀN CHỈNH) ---

# Dữ liệu ban đầu (param_1) từ DAT_00404080
initial_data_hex = (
    "f4b654aef380724897f0b49904396b44"
    "b44b474a5648bb4f2c48e7ebab51ae33"
    "ad4497e22ca84e2d357cb5b898dea05e"
    "47237e9cbabbeea855153a5a9cc999de"
    "a08144398a6d"
)
initial_data = bytearray.fromhex(initial_data_hex)

# Key XOR tại DAT_0040200f
xor_key = b"\x73\x31\xde\xad\xbe\xef\x37\x33\x10"

# Bảng thay thế từ FUN_0040138d
substitution_table = [
    '', '', '3', '0', '4', '5', '1', 'b', 'c', '2', 'd', '9', '8', '7', 'e', 'f', 'a', '6'
]

# --- BƯỚC 2: Mô phỏng lại các hàm biến đổi ---

def step1_sub(data):
    """Mô phỏng FUN_004012b7(data, 0xb)"""
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = (data[i] - 0xb) & 0xFF
    return result

def step2_xor(data, key):
    """Mô phỏng FUN_004011f6(data, key)"""
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = data[i] ^ key[i % len(key)]
    return result

def step3_add(data):
    """Mô phỏng FUN_0040126a(data, 99)"""
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = (data[i] + 99) & 0xFF
    return result

def step4_to_hex(data):
    """Mô phỏng FUN_00401301(data)"""
    return data.hex()

def step5_substitute(hex_string):
    """Mô phỏng FUN_0040138d(hex_string)"""
    result = ""
    for char in hex_string:
        val = int(char, 16)
        result += substitution_table[val + 2]
    return result

def step6_from_hex(hex_string):
    """Mô phỏng FUN_00401449(hex_string)"""
    # Hàm gốc dùng strtol, nên nó có thể chuyển đổi chuỗi hexa bình thường.
    # Vì vậy, chúng ta chỉ cần dùng hàm fromhex của Python.
    return bytes.fromhex(hex_string)

# --- BƯỚC 3: Chạy toàn bộ quy trình mô phỏng ---

print(f"[*] Dữ liệu ban đầu (70 bytes): {initial_data.hex()}")

# Thực hiện từng bước biến đổi
data = step1_sub(initial_data)
data = step2_xor(data, xor_key)
data = step3_add(data)
hex_str = step4_to_hex(data)
sub_hex_str = step5_substitute(hex_str)
final_bytes = step6_from_hex(sub_hex_str)

# --- BƯỚC 4: In Flag ---
try:
    # Decode kết quả và loại bỏ các byte null ở cuối
    flag = final_bytes.decode('ascii').rstrip('\x00')
    print("\n========================================================")
    print(f"FLAG: {flag}")
    print("========================================================")
except UnicodeDecodeError:
    print("\n[!] Không thể decode kết quả cuối cùng sang ASCII.")
    print(f"Dữ liệu cuối dạng hex: {final_bytes.hex()}")
```

#### **5. Kết quả**

Sau khi chạy script, chúng ta thu được kết quả cuối cùng:
```
FLAG: ooh you figured out me :) Flag is DH{63db030352ca9f9f5e6b8a59c0527bee}
```

#### **6. Tổng kết**

Bài toán này là một ví dụ tuyệt vời về việc kết hợp phân tích tĩnh để hiểu luồng chương trình và scripting để tự động hóa các phép toán phức tạp. Mặc dù mô tả ban đầu hướng người giải đến việc sử dụng debugger, nhưng bằng cách phân tích cặn kẽ với Ghidra, chúng ta có thể tái tạo lại hoàn toàn quá trình tạo flag mà không cần chạy chương trình, qua đó tìm ra đáp án một cách chính xác.