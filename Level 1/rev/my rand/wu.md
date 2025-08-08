# [REV] My rand (Dreamhack)
---
## 1. Mô tả Thử thách

Thử thách yêu cầu chúng ta chơi oẳn tù tì (rock-paper-scissors) với máy. Để nhận được flag, chúng ta phải thắng 100 lần liên tiếp. Nếu hòa hoặc thua dù chỉ một lần, chương trình sẽ ngay lập tức kết thúc.

Gợi ý trong mô tả, "I can’t trust rand()!", cho thấy rằng hệ thống tạo số "ngẫu nhiên" của chương trình có thể dự đoán được, và đây chính là điểm mấu chốt để giải quyết bài toán.

## 2. Phân tích Mã giả (Pseudocode)

Chúng ta được cung cấp mã giả C từ một công cụ decompiler (như Ghidra hoặc IDA).

**a. Hàm logic chính `FUN_001013a5`**

*   Chương trình mở tệp "flag" và đọc nội dung vào một biến cục bộ (`local_78`). Điều này có nghĩa là flag đã nằm sẵn trong bộ nhớ.
*   Yêu cầu người dùng nhập tên (dài từ 4-20 ký tự). Tên và độ dài của nó được lưu lại.
*   Gọi hàm `FUN_001012f7` để "khởi tạo" một mảng dữ liệu toàn cục là `DAT_00104020` bằng cách sử dụng tên người dùng.
*   Bắt đầu vòng lặp trò chơi:
    *   **Điều kiện thoát:** Nếu thua hoặc hòa, chương trình gọi `exit(0)`.
    *   **Điều kiện thắng:** Nếu thắng 100 lần (`local_a8 > 99`), chương trình sẽ in ra flag đã đọc từ tệp.

**b. Hàm khởi tạo `FUN_001012f7` (Hàm "gieo mầm")**

Đây là trái tim của thuật toán. Hàm này xác định trạng thái của bộ tạo số ngẫu nhiên.

```c
void FUN_001012f7(long param_1, int param_2) {
  // param_1: Tên người dùng
  // param_2: Độ dài tên
  
  for (int i = 0; i < 256; i++) {
    // 1. Lấy một ký tự từ tên (lặp lại nếu tên ngắn hơn 256)
    //    và XOR nó với giá trị hiện tại trong mảng trạng thái.
    (&DAT_00104020)[i] = *(byte *)(param_1 + i % param_2) ^ (&DAT_00104020)[i];
    
    // 2. Thực hiện một phép biến đổi trên byte vừa được XOR.
    (&DAT_00104020)[i] = (&DAT_00104020)[i] * 0x10 + ((byte)(&DAT_00104020)[i] >> 4);
  }
}
```

*   **Phép toán 1 (XOR):** Trạng thái được thay đổi dựa trên đầu vào của người dùng (tên).
*   **Phép toán 2 (Biến đổi):** `x * 0x10` tương đương với dịch trái 4 bit (`x << 4`). `x >> 4` là dịch phải 4 bit. Phép toán `(x << 4) | (x >> 4)` chính là **hoán vị 4 bit cao và 4 bit thấp (nibble swap)** của một byte.

**c. Công thức tạo nước đi của máy**

Trong vòng lặp chính, nước đi của máy được tính như sau:

```c
// local_a8: Số vòng đã thắng (từ 0 đến 99)
// local_ac: Độ dài tên người dùng
let index = (local_a8 * local_ac) % 0x100;
let value = (&DAT_00104020)[index];
let computer_move = value % 3;
```
Nước đi của máy hoàn toàn có thể dự đoán được nếu chúng ta biết được nội dung của mảng trạng thái `DAT_00104020`.

## 3. Lỗ hổng & Điểm mấu chốt

1.  **Thuật toán có thể dự đoán:** Nước đi của máy không hề ngẫu nhiên. Nó phụ thuộc hoàn toàn vào (1) tên người dùng, (2) số vòng đã thắng, và (3) trạng thái của mảng `DAT_00104020`.
2.  **Trạng thái ban đầu:** Lỗi sai phổ biến khi tiếp cận bài này là cho rằng mảng `DAT_00104020` ban đầu chứa toàn số 0. Tuy nhiên, vì nó là một biến toàn cục được khởi tạo trong vùng `.data` của file thực thi, nó có một bộ giá trị ban đầu cố định. Phép XOR từ tên người dùng được thực hiện **lên trên các giá trị có sẵn này**.

Việc không biết các giá trị ban đầu này sẽ dẫn đến việc tính toán sai toàn bộ mảng trạng thái, dẫn đến dự đoán sai nước đi của máy và bị ngắt kết nối (`EOFError`).

#### 4. Lộ trình khai thác

1.  **Trích xuất trạng thái ban đầu:** Mở file binary của challenge bằng một công cụ như Ghidra. Tìm đến địa chỉ của biến `DAT_00104020` (là `0x00104020`) và sao chép 256 byte dữ liệu ban đầu của nó.
2.  **Viết kịch bản mô phỏng:** Tạo một kịch bản Python để mô phỏng lại hoàn toàn logic của chương trình.
    *   Lưu 256 byte dữ liệu đã trích xuất vào một biến.
    *   Viết lại hàm `FUN_001012f7` để tính toán mảng trạng thái cuối cùng, dựa trên một tên người dùng tự chọn (ví dụ: "AAAA") và trạng thái ban đầu.
3.  **Tự động hóa trò chơi:** Sử dụng thư viện `pwntools` để tương tác với server.
    *   Kết nối đến server.
    *   Gửi tên đã chọn.
    *   Bắt đầu một vòng lặp 100 lần.
    *   Trong mỗi vòng, tính toán nước đi của máy dựa trên công thức đã phân tích (`state[(round * name_len) % 256] % 3`).
    *   Tính nước đi để thắng: `my_move = (computer_choice + 1) % 3`.
    *   Gửi nước đi chiến thắng đến server.
4.  **Nhận Flag:** Sau khi thắng 100 vòng, server sẽ tự động gửi flag. Đọc và in nó ra.

## 5. Kịch bản khai thác cuối cùng

Đây là kịch bản Python hoàn chỉnh để giải quyết thử thách.

```python
#!/usr/bin/env python3
from pwn import *

# Hàm hoán vị 4 bit cao và 4 bit thấp của một byte
def rotate_nibble(b):
    return ((b << 4) | (b >> 4)) & 0xFF

# Hàm mô phỏng lại logic khởi tạo mảng trạng thái
def generate_state(name, initial_state):
    name_bytes = name.encode('ascii')
    name_len = len(name_bytes)
    state = bytearray(initial_state)

    for i in range(256):
        char_from_name = name_bytes[i % name_len]
        state[i] ^= char_from_name
        state[i] = rotate_nibble(state[i])
    return state

# Dữ liệu ban đầu của mảng DAT_00104020 được trích xuất từ file binary
initial_state_data = (
    b"\xa5\x90\x07\x7f\x0a\x10\xc9\xae\xa3\x86\x24\x16\x02\x97\x28\x51"
    b"\x54\xfb\x08\x1f\x27\x75\x09\xa7\xe2\xd5\xb4\xbb\x1b\xf8\x33\x50"
    b"\x81\x5f\xef\x0e\x6f\x2e\x55\xab\x4e\xe1\xee\x40\x8c\xd3\x9c\xc5"
    b"\x9b\xb7\xdc\x7d\x80\xc2\x45\x99\x30\x89\xdd\x04\x5d\x41\xe7\x21"
    b"\x67\x44\x69\x47\x32\x8b\x2c\xd1\xa0\x5b\xb9\xbd\x84\x78\xcb\x4f"
    b"\xb6\x13\x1d\xea\xbe\x15\x8f\x3a\x18\x98\x3c\xe4\xcc\xac\x4b\xdf"
    b"\x9d\x3d\x6e\x31\x06\x7a\xd8\x95\xb2\x38\x1c\x6b\xa9\x62\x7e\xf7"
    b"\x60\x5c\x36\x0c\xb0\x9a\xca\xd4\x35\x63\x52\xb1\xa4\x3e\x0b\x82"
    b"\x96\x68\xe5\x6a\xd6\xd2\xf4\xaa\xcd\x1a\x7b\x91\xe6\x6c\xda\x94"
    b"\xd0\x56\xf1\xbc\x4a\x2a\x19\x01\xc8\x43\xc4\x1e\x39\x3f\xe9\xfc"
    b"\x4d\xce\x00\xc7\xf5\xeb\xf9\x8e\x93\xc1\x9f\x22\x87\x70\x23\xb8"
    b"\xff\xa1\xd9\xdb\x46\xf0\xc6\x05\x57\x26\xa6\x17\x59\xc0\xfd\x88"
    b"\x53\x5a\x2b\xe8\x2f\x9e\x49\x11\xde\xb3\x4c\x66\xe0\x34\x8a\x0d"
    b"\x20\xad\xfe\x76\x6d\xed\x12\xba\x74\xc3\x64\xbf\x25\xf3\x29\x71"
    b"\xe3\xa2\xb5\x85\xf2\xaf\x58\xfa\x7c\x5e\x65\x61\x14\x92\xa8\x3b"
    b"\x03\x8d\x42\x2d\x72\x77\x83\x79\xd7\x73\xf6\x0f\x48\xec\xcf\x37"
)

# Kết nối đến server
p = remote("host1.dreamhack.games", 14537)

# Chọn tên và tính toán mảng trạng thái cuối cùng
my_name = "AAAA"
name_len = len(my_name)
state_array = generate_state(my_name, initial_state_data)

# Gửi tên
p.recvuntil(b"Enter name(4~20): ")
p.sendline(my_name.encode())

# Vòng lặp 100 lần để thắng
for i in range(100):
    p.recvuntil(b"me: ")

    # Tính toán nước đi của máy và nước đi để thắng
    index = (i * name_len) % 256
    computer_choice = state_array[index] % 3
    my_move = (computer_choice + 1) % 3

    log.info(f"Round {i+1}: Computer picks {computer_choice}, I pick {my_move} to win.")
    
    # Gửi nước đi
    p.sendline(str(my_move).encode())
    p.recvline() # Đọc dòng "You win!"

# Nhận flag
log.success("Won 100 rounds! Receiving flag...")
print(p.recvall().decode(errors='ignore'))

p.close()
```