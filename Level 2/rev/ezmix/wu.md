Đây là một bài Reverse Engineering (dịch ngược) kinh điển, nơi chương trình hoạt động như một máy ảo (Virtual Machine - VM) đơn giản, thực thi một "bytecode" từ file `program.bin`.

Mục tiêu của chúng ta là hiểu được các "lệnh" (opcodes) này làm gì, sau đó viết một kịch bản để đảo ngược quá trình, biến `output.bin` trở lại thành flag ban đầu.

### Phân tích Decompilation

Hãy cùng phân tích từng hàm để hiểu rõ luồng hoạt động của chương trình.

#### 1. `FUN_001014d8` (Hàm `main`)

*   **Chức năng:** Xử lý file.
*   **Luồng hoạt động:**
    1.  Kiểm tra xem có đủ 2 tham số dòng lệnh không (`Usage: %s [program] [output]`).
    2.  Mở file `program.bin` (tham số đầu tiên) và đọc tối đa `0x400` (1024) bytes vào buffer `local_418`.
    3.  Gọi hàm xử lý chính `FUN_0010136c` với dữ liệu từ `program.bin` và một buffer `local_518` để chứa kết quả.
    4.  Mở file `output.bin` (tham số thứ hai) và ghi kết quả từ `local_518` vào đó.

**Kết luận:** Hàm `main` chỉ là bộ khung đọc/ghi file. Logic cốt lõi nằm ở `FUN_0010136c`.

#### 2. `FUN_0010136c` (Trình thông dịch VM)

*   **Chức năng:** Đọc và thực thi các lệnh từ `program.bin`.
*   **Luồng hoạt động:**
    1.  Hàm này lặp qua dữ liệu từ `program.bin` (`param_1`), xử lý **2 byte mỗi lần** (`local_c = local_c + 2`).
    2.  `bVar2 = *(byte *)(param_1 + local_c)`: Byte đầu tiên được coi là **opcode** (mã lệnh).
    3.  `uVar1 = *(undefined1 *)(param_1 + local_c + 1)`: Byte thứ hai được coi là **operand** (tham số/khóa cho lệnh).
    4.  Chương trình rẽ nhánh dựa trên giá trị của `opcode`:
        *   **`opcode == 4`:**
            *   In ra `Insert your string: `.
            *   Dùng `fgets` để đọc input của người dùng vào `param_3` (buffer kết quả).
            *   Lưu độ dài của chuỗi input vào `local_10`.
            *   **Ý nghĩa:** Đây là lệnh **INPUT**. Nó khởi tạo dữ liệu để các lệnh sau xử lý.
        *   **`opcode == 1`:** Gọi `FUN_00101301` với con trỏ hàm là `FUN_00101289`.
        *   **`opcode == 2`:** Gọi `FUN_00101301` với con trỏ hàm là `FUN_001012a7`.
        *   **`opcode == 3`:** Gọi `FUN_00101301` với con trỏ hàm là `FUN_001012c2`.
        *   Các trường hợp khác: Báo lỗi và thoát.

**Kết luận:** `program.bin` là một chuỗi các cặp `[opcode, operand]`. Chương trình đọc chuỗi input của chúng ta, sau đó áp dụng một loạt các phép biến đổi lên chuỗi đó theo thứ tự được chỉ định trong `program.bin`.

#### 3. `FUN_00101301` (Hàm áp dụng phép biến đổi)

*   **Chức năng:** Áp dụng một phép biến đổi cho từng byte của chuỗi.
*   **Luồng hoạt động:**
    1.  Nhận vào một con trỏ hàm (`param_1`), một khóa (`param_2`), buffer dữ liệu (`param_3`), và độ dài dữ liệu (`param_4`).
    2.  Lặp qua từng byte của buffer dữ liệu.
    3.  Tại mỗi vị trí `i`, nó thực hiện: `data[i] = function(data[i], key)`.

**Kết luận:** Đây là hàm lặp chung để áp dụng các thuật toán mã hóa đơn giản.

#### 4. Các hàm biến đổi (Các "thuật toán")

*   **`FUN_00101289` (cho `opcode == 1`):**
    *   `return (uint)param_2 + (uint)param_1;`
    *   Phép toán: `new_char = old_char + key` (phép cộng theo modulo 256).
    *   **Phép toán ngược:** `old_char = new_char - key`.

*   **`FUN_001012a7` (cho `opcode == 2`):**
    *   `return param_1 ^ param_2;`
    *   Phép toán: `new_char = old_char ^ key` (phép XOR).
    *   **Phép toán ngược:** `old_char = new_char ^ key` (XOR là phép toán tự nghịch đảo).

*   **`FUN_001012c2` (cho `opcode == 3`):**
    *   `return (uint)param_1 << (8 - (param_2 & 7) & 0x1f) | (int)(uint)param_1 >> (param_2 & 7);`
    *   Phép toán này hơi phức tạp. Hãy phân tích nó:
        *   `param_1` là `old_char`, `param_2` là `key`.
        *   Let `shift = key & 7`. Lượng dịch chuyển luôn từ 0 đến 7.
        *   Biểu thức trở thành: `(old_char << (8 - shift)) | (old_char >> shift)`.
        *   Đây chính là định nghĩa của phép **xoay phải bit (Rotate Right - ROR)** trên một giá trị 8-bit.
    *   **Phép toán ngược:** **Xoay trái bit (Rotate Left - ROL)** với cùng một lượng dịch chuyển. `ROL(c, n) = (c << n) | (c >> (8 - n))`.

### Hướng giải quyết

Quá trình mã hóa là: `FLAG -> OP_1 -> OP_2 -> ... -> OP_N -> output.bin`
Để tìm lại flag, chúng ta phải làm ngược lại: `output.bin -> inv(OP_N) -> ... -> inv(OP_2) -> inv(OP_1) -> FLAG`

Các bước cụ thể:
1.  Đọc nội dung của `output.bin` vào một buffer. Đây là dữ liệu khởi đầu của chúng ta.
2.  Đọc nội dung của `program.bin` để lấy danh sách các cặp `[opcode, operand]`.
3.  Lặp qua danh sách các phép toán này **theo thứ tự ngược lại** (từ cuối về đầu).
4.  Với mỗi phép toán, áp dụng phép toán **ngược** của nó lên từng byte trong buffer dữ liệu.
5.  Sau khi áp dụng tất cả các phép toán ngược, buffer dữ liệu sẽ chứa flag ban đầu.

### Script giải

Đây là kịch bản Python để thực hiện các bước trên.

```python
def reverse_add(char_byte, key_byte):
    """Phép toán ngược của opcode 1: trừ"""
    return (char_byte - key_byte) & 0xFF

def reverse_xor(char_byte, key_byte):
    """Phép toán ngược của opcode 2: XOR"""
    return char_byte ^ key_byte

def reverse_ror(char_byte, key_byte):
    """Phép toán ngược của opcode 3: xoay trái (ROL)"""
    shift = key_byte & 7
    if shift == 0:
        return char_byte
    # ROL: (char << shift) | (char >> (8 - shift))
    return ((char_byte << shift) | (char_byte >> (8 - shift))) & 0xFF

# Ánh xạ opcode tới hàm ngược của nó
reverse_operations = {
    1: reverse_add,
    2: reverse_xor,
    3: reverse_ror,
}

# 1. Đọc các file bin
try:
    with open("output.bin", "rb") as f:
        data = bytearray(f.read())

    with open("program.bin", "rb") as f:
        program_code = f.read()
except FileNotFoundError as e:
    print(f"Error: {e}. Make sure 'output.bin' and 'program.bin' are in the same directory.")
    exit(1)

# 2. Phân tích program.bin thành các lệnh
instructions = []
# Lặp qua program_code, mỗi bước 2 byte
for i in range(0, len(program_code), 2):
    opcode = program_code[i]
    operand = program_code[i+1]
    instructions.append((opcode, operand))
    
print(f"[*] Found {len(instructions)} instructions.")

# Lệnh đầu tiên phải là INPUT (opcode 4), chúng ta bỏ qua nó trong quá trình đảo ngược.
# Chúng ta sẽ xử lý các lệnh còn lại theo thứ tự ngược.
# `instructions[1:]` để bỏ qua lệnh INPUT, `reversed()` để đảo ngược.
for opcode, operand in reversed(instructions[1:]):
    if opcode in reverse_operations:
        # Lấy hàm ngược tương ứng
        reverse_func = reverse_operations[opcode]
        # Áp dụng phép toán ngược cho từng byte trong dữ liệu
        for i in range(len(data)):
            data[i] = reverse_func(data[i], operand)
    else:
        print(f"[!] Warning: Unknown opcode {opcode} encountered. Skipping.")

# 5. In ra kết quả
try:
    flag = data.decode('utf-8')
    print("\n[+] Found Flag:")
    print(flag)
except UnicodeDecodeError:
    print("\n[!] Failed to decode the result as UTF-8. Here is the raw byte data:")
    print(data)

```