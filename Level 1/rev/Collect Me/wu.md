### **Write-up Chi tiết: Collect Me"**

#### **1. Phân tích Đề bài (Problem Analysis)**

Đề bài cung cấp một file thực thi (binary) và mô tả như sau:
*   Chương trình chứa 928 hàm, được đặt tên theo quy tắc `func_0`, `func_1`, ..., `func_927`.
*   Bên trong mỗi hàm, có một biến cục bộ duy nhất kiểu `char` được gán một giá trị.
*   Nhiệm vụ là phải trích xuất giá trị `char` này từ mỗi hàm theo đúng thứ tự, ghép chúng lại thành một chuỗi lớn.
*   Chuỗi kết quả sẽ chứa flag có định dạng `DH{...}`.

Từ phân tích này, ta có thể rút ra kết luận ngay lập tức:
*   **Không thể làm thủ công:** Việc mở và kiểm tra 928 hàm bằng tay là không khả thi và tốn thời gian.
*   **Cần tự động hóa:** Đây là bài toán yêu cầu sử dụng scripting để tự động hóa quá trình phân tích và trích xuất dữ liệu.

#### **2. Lựa chọn Công cụ (Tool Selection)**

Để giải quyết bài toán, chúng ta cần một công cụ dịch ngược (decompiler/disassembler) có hỗ trợ API cho việc viết script.
*   **Ghidra:** Là lựa chọn lý tưởng vì nó miễn phí, mạnh mẽ và tích hợp sẵn môi trường scripting Jython (Python), rất phù hợp cho nhiệm vụ này.
*   **IDA Pro:** Cũng là một lựa chọn tuyệt vời với scripting IDAPython, tuy nhiên đây là phần mềm trả phí.

Trong bài viết này, chúng ta sẽ sử dụng **Ghidra**.

#### **3. Phân tích Thủ công - Tìm Quy luật (Manual Analysis - Pattern Finding)**

Trước khi có thể viết script tự động, chúng ta phải hiểu được cấu trúc của các hàm và cách tìm ra ký tự cần trích xuất.

1.  Mở file binary trong Ghidra và cho phép nó thực hiện quá trình phân tích tự động.
2.  Sau khi phân tích xong, vào cửa sổ **Symbol Tree**, ta sẽ thấy một danh sách dài các hàm từ `func_0` đến `func_927`.
3.  Ta mở một vài hàm ngẫu nhiên (ví dụ: `func_0`, `func_10`, `func_123`) để quan sát. Trong cửa sổ **Listing**, ta sẽ thấy mã Assembly của chúng có cấu trúc gần như giống hệt nhau:

    ```assembly
    ; func_0
    push    rbp
    mov     rbp, rsp
    mov     byte ptr [rbp - 0x1], 0x44 ; 'D'
    nop
    leave
    ret

    ; func_10
    push    rbp
    mov     rbp, rsp
    mov     byte ptr [rbp - 0x1], 0x73 ; 's'
    nop
    leave
    ret
    ```

4.  **Phát hiện quy luật:**
    *   Tất cả các hàm đều có cấu trúc prologue (`push rbp`, `mov rbp, rsp`) và epilogue (`leave`, `ret`) tiêu chuẩn.
    *   Điểm mấu chốt nằm ở lệnh `mov byte ptr [rbp + offset], value`. Lệnh này có nhiệm vụ gán một giá trị 8-bit (`value`) vào một vị trí trên stack (biến cục bộ).
    *   **`value` chính là mã ASCII của ký tự mà chúng ta cần trích xuất.**
    *   Nhiệm vụ của script sẽ là lặp qua tất cả 928 hàm, tìm chính xác câu lệnh `MOV` này và lấy ra `value` của nó.

#### **4. Lên Kế hoạch Viết Script (Scripting Strategy)**

Dựa trên quy luật đã tìm thấy, chúng ta xây dựng thuật toán cho script như sau:

1.  Khởi tạo một cấu trúc dữ liệu (ví dụ: dictionary) để lưu các ký tự theo đúng thứ tự.
2.  Tạo một vòng lặp `for` chạy từ `i = 0` đến `927`.
3.  Bên trong vòng lặp:
    a. Xây dựng tên hàm cần tìm: `func_<i>`.
    b. Sử dụng API của Ghidra để lấy đối tượng `Function` tương ứng với tên hàm đó.
    c. Lấy tất cả các câu lệnh (instructions) bên trong thân hàm.
    d. Duyệt qua từng câu lệnh, tìm câu lệnh thỏa mãn điều kiện:
        *   Tên lệnh (mnemonic) là `MOV`.
        *   Toán hạng thứ hai (source operand) là một giá trị tức thời (immediate value/scalar).
    e. Khi tìm thấy, trích xuất giá trị số của toán hạng đó.
    f. Chuyển giá trị số thành ký tự bằng hàm `chr()` và lưu vào dictionary với key là `i`.
4.  Sau khi vòng lặp kết thúc, duyệt qua dictionary theo thứ tự key từ 0 đến 927 để ghép các ký tự lại thành chuỗi hoàn chỉnh.
5.  In chuỗi kết quả và tìm flag bên trong nó.

#### **5. Viết Script Ghidra Hoàn Chỉnh**

Dưới đây là script Jython hoàn chỉnh để thực thi kế hoạch trên.

```python
# Ghidra Jython Script to solve the function-based character extraction challenge

from ghidra.program.model.listing import CodeUnit

# Get the current program object that Ghidra is analyzing
currentProgram = getCurrentProgram()
# Get the function manager to find functions by name
functionManager = currentProgram.getFunctionManager()

# Use a dictionary to store characters, keyed by function index to ensure correct order
flag_chars = {}

print("Starting extraction from func_0 to func_927...")

# Loop through all 928 functions
for i in range(928):
    func_name = "func_{}".format(i)
    
    # Get all functions and find the one with the target name
    functions = functionManager.getFunctions(True) # True iterates through all functions
    target_func = None
    for func in functions:
        if func.getName() == func_name:
            target_func = func
            break
            
    if target_func is None:
        print("Could not find function: {}".format(func_name))
        continue

    # Get the instruction list for the function's body
    listing = currentProgram.getListing()
    instructions = listing.getInstructions(target_func.getBody(), True)

    # Iterate through instructions to find the pattern: MOV r/m8, imm8
    for instr in instructions:
        # Check if the instruction is a MOV
        if instr.getMnemonicString() == "MOV":
            # The source operand (index 1) should be an immediate value (scalar)
            op2 = instr.getOpObjects(1)[0]
            
            # A simple way to check if it's a scalar hex value
            if op2.toString().startswith("0x"):
                try:
                    # Get the scalar value and convert it to an integer
                    char_val = int(op2.toString(), 16)
                    # Store the character in our dictionary
                    flag_chars[i] = chr(char_val)
                    # We found our character, no need to check other instructions in this function
                    break 
                except ValueError:
                    # This handles cases where the string isn't a valid number, just in case
                    continue

# Assemble the final string by reading from the dictionary in order
flag_string = ""
for i in range(928):
    if i in flag_chars:
        flag_string += flag_chars[i]

print("\nExtraction complete!")
print("=============================================")
print("Full extracted string:")
print(flag_string)

# Use regex to find and print the flag
import re
flag_match = re.search(r'DH{.*?}', flag_string)
if flag_match:
    print("\nFLAG FOUND:")
    print(flag_match.group(0))
else:
    print("\nFlag not found in the extracted string.")

print("=============================================")

```

#### **6. Hướng dẫn Thực thi**

1.  Trong Ghidra, mở **Script Manager** (`Window -> Script Manager`).
2.  Tạo một script mới bằng cách click vào biểu tượng `Create new script`.
3.  Chọn ngôn ngữ là **Python** và đặt tên cho script (ví dụ: `solve_func.py`).
4.  Dán toàn bộ đoạn mã trên vào trình soạn thảo.
5.  Lưu lại và chạy script bằng cách nhấn nút `Run Script` (biểu tượng play màu xanh).
6.  Kết quả sẽ được in ra trong cửa sổ **Console** của Ghidra.

#### **7. Kết quả và Tổng kết**

Sau khi chạy script, Console sẽ hiển thị một chuỗi dài gồm 928 ký tự. Bên trong chuỗi đó, script sẽ tự động tìm và in ra flag.

**Kết luận:** Bài toán này là một minh chứng xuất sắc cho tầm quan trọng của việc tự động hóa trong lĩnh vực Reverse Engineering. Thay vì thực hiện một công việc đơn giản 928 lần, chúng ta đã tận dụng sức mạnh của scripting để giải quyết vấn đề chỉ trong vài giây. Đây là một kỹ năng nền tảng và cực kỳ hữu ích cho bất kỳ ai muốn đi sâu vào lĩnh vực này.