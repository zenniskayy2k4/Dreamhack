# Easy Assembly (Dreamhack)

## 1. Tóm tắt & Phân tích ban đầu

Thử thách này là một bài reverse engineering kinh điển, được thiết kế với một cái bẫy lớn để đánh lừa người giải. Khi mở file bằng decompiler (như Ghidra/IDA), chúng ta thấy rất nhiều mã C bị lỗi, đặc biệt là các hàm trông có vẻ phức tạp như `decode_b64` và `check_password`. Đây chính là **mồi nhử (red herring)**.

Mô tả của bài đã gợi ý rất rõ: "Nếu bạn có kiến thức về hợp ngữ, đây là một bài toán rất đơn giản... Lấy flag bằng cách chỉ tìm những thông tin bạn cần". Điều này thôi thúc chúng ta bỏ qua mã C bị lỗi và tập trung đọc trực tiếp mã Assembly.

## 2. Phân tích Chi tiết Mã Assembly

Logic thực sự của chương trình nằm trong hàm `entry` và `check_password`.

**a. Luồng thực thi trong `entry`:**
1.  Chương trình yêu cầu một tham số đầu vào từ dòng lệnh, mà chúng ta gọi là `key`.
2.  Nó gọi `strlen` để tính độ dài của `key` này. Kết quả `L = strlen(key)` được lưu vào thanh ghi `EAX`.
3.  Giá trị `L` này được lưu vào một biến toàn cục tên là `len` (`MOV [len], EAX`).
4.  Nó gọi `check_password` để so sánh `key` của người dùng với một chuỗi đã mã hóa sẵn là `enc_flag`.
5.  Nếu `check_password` trả về 0, chương trình in ra thông báo thành công.

**b. Thuật toán trong `check_password`:**
Đây là phần quan trọng nhất:
```assembly
check_password:
    XOR  EDX, EDX              ; Xóa sạch EDX
    MOV  DL, byte ptr [ESI]    ; DL = key[i]
    XOR  DL, byte ptr [len]    ; DL = key[i] ^ (len & 0xFF)
    XOR  DL, byte ptr [EDI]    ; DL = (key[i] ^ (len & 0xFF)) ^ enc_flag[i]
    OR   ECX, EDX              ; Tích lũy kết quả
    ...
    JNZ  check_password        ; Lặp lại L lần
```
Để hàm trả về 0, giá trị `OR` vào `ECX` phải luôn bằng 0. Điều này có nghĩa là kết quả của phép XOR 3 thành phần phải bằng 0 trong mỗi vòng lặp:
`key[i] ^ (len & 0xFF) ^ enc_flag[i] = 0`

Suy ra công thức giải mã:
`key[i] = (len & 0xFF) ^ enc_flag[i]`

## 3. Phát hiện "Cái Bẫy" Tinh Vi - Vòng Phụ thuộc Luẩn quẩn

Đây là điểm mấu chốt khiến bài toán trở nên hóc búa:
1.  `key` của chúng ta xác định giá trị của `len` (thông qua `strlen`).
2.  Giá trị `len` lại xác định byte dùng để XOR, từ đó xác định chính `key`.

Chúng ta có một vòng phụ thuộc: `key` -> `len` -> `key`. Để phá vỡ vòng lặp này, chúng ta phải tìm một giá trị độ dài `L` sao cho nó tự thỏa mãn điều kiện của chính nó. Cụ thể:
> **Tìm một độ dài `L` mà khi dùng `L` để giải mã `L` byte đầu tiên của `enc_flag`, chuỗi `key` kết quả có `strlen(key)` cũng chính bằng `L`.**

Điều này chỉ xảy ra khi và chỉ khi chuỗi `key` được tạo ra **không chứa bất kỳ byte NULL (`\0`) nào**.

## 4. Phương pháp Giải quyết

Chiến lược đúng là duyệt (brute-force) qua tất cả các độ dài `L` có thể (từ 1 đến độ dài tối đa của `enc_flag` là 49). Với mỗi `L`:
1.  Tạo ra một `key` ứng viên bằng công thức `key[i] = (L & 0xFF) ^ enc_flag[i]`.
2.  Kiểm tra xem `key` ứng viên này có chứa byte NULL hay không.
3.  Nếu không chứa, nó là một "lời giải hợp lệ".
4.  Chúng ta thu thập tất cả các lời giải hợp lệ và chọn cái có định dạng `DH{...}`.

## 5. Script

```python
def solve_easy_assembly():
    """
    Hàm giải quyết bài toán "Easy Assembly" của Dreamhack.
    Tìm flag bằng cách brute-force độ dài và kiểm tra điều kiện tự tham chiếu.
    """
    
    # Dữ liệu 49 byte của `enc_flag` được trích xuất từ file binary.
    enc_flag_data = bytearray([
        0x74, 0x78, 0x4b, 0x65, 0x77, 0x48, 0x5c, 0x69, 0x68, 0x7e, 0x5c, 0x79, 
        0x77, 0x62, 0x46, 0x79, 0x77, 0x05, 0x46, 0x54, 0x73, 0x72, 0x59, 0x69, 
        0x68, 0x7e, 0x5c, 0x7e, 0x5a, 0x61, 0x57, 0x6a, 0x77, 0x66, 0x5a, 0x52, 
        0x02, 0x62, 0x5c, 0x79, 0x77, 0x5c, 0x00, 0x7c, 0x57, 0x0d, 0x0d, 0x4d, 
        0x00
    ])

    print("[*] Starting search for the correct key length...")
    
    found_flag = ""

    # Thử mọi độ dài có thể từ 1 đến 49.
    for length_to_test in range(1, len(enc_flag_data) + 1):
        
        # Byte dùng để XOR là byte cuối của giá trị độ dài (L & 0xFF).
        xor_byte = length_to_test & 0xFF
        
        # Lấy đúng "length_to_test" byte đầu tiên để giải mã.
        data_to_decode = enc_flag_data[:length_to_test]
        
        candidate_key = bytearray()
        
        # Tạo key ứng viên. Nếu gặp byte NULL, key này không hợp lệ và bị loại.
        # `all()` là một cách viết gọn gàng để kiểm tra.
        if all((xor_byte ^ encrypted_byte) != 0 for encrypted_byte in data_to_decode):
            # Nếu không có byte NULL, đây là một lời giải hợp lệ.
            candidate_key = bytearray(xor_byte ^ b for b in data_to_decode)
            
            try:
                decoded_string = candidate_key.decode('utf-8')
                # Chúng ta chỉ quan tâm đến lời giải có định dạng flag.
                if decoded_string.startswith("DH{") and decoded_string.endswith("}"):
                    print(f"\n[+] Found the intended flag at length = {length_to_test}!")
                    found_flag = decoded_string
                    break # Tìm thấy flag rồi, không cần tìm nữa.
            except UnicodeDecodeError:
                # Bỏ qua các chuỗi không phải UTF-8
                continue

    if found_flag:
        print(f"\n>>> The flag is: {found_flag}\n")
        
        # Chi tiết thú vị về flag
        b64_part = found_flag.strip("DH{}")
        try:
            import base64
            decoded_message = base64.b64decode(b64_part).decode('utf-8')
            print(f"Fun fact: The content of the flag is a Base64 encoded message:")
            print(f"'{decoded_message}'")
        except:
            pass
    else:
        print("\n[-] Could not find a valid flag. Something is wrong.")

if __name__ == "__main__":
    solve_easy_assembly()

```