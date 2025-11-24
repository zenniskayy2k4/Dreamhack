### Giai đoạn 1: Đánh giá ban đầu và Đặt giả thuyết

1.  **Phân tích đề bài:**
    *   **"A strange binary that confuses tools yet still runs."**: Đây là gợi ý vàng. "Confuses tools" (làm các công cụ bối rối) gần như luôn luôn chỉ đến các kỹ thuật anti-analysis (chống phân tích). "Still runs" (vẫn chạy được) cho thấy lỗi không quá nghiêm trọng đến mức HĐH không thể load được file.
    *   **Giả thuyết số 1:** Kỹ thuật anti-analysis phổ biến nhất ở mức độ này là **làm hỏng header của file (ELF Header Corruption)**. Các công cụ như Ghidra/IDA dựa hoàn toàn vào header để xác định kiến trúc (32/64-bit), entry point, các section... Nếu header sai, chúng sẽ không thể phân tích. Trong khi đó, Linux loader có thể "tha thứ" cho một số lỗi nhỏ và vẫn chạy được file.

2.  **Phân tích output của `strings`:**
    *   `/lib64/ld-linux-x86-64.so.2`: Chuỗi này **khẳng định chắc chắn** đây là một file thực thi 64-bit cho Linux. Đây là một bằng chứng quan trọng để đối chiếu sau này.
    *   `ptrace`: Một dấu hiệu rõ ràng của kỹ thuật **chống debug**. Mình ghi nhớ điều này, nhưng đây là vấn đề của giai đoạn sau. Ưu tiên hàng đầu là phải đọc được file đã.
    *   `Flag ->`, `Incorrect Lenght`, `Access granted!`: Luồng hoạt động của một bài flag-checker tiêu chuẩn. Mục tiêu của mình là làm chương trình in ra "Access granted!".

**Kết luận Giai đoạn 1:** Giả thuyết mạnh nhất là file `prob` bị cố tình làm hỏng header để ngăn Ghidra phân tích. Mục tiêu tiếp theo là phải chứng minh và sửa lỗi này.

---

### Giai đoạn 2: Sửa lỗi Header và Vượt qua chướng ngại vật đầu tiên

1.  **Hành động:** Để kiểm tra header, công cụ tiêu chuẩn là `readelf`.
    *   **Lệnh:** `readelf -h prob`
    *   **Phân tích kết quả:** Output của `readelf` đã xác nhận giả thuyết của chúng ta một cách hoàn hảo.
        *   **Mâu thuẫn chí mạng:** `strings` nói file là 64-bit, nhưng `readelf` lại đọc ra `Class: ELF32`. Đây chính là "viên đạn bạc", điểm mấu chốt của vấn đề.
        *   Các giá trị vô lý khác (`Size of this header: 13936`, `Start of program headers: 0`...) chỉ củng cố thêm rằng header đã bị phá nát.

2.  **Lên kế hoạch sửa chữa:**
    *   **Vấn đề:** Header bị sai.
    *   **Giải pháp:** Thay thế nó bằng một header đúng.
    *   **Cách làm:** Kỹ thuật "ghép đầu" (Head Transplant). Tạo ra một file ELF 64-bit mẫu đơn giản, sau đó copy 64 bytes header của nó đè lên file bị hỏng.
    *   **Chi tiết thực hiện:**
        1.  `gcc -no-pie -o template template.c`: Tạo file mẫu. Dùng `-no-pie` để file có cấu trúc đơn giản, dễ tương thích hơn.
        2.  `dd if=template of=prob_fixed bs=1 count=64 conv=notrunc`: Dùng `dd` để copy chính xác 64 bytes đầu tiên. Tùy chọn `conv=notrunc` là tối quan trọng để không làm hỏng phần còn lại của file.

3.  **Đánh giá sau khi sửa:**
    *   Chạy lại `readelf -h prob_fixed`.
    *   **Thành công:** `Class: ELF64` đã đúng! Đây là chiến thắng lớn nhất.
    *   **Vấn đề còn lại:** Các con trỏ trong header (Entry point, Section header offset) giờ là của file `template`, không phải của file `prob`.
    *   **Suy luận:** Mặc dù các con trỏ này sai, nhưng việc `Class` đã đúng có thể đủ để Ghidra nhận diện được kiến trúc (x86-64). Ghidra đủ thông minh để tự tìm các hàm và code ngay cả khi thông tin section bị thiếu. **Vì vậy, bước hợp lý tiếp theo là mở ngay file đã sửa bằng Ghidra.**

**Kết luận Giai đoạn 2:** Chúng ta đã thành công trong việc sửa lỗi nghiêm trọng nhất, giúp các công cụ phân tích tĩnh có thể "đọc" được file.

---

### Giai đoạn 3: Phân tích Logic bên trong

1.  **Hành động:** Mở file `prob_fixed` bằng Ghidra. Kết quả là Ghidra đã decompile thành công mã C.

2.  **"Đọc hiểu" mã C:**
    *   **Nhìn tổng thể:** Thấy có một mảng byte được hardcode (`local_b8`), có `fgets` để nhận input, có `strlen` để kiểm tra độ dài, và có một vòng lặp `for` để so sánh. Đây là cấu trúc kinh điển.
    *   **Loại bỏ nhiễu:** Phần code về `__stack_chk_fail` là stack canary của trình biên dịch. Nó không liên quan đến logic tìm flag. Bỏ qua nó.
    *   **Tập trung vào các bước chính:**
        1.  **Kiểm tra độ dài:** `if (sVar3 == 0x15)`. `0x15` là 21. Vậy flag phải có đúng 21 ký tự.
        2.  **Dữ liệu đích:** Mảng `local_b8` chứa 21 giá trị. Đây chắc chắn là dữ liệu được mã hóa/biến đổi mà input của chúng ta cần phải khớp sau khi xử lý.
        3.  **Phép toán cốt lõi:** `if (local_b8[local_c8] - 0x13 != (uint)local_98[local_c8])`. Đây là trái tim của bài toán.

3.  **Dịch logic sang ngôn ngữ tự nhiên:**
    *   Vòng lặp sẽ kiểm tra từng ký tự.
    *   Chương trình sẽ thoát với thông báo "Acces denied" NẾU `(byte mã hóa thứ i) - 19` **KHÔNG BẰNG** `(byte input của bạn thứ i)`.
    *   Vậy, để chương trình tiếp tục chạy và in ra "Access granted", điều kiện sau phải luôn đúng cho tất cả 21 ký tự:
        **`(byte mã hóa thứ i) - 19` == `(byte input của bạn thứ i)`**

**Kết luận Giai đoạn 3:** Chúng ta đã tìm ra công thức chính xác để tìm flag.

---

### Giai đoạn 4: Đảo ngược thuật toán và tìm Flag

1.  **Hành động:** Viết một script (Python là lựa chọn tốt nhất) để tự động hóa việc giải mã.
2.  **Logic của script:**
    *   Tạo một list chứa tất cả các byte trong mảng `local_b8`.
    *   Lặp qua từng byte trong list này.
    *   Với mỗi byte, thực hiện phép toán ngược: `ký_tự_gốc = byte_mã_hóa - 0x13`.
    *   Chuyển kết quả (là một số) thành ký tự bằng hàm `chr()`.
    *   Nối các ký tự lại với nhau để tạo thành chuỗi flag hoàn chỉnh.
3.  **Kết quả:** Script chạy ra flag `DH{H4ad3rsC0rrupt1on}`.