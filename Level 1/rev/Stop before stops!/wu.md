### Write-up: Stop before stops!

Đây là một bài Reverse Engineering (Dịch ngược) C++, mục tiêu là tìm ra một chuỗi flag ẩn và sử dụng nó làm tham số dòng lệnh để chương trình in ra flag cuối cùng.

#### Bước 1: Phân Tích Tổng Quan (Static Analysis)

Khi phân tích hàm `main` bằng Ghidra, chúng ta có thể thấy chương trình có hai luồng thực thi chính dựa vào số lượng tham số dòng lệnh (`argc`).

1.  **`argc == 3` (Oracle Mode):** Nếu chạy với 2 tham số (ví dụ: `./program a b`), chương trình sẽ vào một chế độ tương tác, cho phép người dùng đoán từng ký tự của flag. Tuy nhiên, chế độ này chứa nhiều cạm bẫy:
    *   **"Stop before stops!"**: Sau một số lần đoán ngẫu nhiên (từ 3 đến 7 lần), chương trình sẽ ghi đè lên chuỗi flag thật bằng một chuỗi ngẫu nhiên.
    *   **Chống bruteforce**: Chương trình kiểm tra 3 ký tự cuối cùng người dùng nhập để ngăn chặn việc đoán theo thứ tự.
    *   **Oracle không hoàn hảo**: Hàm tìm kiếm (`find_in_str`) chỉ trả về vị trí xuất hiện *đầu tiên* của ký tự, gây khó khăn cho việc tìm các ký tự trùng lặp.
    => Kết luận: Tương tác với oracle rất rủi ro và không hiệu quả. Chúng ta cần tìm một cách khác.

2.  **`argc == 2` (Checker Mode):** Nếu chạy với 1 tham số (ví dụ: `./program <chuỗi_đoán>`), chương trình sẽ:
    *   Kiểm tra xem chuỗi đầu vào có độ dài 24 ký tự không.
    *   So sánh chuỗi đầu vào với một biến toàn cục tên là `vlkjbkldsajfksdkfl2[abi:cxx11]`.
    *   Nếu trùng khớp, chương trình sẽ in ra flag cuối cùng được định dạng `DH{...}`.
    => **Mục tiêu chính của chúng ta là tìm ra nội dung của biến `vlkjbkldsajfksdkfl2`.**

#### Bước 2: Tìm Kiếm Nguồn Gốc Của Flag

Giá trị của `vlkjbkldsajfksdkfl2` không được gán trực tiếp. Nó được xây dựng trong các hàm khởi tạo toàn cục trước khi `main` bắt đầu.

-   Bằng cách truy tìm các hàm có tên khó hiểu (`vhlkjhadskufhuli3`, `hilcvfhluh3`, v.v.), chúng ta phát hiện ra rằng flag được tạo ra bằng cách ghép nhiều mảnh chuỗi nhỏ lại với nhau.
-   Các mảnh chuỗi này được lưu trữ dưới dạng các biến tĩnh (static variables) như `oiuvdhoiau3::segment`, `salkdhvkhlklhkjfdhkjd::segment`, v.v.
-   Tuy nhiên, khi kiểm tra các biến này trong Ghidra, chúng chỉ hiển thị dưới dạng các byte 0. Điều này cho thấy các chuỗi này được mã hóa/che giấu và chỉ được giải mã tại thời điểm chạy.

#### Bước 3: Phân Tích Động để Trích Xuất Flag (Dynamic Analysis with GDB)

Cách hiệu quả nhất để lấy các chuỗi đã được giải mã là sử dụng debugger để chương trình tự chạy các hàm khởi tạo, sau đó dừng nó lại và đọc giá trị từ bộ nhớ.

1.  **Đặt Breakpoint:** Chúng ta cần dừng chương trình sau khi các biến toàn cục đã được khởi tạo. Điểm dừng lý tưởng là ngay tại đầu hàm `main`.
    ```bash
    gdb ./stop_before_stops
    (gdb) b main
    (gdb) run
    ```

2.  **Tìm biến `vlkjbkldsajfksdkfl2`:** Trong Ghidra, chúng ta tìm thấy biến `vlkjbkldsajfksdkfl2` được lưu tại một địa chỉ cụ thể.
    *   **Xác định địa chỉ cơ sở:** Trong GDB, dùng lệnh `info proc map` để tìm địa chỉ cơ sở (base address) của chương trình. Ví dụ: `0x555555554000`.
    *   **Tìm offset:** Trong Ghidra, địa chỉ của `vlkjbkldsajfksdkfl2` là `0x10d440`, suy ra offset là `0xd440`.
    *   **Tính địa chỉ tuyệt đối:** `0x555555554000` + `0xd440` = `0x555555561440`.

3.  **Đọc bộ nhớ:** Biến `vlkjbkldsajfksdkfl2` là một đối tượng `std::string`. Trong các hệ thống 64-bit, nếu chuỗi dài, 8 byte đầu tiên của đối tượng này là một con trỏ trỏ đến dữ liệu chuỗi thực tế trên heap.
    *   Đầu tiên, chúng ta đọc 8 byte tại địa chỉ của đối tượng để lấy con trỏ:
        ```gdb
        gef➤ x/gx 0x555555561440
        0x555555561440 <_Z15lkjasvhkjsldhklB5cxx11>: 0x0000555555574340
        ```
    *   Lệnh trên cho chúng ta biết chuỗi thực sự nằm tại địa chỉ `0x0000555555574340`.

4.  **Trích xuất chuỗi:** Bây giờ, chúng ta dùng lệnh `x/s` để in chuỗi tại địa chỉ con trỏ vừa tìm được.
    ```gdb
    gef➤ x/s 0x0000555555574340
    0x555555574340: "why_don'7_y0u_j0in_ro11in6_r3ss????"
    ```
    Vậy, chuỗi bí mật là `why_don'7_y0u_j0in_ro11in6_r3ss????`.

#### Bước 4: Lấy Flag Cuối Cùng

Chúng ta chạy lại chương trình với chuỗi vừa tìm được làm tham số:

```bash
./stop_before_stops "why_don'7_y0u_j0in_ro11in6_r3ss????"
```

Chương trình sẽ xác nhận chuỗi này là đúng và in ra flag.

**Flag:** (Chương trình sẽ in ra flag ở đây, ví dụ: `DH{why_don'7_y0u_j0in_ro11in6_r3ss????}`)