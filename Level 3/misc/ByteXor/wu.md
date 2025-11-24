# Write-up CTF: ByteXor

## Giới thiệu

ByteXor là một thử thách thuộc thể loại "Leo thang đặc quyền" (Privilege Escalation - pwn/misc). Chúng ta được cung cấp mã nguồn của một chương trình C, một Dockerfile mô tả môi trường, và một server Python. Mục tiêu là đọc nội dung file `/flag`, file này chỉ có người dùng `root` mới có quyền đọc. Thử thách nhấn mạnh rằng chúng ta chỉ có "một cơ hội duy nhất".

#### Bước 1: Phân tích các file được cung cấp

Đây là bước quan trọng nhất. Chúng ta cần hiểu rõ mình có gì trong tay và môi trường hoạt động như thế nào.

**1. `Dockerfile` - Bản thiết kế môi trường**

*   **Hệ điều hành:** `FROM python:3.11-alpine` -> Đây là một phiên bản Linux rất nhẹ, Alpine Linux.
*   **Chương trình `xor`:**
    *   `RUN gcc /app/xor.c -o /app/xor` -> Chương trình C được biên dịch thành file thực thi `/app/xor`.
    *   `chmod u+s /app/xor` -> **Đây là điểm mấu chốt số 1!** Lệnh này bật cờ **SUID** (Set User ID) cho file `/app/xor`. File này thuộc sở hữu của `root` (vì các lệnh `RUN` trong Dockerfile mặc định chạy với quyền `root`). Khi một chương trình có cờ SUID, bất kỳ ai chạy nó cũng sẽ chạy với quyền của chủ sở hữu file. Tóm lại: **Khi chúng ta (user) chạy `/app/xor`, nó sẽ thực thi với quyền `root`!**
*   **File `/flag`:**
    *   `mv /app/flag.txt /flag` -> Flag được đặt tại `/flag`.
    *   `chmod 600 /flag` và `chown root:root /flag` -> Chỉ có `root` mới có thể đọc và ghi vào file này.
*   **Người dùng (`user`):**
    *   `RUN adduser -D -s /bin/sh user` -> Tạo một người dùng tên là `user`.
    *   `RUN echo "user:password" | chpasswd` -> **Đây là điểm mấu chốt số 2!** Mật khẩu của `user` được đặt là `password`. Thông tin này rất có thể sẽ hữu ích.
*   **File `/etc/passwd`:**
    *   `RUN echo "user:x:..." > /etc/passwd` -> Lệnh `>` ghi đè toàn bộ file `/etc/passwd` bằng dòng thông tin của `user`.
    *   `&& echo "root:x:..." >> /etc/passwd` -> Lệnh `>>` nối thêm dòng thông tin của `root` vào cuối file.
    *   => Nội dung file `/etc/passwd` sẽ là:
        ```
        user:x:1000:1000::/home/user:/bin/sh
        root:x:0:0:root:/root:/bin/sh
        ```
        Thứ tự này rất quan trọng.
*   **Server:** `CMD ["python", "app.py"]` -> Khi container khởi động, nó sẽ chạy file `app.py`, mở một reverse shell trên cổng 5000. Chúng ta sẽ kết nối vào đây và bắt đầu với quyền của `user`.

**2. `xor.c` - Công cụ duy nhất của chúng ta**

*   **Chức năng:** Chương trình nhận 3 tham số: `filepath`, `offset`, `xor_value`. Nó sẽ đọc `filepath`, tìm đến byte ở vị trí `offset`, thực hiện phép toán XOR với `xor_value`, và ghi kết quả ra file mới.
*   **Giới hạn:**
    *   `if (stat("/tmp/.xor_lock", ...) == 0)` -> Chương trình kiểm tra sự tồn tại của file `/tmp/.xor_lock`. Nếu file này tồn tại, nó sẽ báo lỗi "This operation has already been performed." và thoát.
    *   `int lock = open("/tmp/.xor_lock", ...)` -> Sau khi chạy xong, nó tạo ra file `/tmp/.xor_lock`.
    *   => **Đây là điểm mấu chốt số 3!** Chúng ta chỉ có thể chạy thành công chương trình này **đúng một lần**.

**Tổng kết phân tích:**
*   Chúng ta là `user` và muốn đọc `/flag`.
*   Chúng ta có một công cụ là `/app/xor` chạy với quyền `root`.
*   Công cụ này cho phép chúng ta thay đổi **một byte duy nhất** tại **một vị trí bất kỳ** trong **một file bất kỳ**.
*   Chúng ta chỉ được dùng công cụ này một lần.
*   Chúng ta biết mật khẩu của `user` là `password`.

#### Bước 2: Lên kế hoạch tấn công

Mục tiêu là trở thành `root`. Với khả năng ghi vào bất kỳ file nào (với quyền `root`), một mục tiêu cổ điển là các file quản lý người dùng. File `/etc/passwd` là lựa chọn hàng đầu.

File này chứa thông tin người dùng, bao gồm User ID (UID). Trong Linux, hệ thống không nhận diện `root` bằng tên, mà bằng **UID = 0**. Bất kỳ người dùng nào có UID là 0 đều có đặc quyền của `root`.

**Kế hoạch:**
1.  Sử dụng `/app/xor` để sửa file `/etc/passwd`.
2.  Mục tiêu là thay đổi UID của `user` từ `1000` thành `0`.
3.  Để làm điều đó, chúng ta chỉ cần thay đổi một byte: đổi ký tự `'1'` trong chuỗi `1000` thành ký tự `'0'`.
4.  Sau khi UID của `user` đã là `0`, chúng ta cần một cách để "kích hoạt" quyền mới này.

#### Bước 3: Tính toán các tham số

Chúng ta cần tìm 2 giá trị cho lệnh `/app/xor <file> <offset> <value>`: `offset` và `value`.

*   **File:** `/etc/passwd`
*   **Offset (Vị trí):**
    Chúng ta cần tìm vị trí của ký tự `'1'` trong file `/etc/passwd`. Nội dung file là:
    ```
    user:x:1000:1000::/home/user:/bin/sh
    root:x:0:0:root:/root:/bin/sh
    ```
    Đếm từ đầu (offset bắt đầu từ 0):
    ```
    u s e r : x : 1 ...
    0 1 2 3 4 5 6 7
    ```
    Vậy ký tự `'1'` nằm ở **offset = 7**.

*   **Value (Giá trị XOR):**
    Chúng ta muốn đổi `'1'` thành `'0'`. Ta cần tìm `V` sao cho: `'1' XOR V = '0'`.
    Trong mã ASCII:
    *   `'1'` có giá trị thập lục phân (hex) là `0x31`.
    *   `'0'` có giá trị thập lục phân (hex) là `0x30`.
    Phương trình trở thành: `0x31 XOR V = 0x30`.
    Sử dụng tính chất của XOR, ta có: `V = 0x31 XOR 0x30`.
    Tính toán nhị phân:
    ```
      0011 0001  (0x31)
    ^ 0011 0000  (0x30)
    -----------
      0000 0001  (0x01)
    ```
    Vậy giá trị XOR cần tìm là `0x01`. Ta sẽ cung cấp nó dưới dạng hex là `01`.

**Lệnh tấn công cuối cùng của chúng ta là:** `/app/xor /etc/passwd 7 01`

#### Bước 4: Thực thi và Leo thang đặc quyền

Bây giờ, chúng ta sẽ thực hiện kế hoạch.

1.  **Kết nối vào server:**
    ```bash
    nc <địa-chỉ-ip> 5000
    ```
    Ta sẽ nhận được một shell với quyền của `user`.

2.  **Chạy lệnh tấn công:**
    Thực hiện lệnh duy nhất và quan trọng nhất mà chúng ta đã chuẩn bị.
    ```sh
    /app/xor /etc/passwd 7 01
    ```
    Lệnh này sẽ chạy âm thầm và không có output nếu thành công. File `/etc/passwd` giờ đã được sửa.

3.  **Kích hoạt quyền Root:**
    Chỉ sửa file thôi là chưa đủ. Tiến trình shell hiện tại của chúng ta vẫn đang chạy với UID cũ là `1000`. Chúng ta cần một cách để buộc hệ thống tạo ra một tiến trình mới và đọc lại thông tin từ file `/etc/passwd`.
    Lệnh `su` (substitute user) được sinh ra để làm việc này. Chúng ta sẽ dùng nó để "đăng nhập lại" với tư cách `user`.
    ```sh
    su user
    ```
    Hệ thống sẽ hỏi mật khẩu. Từ bước phân tích, ta biết mật khẩu là `password`.
    ```
    Password: password
    ```
    Sau khi nhập đúng mật khẩu, `su` sẽ tạo một phiên đăng nhập mới cho `user`. Nó đọc file `/etc/passwd`, thấy rằng UID của `user` giờ đã là `0`, và cấp cho shell mới này quyền của `root`.

4.  **Xác nhận và lấy Flag:**
    Chúng ta đang ở trong một shell mới. Hãy kiểm tra lại danh tính:
    ```sh
    id
    ```
    Output sẽ là `uid=0(user) ...`, xác nhận chúng ta đã là root.
    Bây giờ, việc đọc flag thật đơn giản:
    ```sh
    cat /flag
    ```
    Và flag sẽ hiện ra. Thử thách hoàn thành!

>Toàn bộ quá trình giải trên terminal

```bash
zenniskayy@ZennisKayy:~$ nc host8.dreamhack.games 15976
/bin/sh: can't access tty; job control turned off
/app $ /app/xor /etc/passwd 7 01
/app $ su user
Password: password

id
uid=0(user) gid=1000(user) groups=1000(user)
cat /flag
DH{X0r_u1d_0000_P4sswd}
```