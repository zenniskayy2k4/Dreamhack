### Write-up CTF: Checkers

#### Giới thiệu

**Checkers** là một thử thách kết hợp giữa **Reverse Engineering (Dịch ngược mã nguồn)** và **Puzzle (Giải đố)**. Mục tiêu của chúng ta là phân tích một file thực thi Linux để hiểu luật chơi của một trò chơi cờ, sau đó tìm ra một chuỗi 46 nước đi chính xác để chiến thắng và nhận được flag.

---

### Bước 1: Phân tích Môi trường (Reconnaissance)

Đây là bước đầu tiên và quan trọng nhất: hiểu được chúng ta đang đối mặt với cái gì.

**1. Phân tích `Dockerfile`:**

*   `FROM ubuntu:24.04`: Môi trường là Ubuntu Linux.
*   `RUN apt-get -y install socat`: `socat` là một công cụ mạng. Lệnh `CMD` ở cuối file cho thấy nó được dùng để mở cổng `5000` và chuyển tiếp mọi kết nối đến chương trình `./checkers`.
    *   **=> Suy luận:** Đây là một thử thách mạng (network service). Chúng ta sẽ tương tác với nó bằng `netcat` hoặc `pwntools`.
*   `RUN useradd -u 1337 ... rootsquare`: Một người dùng tên `rootsquare` được tạo.
*   `COPY checkers .`, `COPY flag.txt .`: File chương trình và file flag được chép vào container.
*   `RUN chown rootsquare:rootsquare /chall/checkers /chall/flag.txt`: Cả chương trình và flag đều thuộc sở hữu của user `rootsquare`.
*   `RUN chmod 0400 /chall/flag.txt`: **Điểm cực kỳ quan trọng!** Quyền của `flag.txt` là `0400` (`r--------`), nghĩa là chỉ có chủ sở hữu (`rootsquare`) mới có quyền đọc.
    *   **=> Suy luận:** Chúng ta không thể tìm cách đọc flag trực tiếp. Cách duy nhất là làm cho chương trình `checkers` (vốn đang chạy với quyền của `rootsquare`) tự đọc và in flag ra cho chúng ta.

---

### Bước 2: Dịch ngược file `checkers` (Reverse Engineering)

Bây giờ chúng ta cần hiểu chương trình hoạt động như thế nào bằng cách đọc mã nguồn đã được dịch ngược.

**1. Hàm `main` (Luồng chính của chương trình):**

*   **Khởi tạo bàn cờ:** `main` tạo ra một bàn cờ 5x5 trong một mảng. Các giá trị hex được gán tương ứng với ký tự ASCII: `0x42`='B', `0x57`='W', `0x2e`='.', `0x2a`='*'.
*   **Vòng lặp trò chơi:** Có một vòng lặp `for` chạy `0x2e` lần (tức 46 lần).
    *   **=> Suy luận:** Trò chơi yêu cầu **chính xác 46 nước đi**.
*   **Nhận input:** Chương trình dùng `scanf("%d %d %d %d", ...)` để đọc 4 số nguyên, tương ứng với `from_row from_col to_row to_col`.
*   **Kiểm tra nước đi:** Nó gọi hàm `FUN_001015ee` để kiểm tra nước đi có hợp lệ không. Nếu không, chương trình `exit(1)`.
    *   **=> Suy luận:** Đây là nguyên nhân gây ra lỗi `EOFError` mà chúng ta gặp liên tục. Khi chúng ta gửi một nước đi sai, chương trình thoát, kết nối bị đóng.
*   **Điều kiện thắng:** Sau 46 nước đi, nó gọi hàm `FUN_001017d1`. Nếu hàm này trả về "true", nó sẽ gọi tiếp `FUN_0010192e`.
*   **Mục tiêu cuối cùng:** `FUN_0010192e` chính là hàm `print_flag`. Nó mở `flag.txt` và in nội dung ra.
    *   **=> Lộ trình chiến thắng:** Thực hiện 46 nước đi hợp lệ -> Đạt được trạng thái bàn cờ thắng -> Chương trình tự in flag.

**2. Hàm `FUN_001017d1` (Điều kiện thắng):**

Hàm này định nghĩa trạng thái thắng. Nó chứa một chuỗi được hardcode:
`"WWW**WWW**WW.BB**BBB**BBB"`
Sau đó, nó so sánh bàn cờ hiện tại của người chơi với chuỗi này. Nếu khớp hoàn toàn, bạn thắng.

**3. Hàm `FUN_001015ee` (Luật di chuyển):**

Đây là hàm quan trọng nhất, định nghĩa "luật chơi". Phân tích kỹ hàm này, ta rút ra các quy tắc:
1.  **Tọa độ hợp lệ:** Tất cả tọa độ (from/to, row/col) phải nằm trong khoảng từ 0 đến 4.
2.  **Quân cờ được di chuyển:** Ô xuất phát phải chứa quân `'W'` hoặc `'B'`. **Không được di chuyển** ô `'.'` hay `'*'`.
3.  **Điểm đến hợp lệ:** Ô đích phải là ô trống `'.'`.
4.  **Hướng di chuyển:** Chương trình định nghĩa 4 vector di chuyển: `(-1,0)` (lên), `(1,0)` (xuống), `(0,1)` (phải), `(0,-1)` (trái).
    *   **=> Suy luận:** Chỉ cho phép di chuyển **theo chiều ngang hoặc chiều dọc**. Không có di chuyển chéo.
5.  **Khoảng cách di chuyển:** Vòng lặp `for (local_3c = 1; local_3c < 3; ...)` cho thấy khoảng cách di chuyển chỉ có thể là **1 hoặc 2 ô**.

---

### Bước 3: Tổng hợp lại bài toán Puzzle

Từ những phân tích trên, bài toán được định nghĩa lại như sau:

**1. Bàn cờ ban đầu (Initial State):**
Dựa trên các lệnh gán trong `main`, đặc biệt `local_38[0xc] = 0x2e` (index 12 là hàng 2, cột 2), ta có:
```
  0 1 2 3 4 (Cột)
0 B B B * *
1 B B B * *
2 W W . B B
3 * * W W W
4 * * W W W
(Hàng)
```

**2. Bàn cờ mục tiêu (Target State):**
Dựa trên chuỗi trong hàm điều kiện thắng:
```
  0 1 2 3 4 (Cột)
0 W W W * *
1 W W W * *
2 W W . B B
3 * * B B B
4 * * B B B
(Hàng)
```

**Nhiệm vụ:** Tìm một chuỗi gồm **chính xác 46 nước đi** để biến Bàn cờ ban đầu thành Bàn cờ mục tiêu, tuân thủ nghiêm ngặt 5 quy tắc di chuyển đã phân tích.

---

### Bước 4: Giải quyết Puzzle - Tại sao tự giải lại khó?

Việc giải bằng tay bài toán này là cực kỳ khó khăn và dễ mắc lỗi vì:
*   Số lượng nước đi lớn (46).
*   Chỉ một sai sót nhỏ trong việc theo dõi vị trí quân cờ sẽ dẫn đến nước đi không hợp lệ.
*   Phải đảm bảo không vi phạm bất kỳ quy tắc nào (ví dụ: cố gắng di chuyển quân `*`, hoặc đi vào ô đã có quân khác).

Đây chính là lý do các chuỗi nước đi "hardcode" liên tục thất bại. Cách tiếp cận đáng tin cậy nhất là để máy tính tự tìm lời giải.

---

### Bước 5: Viết Script tự giải bằng thuật toán BFS

Chúng ta sử dụng thuật toán **BFS (Breadth-First Search - Tìm kiếm theo chiều rộng)**. Đây là lựa chọn lý tưởng vì:
*   Nó khám phá tất cả các nước đi có thể từ trạng thái hiện tại.
*   Nó đảm bảo sẽ tìm thấy con đường ngắn nhất (về số lượng nước đi) để đến được đích.

**Script `solve.py` hoạt động như sau:**
1.  **Phần giải đố (`solve_puzzle`):**
    *   Định nghĩa `initial_state` và `target_state` dưới dạng chuỗi.
    *   Sử dụng một `queue` (hàng đợi) để lưu các trạng thái cần khám phá. Mỗi phần tử trong `queue` bao gồm `(trạng thái bàn cờ hiện tại, con đường đã đi để đến đó)`.
    *   Sử dụng một `set` tên là `visited` để lưu các trạng thái bàn cờ đã gặp, tránh đi vào vòng lặp vô tận.
    *   Vòng lặp chính của BFS sẽ:
        *   Lấy một trạng thái từ `queue`.
        *   Kiểm tra xem nó có phải là trạng thái đích và có đủ 46 bước không.
        *   Nếu không, nó tìm ô trống `.` và thử tất cả các nước đi hợp lệ (di chuyển các quân `W`, `B` gần đó vào ô trống theo luật chơi).
        *   Với mỗi nước đi hợp lệ, nó tạo ra một trạng thái bàn cờ mới, thêm vào `queue` và `visited` để khám phá sau.
    *   Quá trình này tiếp tục cho đến khi tìm thấy một con đường hợp lệ gồm 46 nước đi đến được đích.

2.  **Phần kết nối và gửi lời giải:**
    *   Sau khi hàm `solve_puzzle` trả về chuỗi 46 nước đi chính xác, script sẽ kết nối tới server.
    *   Nó lặp qua danh sách nước đi, gửi từng cái một và chờ phản hồi từ server.
    *   Sau khi gửi xong 46 nước đi, nó chờ thông báo chiến thắng và in ra dòng chứa flag.

### Bước 6: Thực thi và nhận Flag

1.  **Reset môi trường Docker:** Luôn chạy lệnh `docker stop/rm/run` để đảm bảo bạn bắt đầu với một bàn cờ mới.
2.  **Chạy script:** `python solve.py`
3.  Script sẽ tự động tìm lời giải, kết nối, gửi đi, và cuối cùng bạn sẽ nhận được flag.