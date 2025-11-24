Đây là một bài CTF dạng "troll" rất phổ biến, mục đích là để kiểm tra xem bạn có biết cách sử dụng các công cụ lập trình viên (Developer Tools) của trình duyệt hay không. Việc cố gắng click vào nút bằng chuột theo cách thông thường là không thể.

Hãy cùng phân tích code để thấy điểm mấu chốt:

### Phân tích mã nguồn

1.  **Sự kiện `mousemove`:**
    ```javascript
    document.addEventListener("mousemove", (event) => {
      // ... tính toán khoảng cách từ chuột đến nút ...
      const distance = Math.sqrt(...);

      if (distance < 200) { // Nếu chuột cách tâm nút dưới 200px
        moveButtonRandomly(); // Thì di chuyển nút đến vị trí ngẫu nhiên
      }
    });
    ```
    Đây chính là lý do tại sao nút luôn "chạy trốn" bạn. Bất cứ khi nào con trỏ chuột tiến vào một vùng bán kính 200px quanh tâm của nút, sự kiện này sẽ được kích hoạt và di chuyển nút đi chỗ khác.

2.  **Sự kiện `click` (Đây là mục tiêu!):**
    ```javascript
    escapeButton.addEventListener("click", () => {
      window.location.href = "/fnxmtmznpdjakstp";
    });
    ```
    Đây mới là phần quan trọng. Khi bạn **click thành công** vào nút, trang web sẽ chuyển hướng bạn đến một đường dẫn bí mật: `/fnxmtmznpdjakstp`. Đây chính là nơi chứa flag.

### Các cách giải quyết

Có nhiều cách để "click" vào nút này mà không cần dùng chuột dí theo nó. Dưới đây là các cách từ dễ nhất đến phức tạp hơn.

---

### Cách 1: Dùng Console của Trình duyệt (Cách dễ nhất và hiệu quả nhất)

Đây là phương pháp được mong đợi nhất cho loại thử thách này. Bạn có thể ra lệnh cho trình duyệt tự "click" vào nút bằng JavaScript.

1.  Mở trang web của bài CTF.
2.  Nhấn phím `F12` (hoặc chuột phải -> "Kiểm tra" / "Inspect") để mở Developer Tools.
3.  Chuyển sang tab **"Console"**.
4.  Trong Console, gõ lệnh sau rồi nhấn Enter:

    ```javascript
    document.getElementById('escapeButton').click();
    ```

**Giải thích:**
*   `document.getElementById('escapeButton')` sẽ chọn đúng cái nút đang chạy trốn.
*   `.click()` là một hàm JavaScript mô phỏng lại hành động click chuột vào phần tử đó.

Ngay sau khi bạn nhấn Enter, sự kiện `click` sẽ được kích hoạt và trình duyệt sẽ tự động chuyển bạn đến trang `/fnxmtmznpdjakstp` để lấy flag.

---

### Cách 2: Truy cập trực tiếp vào URL chứa Flag

Đôi khi, các bài CTF đơn giản không có cơ chế bảo vệ nào ở phía server. Bạn chỉ cần đọc code, thấy được URL bí mật và truy cập thẳng vào nó.

1.  Bạn đã thấy trong code rằng khi click, nó sẽ chuyển đến `/fnxmtmznpdjakstp`.
2.  Giả sử URL của bài là `http://host8.dreamhack.games:23143/`.
3.  Bạn chỉ cần ghép chúng lại và truy cập vào URL: `http://host8.dreamhack.games:23143/fnxmtmznpdjakstp`.

Cách này cực kỳ đơn giản và nên được thử đầu tiên nếu bạn phát hiện ra một đường dẫn ẩn trong mã nguồn client-side.

---

### Cách 3: Vô hiệu hóa JavaScript hoặc dùng Debugger

Cách này hơi phức tạp hơn nhưng cũng là một kỹ năng hữu ích.

1.  Mở Developer Tools (`F12`).
2.  Chuyển sang tab **"Sources"** (trên Chrome) hoặc **"Debugger"** (trên Firefox).
3.  Tìm đến đoạn code JavaScript của trang (nó nằm ngay trong file HTML).
4.  Đặt một điểm dừng (breakpoint) vào bên trong hàm `moveButtonRandomly()` bằng cách click vào số dòng của nó.
5.  Bây giờ, di chuột của bạn lại gần nút.
6.  Ngay khi nút chuẩn bị di chuyển, mã nguồn sẽ bị **dừng lại** ở breakpoint bạn đã đặt. Lúc này, trang web bị "đóng băng".
7.  Khi trang web đang bị đóng băng, cái nút sẽ đứng im. Bạn có thể thoải mái di chuột đến và click vào nó một cách bình thường.