### **Write-up: EZ-MT Challenge**

**Thể loại:** Crypto / PRNG
**Mô tả:** Server sử dụng `random` của Python để tạo ra một chuỗi số ngẫu nhiên, cung cấp một phần trong số đó và yêu cầu chúng ta dự đoán số tiếp theo.

---

### 1. Phân Tích Ban Đầu

Mã nguồn `EZ-MT.py` cho chúng ta biết luồng hoạt động của server:
1.  **Tạo Seed:** Một seed được tạo ra bằng cách kết hợp thời gian nano giây và một số ngẫu nhiên an toàn: `seed = int(time.time_ns()) ^ secrets.randbits(64)`. Việc này làm cho seed không thể bị brute-force.
2.  **Khởi tạo PRNG:** Server khởi tạo một đối tượng `random.Random(seed)`.
3.  **Tạo Dữ Liệu:**
    *   Nó gọi `r.getrandbits(512)` 39 lần để tạo ra `leaks`.
    *   Nó gọi `r.getrandbits(512)` thêm một lần nữa để tạo ra `ans` (đáp án).
4.  **Tương tác:** Server gửi 39 số trong `leaks` cho client. Client phải gửi lại `ans` để nhận được flag.

### 2. Lỗ Hổng Cốt Lõi: Sự "Yếu Đuối" của Mersenne Twister

Lỗ hổng cốt lõi nằm ở việc server sử dụng `random.Random`, vốn dựa trên thuật toán **Mersenne Twister (MT19937)**. MT19937 là một bộ sinh số giả ngẫu nhiên (PRNG) rất nhanh và có chu kỳ dài, nhưng nó **không an toàn về mặt mật mã học (cryptographically insecure)**.

Tính chất "yếu" quan trọng nhất của nó là:
> Nếu bạn biết được 624 đầu ra 32-bit liên tiếp từ một bộ sinh MT19937, bạn có thể khôi phục lại toàn bộ **trạng thái nội bộ (internal state)** của nó. Một khi đã có trạng thái, bạn có thể dự đoán tất cả các số ngẫu nhiên trong tương lai mà nó sẽ tạo ra.

Trong bài toán này:
*   Mỗi lần gọi `getrandbits(512)`, server đang lấy `512 / 32 = 16` số 32-bit từ trạng thái.
*   Server cung cấp cho chúng ta 39 số 512-bit.
*   Tổng cộng, chúng ta nhận được `39 * 16 = 624` số 32-bit.
*   **Đây chính là chìa khóa!** Chúng ta có chính xác đủ dữ liệu để khôi phục toàn bộ trạng thái.

### 3. Con Đường Tấn Công

Kế hoạch tấn công của chúng ta như sau:
1.  Nhận 39 số 512-bit từ server.
2.  Tách chúng thành 624 số 32-bit.
3.  "Untemper" (đảo ngược các phép toán bitwise) 624 số này để lấy lại trạng thái nội bộ thô (raw state).
4.  Đồng bộ hóa một đối tượng `random` ở phía client với trạng thái đã khôi phục.
5.  Dùng đối tượng `random` đã đồng bộ để dự đoán số 512-bit tiếp theo.
6.  Gửi kết quả và nhận flag.

### 4. Hành Trình Gỡ Lỗi: Sai Lầm Chí Mạng về Thứ Tự Byte (LSB vs. MSB)

Đây là phần quan trọng nhất giải thích tại sao các script ban đầu thất bại. Vấn đề nằm ở **Bước 2: Tách các số 512-bit**.

Ban đầu, chúng ta đã có một giả định sai lầm về cách `getrandbits(k)` hoạt động.
*   **Giả định sai:** `getrandbits(512)` tạo ra 16 số 32-bit (`r1, r2, ..., r16`) và ghép chúng lại theo kiểu `(r1 << 480) | (r2 << 448) | ...`. Theo cách này, `r1` là phần quan trọng nhất (MSB - Most Significant Bit).
*   **Thực tế CPython:** `getrandbits(k)` tạo ra các số 32-bit và xếp chúng vào một mảng byte. Số đầu tiên (`r1`) chiếm 4 byte đầu tiên. Khi chuyển đổi mảng byte này thành số nguyên lớn, 4 byte đầu tiên trở thành phần **ít quan trọng nhất (LSB - Least Significant Bit)**.

Hãy xem một ví dụ đơn giản với 64-bit:
```python
# Giả sử random.Random() tạo ra 2 số: 0xAAAAAAAA và 0xBBBBBBBB
# Giả định sai (MSB-first) sẽ cho ra: 0xAAAAAAAA_BBBBBBBB
# Thực tế (LSB-first) sẽ cho ra:     0xBBBBBBBB_AAAAAAAA 
```
Do sự nhầm lẫn này, thứ tự của các chunk 32-bit bên trong mỗi số 512-bit đã bị đảo lộn, dẫn đến việc khôi phục một trạng thái hoàn toàn sai.

**Cách sửa lỗi:** Khi tách số 512-bit, chúng ta phải lấy các chunk 32-bit từ phải sang trái (LSB-first).

```python
# Code sửa lỗi
tempered_state = []
for num in leaks_512bit:
    temp_num = num
    for _ in range(16):
        chunk = temp_num & 0xFFFFFFFF # Lấy 32 bit cuối cùng (LSB)
        tempered_state.append(chunk)
        temp_num >>= 32              # Dịch phải để lộ 32 bit tiếp theo
```

### 5. Chi Tiết Các Bước Giải Quyết

#### Bước 1: Kết nối và nhận dữ liệu
Sử dụng `pwntools` để dễ dàng kết nối và nhận 39 chuỗi hex.

#### Bước 2: Phân tích dữ liệu (Đúng cách)
Áp dụng logic LSB-first đã nêu ở trên để có được `tempered_state` gồm 624 số 32-bit theo đúng thứ tự.

#### Bước 3: Khôi phục trạng thái với `untemper`
Các số trong `tempered_state` đã qua một quá trình "tôi luyện" (tempering) để cải thiện tính chất thống kê. Chúng ta cần đảo ngược quá trình này. Hàm `untemper` thực hiện việc đảo ngược các phép toán XOR và dịch bit (bit-shift).

```python
# Một hàm untemper mạnh mẽ, đảo ngược từng bước
def untemper(y):
    # Các hằng số của MT19937
    u, s, t, l = 11, 7, 15, 18
    b, c = 0x9D2C5680, 0xEFC60000

    y = invert_right_shift_xor(y, l)
    y = invert_left_shift_xor(y, t, c)
    y = invert_left_shift_xor(y, s, b)
    y = invert_right_shift_xor(y, u)
    return y
```
Sau bước này, chúng ta có `raw_state_list` chứa trạng thái nội bộ thô của PRNG trên server.

#### Bước 4: Đồng bộ hóa PRNG
Chúng ta tạo một đối tượng `random.Random` mới và sử dụng phương thức `setstate()` để nạp trạng thái đã khôi phục vào.
*   `state_tuple`: Là một tuple chứa 624 số 32-bit thô và một số nguyên là chỉ số (index) hiện tại.
*   Vì server đã tạo ra 624 số, nên chỉ số hiện tại đã chạy hết vòng và đang là `624` (hoặc `N`).
*   `state_to_set = (3, tuple(raw_state_list + [N]), None)`

#### Bước 5: Dự đoán và nhận Flag
Sau khi `setstate`, đối tượng `cloned_rng` của chúng ta đã được đồng bộ hóa hoàn toàn. Lần gọi `cloned_rng.getrandbits(512)` tiếp theo sẽ:
1.  Thấy rằng chỉ số `cnt` đã đến cuối (`N=624`).
2.  Tự động gọi hàm `twist()` để tạo ra trạng thái mới.
3.  Bắt đầu tạo ra các số ngẫu nhiên từ trạng thái mới này.

Quá trình này giống hệt những gì xảy ra trên server. Do đó, kết quả trả về sẽ chính là `ans` mà server đang chờ đợi. Chúng ta chỉ cần định dạng nó thành hex và gửi đi.

### 6. Kết Luận và Bài Học Rút Ra

*   **`random` không dành cho mật mã:** Không bao giờ sử dụng `random` cho các mục đích yêu cầu tính bảo mật, như tạo khóa, token, hay salt. Hãy dùng module `secrets`.
*   **Hiểu rõ thư viện:** Đây là bài học lớn nhất từ thử thách này. Việc không hiểu rõ cách `getrandbits` sắp xếp các byte đã dẫn đến nhiều lần thất bại. Luôn kiểm tra mã nguồn hoặc tài liệu của thư viện khi xử lý các vấn đề ở mức độ bit/byte.
*   **Thứ tự Byte (Endianness):** Vấn đề LSB/MSB là một dạng của endianness, một khái niệm quan trọng trong lập trình hệ thống và mật mã.