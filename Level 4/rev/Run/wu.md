# Tóm tắt vấn đề

*   **Thử thách:** Bạn được cho một file tên là `flag.enc`. Nhiệm vụ của bạn là tìm ra file gốc (có thể là file `flag.png`) từ file đã bị mã hóa/nén này.
*   **Tác giả WU đã làm:**
    1.  Phân tích file `flag.enc` để tìm ra thuật toán mã hóa (encoding) đã được sử dụng.
    2.  Viết một đoạn script Python để giải mã (decoding) theo thuật toán ngược lại.
    3.  Chạy script và thu được file gốc.
*   **Những gì bạn có:**
    1.  Mô tả về thuật toán **mã hóa** (encoding) trong bài WU.
    2.  Đoạn script Python dùng để **giải mã** (decoding).

Sự nhầm lẫn của bạn có thể đến từ việc đọc mô tả về quá trình *tạo ra file* (`encoding`) trong khi đoạn script lại thực hiện quá trình *khôi phục file* (`decoding`). Chúng là hai quá trình ngược nhau.

### 3. Phân tích thuật toán

Hãy cùng phân tích song song quá trình mã hóa (theo WU) và giải mã (theo script) để thấy sự đối nghịch của chúng.

#### Thuật toán MÃ HÓA (Encoding - Theo WU)

Đây là quá trình biến file gốc (ví dụ `flag.png`) thành `flag.enc`.

1.  **Đọc file gốc dưới dạng một chuỗi bit dài.**
    *   Ví dụ, file của bạn có chuỗi bit là: `00010111...`

2.  **Áp dụng quy tắc nén:**
    *   **Khi gặp số `0`:**
        *   Đếm số lượng số `0` lặp lại liên tiếp. Gọi số lượng này là `c`.
        *   Tìm số bit cần thiết để biểu diễn `c`. Gọi là `L`.
        *   Ghi `(L-1)` số `1` vào file output.
        *   Ghi một số `0` để làm dấu ngăn cách.
        *   Ghi `L` bit biểu diễn của `c` (theo thứ tự bit little-endian, tức là đảo ngược lại).
    *   **Khi gặp số `1`:** Đây là trường hợp đặc biệt của quy tắc trên. Một số `1` tương đương với một chuỗi `0` có độ dài là `0` (`c=0`).
        *   `c = 0`. Biểu diễn nhị phân của 0 là `0` (cần `L=1` bit).
        *   Ghi `(1-1) = 0` số `1`.
        *   Ghi một số `0`.
        *   Ghi `1` bit biểu diễn của `0` là `0`.
        *   => Vậy, một số `1` trong file gốc sẽ được mã hóa thành `00`. (Mô tả trong WU hơi khác một chút nhưng logic của script cho thấy điều này).

#### Thuật toán GIẢI MÃ (Decoding - Theo Script Python)

Đây là quá trình biến `flag.enc` trở lại file gốc. Nó làm chính xác những bước ngược lại.

**Phân tích chi tiết script:**

1.  **Đọc file và chuyển thành chuỗi bit:**
    ```python
    with open("flag.enc", "rb") as f:
        f.read(8) # Bỏ qua 8 bytes đầu, có thể là header của file .enc
        t= f.read()

    # Dòng này rất quan trọng
    b = ''.join(bin(i)[2:].zfill(8)[::-1] for i in t)
    ```
    *   `for i in t`: Lấy từng byte từ file `flag.enc`.
    *   `bin(i)[2:].zfill(8)`: Chuyển byte thành chuỗi 8 bit (ví dụ: `65` -> `01000001`).
    *   `[::-1]`: **Đảo ngược** chuỗi 8 bit đó. (ví dụ: `01000001` -> `10000010`). Đây là bước ngược lại với "little-endian" được nhắc đến trong WU.
    *   Kết quả: `b` là một chuỗi bit dài, là nội dung của file `.enc`.

2.  **Vòng lặp giải mã chính:**
    ```python
    g = '' # Chuỗi bit gốc sẽ được khôi phục vào đây
    i = 0  # Con trỏ vị trí trong chuỗi b
    while i < len(b):
        # --- BƯỚC 1: Đọc tiền tố (prefix) ---
        c = 0
        while b[i + c] == '1': c += 1 # Đếm số lượng số '1' liên tiếp
        # c bây giờ là số lượng số 1, tương ứng với (L-1) trong lúc mã hóa
        
        assert(b[i + c] == '0') # Kiểm tra xem có dấu ngăn cách '0' không
        
        c += 1 # Bây giờ c = (L-1) + 1 = L. Đây là độ dài của số c gốc.

        # --- BƯỚC 2: Đọc dữ liệu (data) ---
        r = ''
        for j in range(c):
            # Đọc c bit tiếp theo và đảo ngược lại để có được số c gốc
            r = b[i + c + j] + r 
        
        # --- BƯỚC 3: Tái tạo chuỗi bit gốc ---
        # int(r, 2) là số lượng số 0 lặp lại
        # Sau mỗi chuỗi 0 là một số 1
        g += '0' * int(r, 2) + '1'
        
        # --- BƯỚC 4: Di chuyển con trỏ ---
        # Bỏ qua phần đã đọc: c bit cho prefix và c bit cho data
        i += c * 2
    ```
    Vòng lặp này đã thực hiện chính xác quy trình ngược lại của thuật toán mã hóa.

3.  **Chuyển chuỗi bit trở lại thành file:**
    ```python
    # Chuyển chuỗi bit g (đang là big-endian) về lại các byte
    r = [int(g[i:i+8][::-1], 2) for i in range(0, len(g), 8)]

    # In ra 16 bytes đầu tiên để kiểm tra
    print(bytes(r)[:16])
    # Output của bạn: b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR'
    # Đây chính là header của một file PNG. Hoàn toàn chính xác!

    # Ghi kết quả ra file 'x'
    with open('x', 'wb') as f:
        f.write(bytes(r))
    ```
    *   `g[i:i+8]`: Lấy ra từng cụm 8 bit.
    *   `[::-1]`: Lại đảo ngược cụm 8 bit đó. Đây là bước ngược lại với thao tác đảo bit ở bước đầu tiên.
    *   `int(..., 2)`: Chuyển chuỗi 8 bit thành một số (byte).
    *   Cuối cùng ghi các byte này ra file `x`. Nếu bạn đổi tên file `x` thành `x.png`, bạn sẽ mở được một file ảnh.

### Kết luận

*   Bài WU mô tả thuật toán **nén/mã hóa** (encoding) một file theo kiểu nén Run-Length Encoding (RLE) ở mức bit.
*   Đoạn script Python bạn có là để **giải nén/giải mã** (decoding), làm ngược lại quá trình trên.
*   Output bạn nhận được `b'\x89PNG...'` chính là header của file PNG, chứng tỏ script đã giải mã thành công file `flag.enc` thành một file ảnh. Thử thách có thể yêu cầu bạn tìm flag (đáp án) bên trong tấm ảnh đó.
*   Ta đổi đuôi của file thực thi `x` thành `x.png` là có được flag trong bức ảnh đó.