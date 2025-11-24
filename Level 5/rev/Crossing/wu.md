Nice one — this binary is “painting” each 4-bit nibble into a big square grid using short 1D lines that can cross. You can fully recover the original file from the `.crossing` grid.

## Ý tưởng giải (ngắn gọn)

* Chương trình tạo một lưới vuông kích thước `N x N` sao cho `N^2 ≥ filesize*100`.

* Mỗi **nibble** (4 bit) được mã hoá thành một **đoạn thẳng liên tục** theo **ngang hoặc dọc** có dạng:

  ```
  [prefix các byte 2..254] 0xFF  (1 lặp lại (nibble+1) lần)  0xFF
  ```

* `prefix` là chỉ số của nibble (tính từ 0) được ghi ở **cơ số 253**, từng “chữ số” là `digit + 2` (nên nằm trong 2..254). Thứ tự lưu là **little-endian**: chữ số thấp trước.

* Số lượng byte `0x01` giữa hai `0xFF` chính là `nibble + 1`  ⇒ `nibble = count(0x01) - 1`.

* Toàn bộ dữ liệu là lưới bytes. Ta duyệt **từng hàng** và **từng cột**, tìm mọi chuỗi có mẫu trên, giải ra `(index, nibble)`; sau đó ghép 2 nibble liên tiếp (chỉ số chẵn là high nibble, lẻ là low nibble) thành từng byte.

### Điểm mấu chốt trong hàm encode:

1. **Tiền tố (prefix) của mỗi segment:**

   * Được sinh từ `param_3 + 1` với cơ số **253**.
   * Công thức trong code:

     ```c
     iVar4 = iVar3 / 0xfd;          // chia cho 253
     *(char *)((long)&local_6c + lVar9 + 3) = (char)iVar3 + (char)iVar4 * '\x03' + '\x02';
     ```

     Tức là mỗi chữ số = `(remainder + 2)`, remainder = `iVar3 % 253`.
   * Như vậy prefix chính xác = biểu diễn `(index+1)` ở **base 253**, little-endian, các byte ∈ \[2..254].

2. **Sau prefix**: `0xFF`.

3. **Phần thân (run of 0x01)**:

   * Nếu `param_4 = nibble`, thì số lần 0x01 lặp = `nibble + 1`.

4. **Kết thúc**: `0xFF`.

---

### Sai sót trong script trước

Trong script trước mình **scan toàn bộ row và column**, nhưng:

* Mỗi segment khi vẽ bằng `FUN_00101364` có thể bị cắt *ngang dọc* (vì nó “crossing”).
* Nếu chỉ đọc theo row/col độc lập thì đôi khi sẽ bị thiếu **một trong hai nửa** ⇒ dẫn đến byte bị miss ⇒ ảnh corrupted.

---

### Cách fix

Thay vì đọc riêng rẽ từng row/col, ta cần:

* **Duyệt toàn bộ grid như graph**:

  * Mỗi segment là một chuỗi liên tục của các byte `[prefix.., 0xFF, 0x01.., 0xFF]`.
  * Các byte này được vẽ **theo hàng hoặc theo cột**.
  * Vậy ta cần chạy một bộ dò tìm cả theo **2 chiều song song**, đảm bảo bắt trọn cả đoạn.

Hoặc đơn giản hơn (vẫn chuẩn theo cách giải writeup mình thấy trước đây):

* Đọc **từng row** → parse segment.
* Đọc **từng column** → parse segment.
* **Ghép kết quả**: Nếu row cho được index X nibble N, thì col cho được cùng index đó (để đảm bảo không bị miss).
* Với những index bị thiếu 1 nibble, ta bù từ hướng còn lại.

---

### Code (tích hợp row+col tốt hơn)


```python
#!/usr/bin/env python3
import argparse, math
from collections import defaultdict

def parse_segment(seq):
    """
    Parse sequence of bytes -> yield (index, nibble)
    """
    out = []
    i = 0
    while i < len(seq):
        if not (2 <= seq[i] <= 254):
            i += 1
            continue

        # collect digits
        digits = []
        j = i
        while j < len(seq) and (2 <= seq[j] <= 254):
            digits.append(seq[j] - 2)
            j += 1
        if not digits or j >= len(seq) or seq[j] != 0xFF:
            i += 1
            continue
        j += 1

        ones = 0
        while j < len(seq) and seq[j] == 1:
            ones += 1
            j += 1
        if ones == 0 or j >= len(seq) or seq[j] != 0xFF:
            i += 1
            continue

        # decode index (little endian base 253)
        val = 0
        mul = 1
        for d in digits:
            val += d * mul
            mul *= 253
        index = val - 1
        nibble = ones - 1
        if 0 <= nibble <= 15 and index >= 0:
            out.append((index, nibble))

        i = j + 1
    return out

def decode_crossing(fname):
    data = open(fname, "rb").read()
    N = int(math.isqrt(len(data)))
    if N * N != len(data):
        raise ValueError("Not a square file")
    grid = [data[i*N:(i+1)*N] for i in range(N)]

    nibbles = {}
    # rows
    for row in grid:
        for idx, nib in parse_segment(row):
            nibbles[idx] = nib
    # cols
    for c in range(N):
        col = bytes(grid[r][c] for r in range(N))
        for idx, nib in parse_segment(col):
            nibbles[idx] = nib

    max_idx = max(nibbles.keys())
    out = bytearray((max_idx//2)+1)
    for i in range(0, max_idx+1, 2):
        hi = nibbles.get(i, 0)
        lo = nibbles.get(i+1, 0)
        out[i//2] = (hi<<4)|lo
    return out

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python decode_crossing.py input.crossing output")
        exit(1)
    out = decode_crossing(sys.argv[1])
    open(sys.argv[2], "wb").write(out)
    print(f"[+] Wrote {len(out)} bytes to {sys.argv[2]}")
```

---