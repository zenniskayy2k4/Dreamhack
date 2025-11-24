Dạng CTF **Web + Misc** liên quan đến **Invisible Unicode / Zero-width character injection**

---

# Write-up: Invisible Unicode / Zero-width Character Challenge

## 1. Mô tả đề bài

Challenge cung cấp:

* Một file `README.txt` chứa flag.
* Mô tả của đề bài và tên đề bài cũng là dạng **Invisible Unicode**.
* Bạn nhìn thấy flag kiểu:

```
D‎H{D‎o_‎‎Yo‎u‎_Be‎‎li‎‎e‎ve‎_‎W‎ha‎t‎_y‎o‎u‎_S‎e‎e‎_o‎n‎_t‎h‎e_‎w‎eb‎?‎}
```

* Nhưng khi copy-paste vào ô submit → **Wrong Answer**.

Inspect HTML:

```html
<h1 data-v-7be4cf0e="">
    ‌
    <!---->
</h1>
```

Kết quả là *gần như rỗng*, nhưng thực tế có chứa các ký tự Unicode vô hình.

---

## 2. Ý tưởng ẩn flag

Các tác giả chèn các **ký tự định dạng Unicode (Format characters)** vào giữa flag.
Những ký tự này **không hiển thị** nhưng vẫn tồn tại trong chuỗi khi copy-paste.

Ví dụ thường gặp:

* `U+200B` — ZERO WIDTH SPACE
* `U+200C` — ZERO WIDTH NON-JOINER
* `U+200D` — ZERO WIDTH JOINER
* `U+200E` — LEFT-TO-RIGHT MARK
* `U+200F` — RIGHT-TO-LEFT MARK
* `U+202A` đến `U+202E` — BiDi overrides
* `U+FEFF` — ZERO WIDTH NO-BREAK SPACE (BOM)

Những ký tự này có category `Cf` (Format) trong Unicode.

---

## 3. Tại sao flag sai khi copy

Server so sánh chuỗi **bit-by-bit**.
Mắt bạn thấy giống hệt, nhưng thực chất:

```
"D" + [U+200E] + "H" + ...
```

Khác hoàn toàn với:

```
"D" + "H" + ...
```

---

## 4. Phân tích chuỗi

### 4.1 Dùng Browser DevTools

Mở **Console** trong Chrome/Firefox:

```js
let s = document.querySelector('h1').textContent;
console.log("RAW:", s);
console.log("Length:", s.length);

// Xem từng codepoint
Array.from(s).forEach((ch, i) => {
  console.log(i, JSON.stringify(ch), 'U+' + ch.charCodeAt(0).toString(16).toUpperCase());
});
```

Bạn sẽ thấy các code như `U+200E`, `U+200B` nằm xen kẽ.

---

### 4.2 Dùng Python để phân tích

Lưu flag copy vào file `flag_raw.txt` rồi chạy:

```python
import unicodedata

s = open('flag_raw.txt', 'r', encoding='utf-8').read().strip()
print("Length:", len(s))

for i, ch in enumerate(s):
    print(i, repr(ch), hex(ord(ch)), unicodedata.name(ch, 'UNKNOWN'))

# Loại ký tự invisible (category 'Cf')
clean = ''.join(ch for ch in s if unicodedata.category(ch) != 'Cf')
print("Cleaned flag:", clean)
```

---

## 5. Cách giải

### 5.1 JavaScript one-liner

```js
let s = "D‎H{D‎o_‎‎Yo‎u‎_Be‎‎li‎‎e‎ve‎_‎W‎ha‎t‎_y‎o‎u‎_S‎e‎e‎_o‎n‎_t‎h‎e_‎w‎eb‎?‎}";
let cleaned = s.replace(/[\u200B\u200C\u200D\u200E\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/g, '');
console.log(cleaned); // Copy cái này submit
```

**Regex** trên lọc hầu hết ký tự zero-width và bidi control.

---

### 5.2 Python (offline)

```python
import re

s = open('flag_raw.txt','r',encoding='utf-8').read()
# Regex loại invisible
cleaned = re.sub(r'[\u200B\u200C\u200D\u200E\u200F\u202A-\u202E\u2066-\u2069\uFEFF]', '', s)
print(cleaned)
```

---

## 6. Kết quả

Sau khi lọc → flag thực:

```
DH{Do_You_Believe_What_you_See_on_the_web?}
```

---

## 7. Bài học rút ra

1. **Đừng tin mắt thường** — trong CTF, flag có thể chứa ký tự vô hình hoặc ký tự Unicode trông giống ASCII.
2. Khi gặp flag copy-paste bị sai:

   * Kiểm tra số lượng ký tự (`len()`).
   * In mã Unicode (`ord()` / `charCodeAt()`).
3. Dùng regex hoặc filter theo `unicodedata.category` để loại ký tự `Cf`.
4. Đây là kỹ thuật **Zero Width Character Injection** — phổ biến trong web challenges, stego text.

---

## 8. Tài liệu tham khảo

* [Unicode Zero Width Characters](https://www.amp-what.com/unicode/search/zero%20width)
* [Bidirectional Text in Unicode](https://www.w3.org/International/questions/qa-bidi-unicode-controls)
* [List of Unicode control characters](https://www.fileformat.info/info/unicode/category/Cf/list.htm)