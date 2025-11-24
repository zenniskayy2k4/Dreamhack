## **Write-up – Just read flag (Dreamhack)**

### **1. Phân tích đề**

* Đề bài cho:

  ```
  ssh with id: dream
  flag only challenge!
  ```
* Thông tin kết nối VM:

  ```
  Host: host1.dreamhack.games
  Port: 23343
  ```
* Kèm **private key** ở dạng `OPENSSH PRIVATE KEY`.

\=> Rõ ràng đây là một **SSH challenge**, ta phải dùng key để đăng nhập vào máy ảo và tìm flag.

---

### **2. Lưu private key và SSH**

**Bước 1:** Lưu nội dung private key ra file, ví dụ `dreamhack_invitational_welcome`

```bash
nano dreamhack_invitational_welcome
```

Dán nguyên key vào, rồi `Ctrl+O`, `Enter`, `Ctrl+X` để lưu.

**Bước 2:** Chỉnh quyền file key (SSH yêu cầu key chỉ được chủ sở hữu đọc/ghi)

```bash
chmod 600 dreamhack_invitational_welcome
```

**Bước 3:** SSH vào server

```bash
ssh -i dreamhack_invitational_welcome -p 23343 dream@host1.dreamhack.games
```

---

### **3. Tìm flag**

Vào được máy ảo, lệnh `ls` cho thấy:

```
flag_welcome
```

Check quyền:

```bash
ls -l
-rw-r----- 1 root dream 45 May  3  2024 flag_welcome
```

* File thuộc owner `root`, group `dream`
* Quyền `640` → group có quyền đọc → user `dream` đọc được

---

### **4. Vấn đề**

Khi `cat flag_welcome` → không thấy gì in ra.
Nguyên nhân: flag chứa ký tự **CR** (`\r`, 0x0d) ở cuối, hoặc chỉ có ký tự không hiển thị.

---

### **5. Cách đọc**

Do máy không có `xxd`/`hexdump`/`file`, phải dùng `od` (octal/hex dump):

```bash
cat flag_welcome | od -An -tx1
```

Kết quả:

```
44 48 7b 41 20 63 61 74 20 77 61 6c 6b 73 20 61
63 72 6f 73 73 20 74 68 65 20 66 72 6f 7a 65 6e
20 48 61 6e 20 52 69 76 65 72 2e 7d 0d
```

---

### **6. Giải mã**

Dùng bảng ASCII:

| Hex   | ASCII |
| ----- | ----- |
| 44 48 | DH    |
| 7b    | {     |
| ...   | ...   |
| 7d    | }     |

Ghép lại:

```
DH{A cat walks across the frozen Han River.}
```

---

### **7. Flag**

```
DH{A cat walks across the frozen Han River.}
```

---

### **8. Kinh nghiệm rút ra**

* Khi SSH dùng private key, luôn `chmod 600` cho key.
* Nếu `cat` không in ra gì, kiểm tra bằng các tool hiển thị raw bytes (`xxd`, `od`, `hexdump`).
* Ký tự `\r` (carriage return) có thể làm terminal “ghi đè” output khiến ta tưởng file rỗng.
* Trong CTF, flag đôi khi được giấu trong binary hoặc file “trông như rỗng” để đánh lừa.