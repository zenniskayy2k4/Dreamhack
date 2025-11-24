Đây là một bài CTF dạng web/logic puzzle rất hay. Thoạt nhìn có vẻ như đây là một trò chơi may rủi, nhưng thực chất nó dựa trên một câu đố logic kinh điển.

### Phân tích quy luật trò chơi

1.  **Thiết lập ban đầu:**
    *   Có tổng cộng 100 đồng xu, được đánh số ID từ 0 đến 99.
    *   Trong đó, **chỉ 10 đồng xu (ID từ 0 đến 9) ban đầu có mặt xanh**. 90 đồng xu còn lại (ID từ 10 đến 99) có mặt đỏ. Đây là sự thật không thay đổi.

2.  **Bắt đầu ván chơi (`/start`):**
    *   Server chọn **ngẫu nhiên 10 đồng xu** trong 100 đồng xu và đưa chúng sang "khu vực bên trái".
    *   90 đồng xu còn lại nằm ở "khu vực bên phải".
    *   Bạn (người chơi) chỉ có thể tương tác với 10 đồng xu bên trái.

3.  **Mục tiêu:**
    *   Bạn cần làm cho **số đồng xu mặt xanh bên trái** BẰNG với **số đồng xu mặt xanh bên phải**.
    *   Bạn có thể "lật" (toggle) bất kỳ đồng xu nào trong 10 đồng xu bên trái. Lật một đồng xu sẽ đổi màu của nó (xanh -> đỏ, đỏ -> xanh).

4.  **Chiến thắng:**
    *   Nếu bạn đạt được mục tiêu, streak (chuỗi thắng) sẽ tăng lên 1.
    *   Nếu thất bại, streak reset về 0.
    *   Đạt được **10 chuỗi thắng liên tiếp**, bạn sẽ nhận được flag.

### Tìm ra lỗ hổng logic (The Puzzle)

Bài toán này không hề ngẫu nhiên. Có một chiến lược đảm bảo thắng 100%. Hãy cùng phân tích bằng toán học đơn giản:

*   Gọi `G_total = 10` là tổng số đồng xu xanh ban đầu.
*   Khi ván chơi bắt đầu, server chọn 10 đồng xu cho bạn.
*   Gọi `k` là số đồng xu xanh **thực sự** nằm trong 10 đồng xu bên trái mà bạn được chọn. `k` có thể là một số bất kỳ từ 0 đến 10.
*   Vậy, số đồng xu đỏ trong 10 đồng xu bên trái sẽ là `10 - k`.

Bây giờ, hãy xem số lượng đồng xu xanh ở hai bên:
*   **Số xu xanh bên trái (ban đầu):** `k`
*   **Số xu xanh bên phải (không đổi):** Vì tổng số xu xanh là 10, và có `k` xu đã ở bên trái, nên số xu xanh bên phải chắc chắn là `10 - k`.

Mục tiêu của chúng ta là làm cho `Số xu xanh cuối cùng bên trái` = `Số xu xanh bên phải` = `10 - k`.

Làm thế nào để từ `k` xu xanh ban đầu bên trái, chúng ta biến nó thành `10 - k` xu xanh?
Câu trả lời nằm ở hành động "lật".

**Chiến lược quyết định: Lật TẤT CẢ 10 đồng xu bên trái.**

Hãy xem điều gì xảy ra khi bạn lật cả 10 đồng xu:
*   `k` đồng xu xanh ban đầu sẽ bị lật thành **đỏ**.
*   `10 - k` đồng xu đỏ ban đầu sẽ bị lật thành **xanh**.

Kết quả cuối cùng: Số đồng xu xanh ở bên trái sẽ chính xác là `10 - k`.

Con số này **luôn luôn bằng** số đồng xu xanh ở bên phải (`10 - k`). Do đó, bạn sẽ **luôn luôn thắng**.

### Hướng dẫn giải

#### Cách giải thủ công

1.  Mở trang web của bài challenge.
2.  Nhấn nút "Start".
3.  Khi 10 đồng xu được chuyển sang ô bên trái, hãy **click vào tất cả 10 đồng xu đó** để chọn lật chúng (chúng sẽ có viền vàng).
4.  Nhấn nút "Submit" (hoặc "Reveal").
5.  Bạn sẽ thấy thông báo thành công và streak tăng lên 1.
6.  Lặp lại quá trình này 10 lần để nhận được flag.

Việc click thủ công có thể hơi tốn thời gian và dễ nhầm lẫn, vì vậy chúng ta nên viết một kịch bản để tự động hóa.

#### Script tự động giải

Chúng ta sẽ sử dụng Python và thư viện `requests` để tự động tương tác với server.

```python
import requests
import json

# URL của challenge (thay đổi nếu cần)
BASE_URL = "http://<CHALLENGE_IP>:<PORT>" 

def solve():
    # Sử dụng requests.Session để tự động quản lý cookie (rất quan trọng cho flask.session)
    s = requests.Session()

    # Truy cập trang chủ lần đầu để khởi tạo session cookie
    s.get(f"{BASE_URL}/")
    print("Session initialized.")

    streak = 0
    while streak < 10:
        print(f"\n--- Attempting round for streak {streak+1} ---")
        
        # 1. Gửi yêu cầu để bắt đầu một ván mới
        try:
            start_resp = s.post(f"{BASE_URL}/start")
            start_data = start_resp.json()
            
            if not start_data.get("ok"):
                print("Failed to start a new round:", start_data)
                return

            round_token = start_data["token"]
            left_ids = start_data["left_ids"]
            print(f"Round started. Token: {round_token[:10]}... Left IDs: {left_ids}")

        except requests.exceptions.RequestException as e:
            print(f"Error during /start request: {e}")
            return
        
        # 2. Xây dựng payload để submit
        # Chiến lược: Lật tất cả các đồng xu bên trái (toggled = left_ids)
        submit_payload = {
            "round": round_token,
            "toggled": left_ids 
        }

        # 3. Gửi câu trả lời
        try:
            submit_resp = s.post(f"{BASE_URL}/submit", json=submit_payload)
            submit_data = submit_resp.json()

            if submit_data.get("success"):
                streak = submit_data.get("streak", 0)
                print(f"Success! New streak: {streak}")
                
                # 4. Kiểm tra xem đã có flag chưa
                if submit_data.get("finished") and "flag" in submit_data:
                    flag = submit_data["flag"]
                    print("\n" + "="*40)
                    print(f"FLAG FOUND: {flag}")
                    print("="*40)
                    return flag
            else:
                print("Failed! Server response:", submit_data)
                print("Streak reset. Retrying...")
                streak = 0 # Reset streak theo logic server
        
        except requests.exceptions.RequestException as e:
            print(f"Error during /submit request: {e}")
            return

    print("\nCompleted 10 streaks but did not find the flag. Please check the logic.")


if __name__ == "__main__":
    # Thay thế URL bên dưới bằng địa chỉ thực tế của challenge
    # Ví dụ: BASE_URL = "http://host8.dreamhack.games:14146/"
    if "CHALLENGE_IP" in BASE_URL:
        print("Please replace <CHALLENGE_IP>:<PORT> with the actual challenge URL in the script.")
    else:
        solve()
```