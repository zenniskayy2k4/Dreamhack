import requests

BASE_URL = "http://host8.dreamhack.games:14146/" 

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
                    print(f"FLAG: {flag}")
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
    solve()