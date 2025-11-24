import asyncio
import aiohttp
import requests
import json
from tqdm.asyncio import tqdm
from PIL import Image

# --- Cấu hình ---
URL = "http://host1.dreamhack.games:15271/check"
HEIGHT = 30
WIDTH = 200
CONCURRENCY = 100  # Số lượng yêu cầu gửi cùng lúc
OUTPUT_IMAGE_FILENAME = "flag.png"


# --- Phần 1: Tìm tất cả các tọa độ đúng (từ sol.py) ---
async def find_solution_coords():
    """Sử dụng aiohttp để tìm tất cả các ô đúng một cách bất đồng bộ."""
    print("--- Bước 1: Bắt đầu tìm các tọa độ đúng... ---")
    
    solution_coords = []
    sem = asyncio.Semaphore(CONCURRENCY)

    async def check_cell(session, r, c):
        async with sem:
            payload = {"filled": [[r, c]]}
            try:
                async with session.post(URL, json=payload) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get("extra") == 0:
                            return (r, c)
            except aiohttp.ClientError:
                # Bỏ qua lỗi in ra để thanh tiến trình đẹp hơn
                pass
        return None

    async with aiohttp.ClientSession() as session:
        tasks = [check_cell(session, r, c) for r in range(HEIGHT) for c in range(WIDTH)]
        results = await tqdm.gather(*tasks, desc="Đang kiểm tra các ô")

        for result in results:
            if result:
                solution_coords.append(result)

    solution_coords.sort()
    print(f"Đã tìm thấy {len(solution_coords)} tọa độ đúng.\n")
    return solution_coords


# --- Phần 2: Gửi toàn bộ giải pháp để xác nhận (từ submit.py) ---
def submit_solution(coords):
    """Gửi toàn bộ tọa độ đã tìm được để xác nhận với server."""
    if not coords:
        print("Không tìm thấy tọa độ nào để gửi đi.")
        return

    print("--- Bước 2: Gửi toàn bộ giải pháp để xác nhận... ---")
    
    # Chuyển đổi tuple (r, c) thành list [r, c]
    filled_payload = [[r, c] for r, c in coords]
    
    try:
        res = requests.post(URL, json={"filled": filled_payload})
        res.raise_for_status()
        response_data = res.json()
        
        print("Phản hồi từ Server:")
        print(json.dumps(response_data, indent=2))
        
        if response_data.get("ok"):
            print("Xác nhận thành công! Đáp án chính xác.\n")
        else:
            print("Xác nhận thất bại. Đáp án có thể chưa đúng.\n")
            
    except requests.exceptions.RequestException as e:
        print(f"Lỗi khi gửi yêu cầu xác nhận: {e}\n")


# --- Phần 3: Vẽ ảnh flag từ tọa độ (từ draw_flag.py) ---
def draw_flag_image(coords):
    """Vẽ ảnh từ danh sách các tọa độ và lưu thành file."""
    if not coords:
        print("Không có tọa độ để vẽ ảnh.")
        return
        
    print(f"--- Bước 3: Vẽ ảnh flag từ {len(coords)} tọa độ... ---")
    
    img = Image.new('RGB', (WIDTH, HEIGHT), 'white')
    pixels = img.load()

    for r, c in coords:
        if 0 <= c < WIDTH and 0 <= r < HEIGHT:
            pixels[c, r] = (0, 0, 0)  # Tô màu đen

    img.save(OUTPUT_IMAGE_FILENAME)
    print(f"Hoàn thành! Flag đã được vẽ và lưu vào file '{OUTPUT_IMAGE_FILENAME}'")


# --- Hàm chính để chạy tất cả các bước ---
async def main():
    # Bước 1
    found_coords = await find_solution_coords()
    
    if found_coords:
        # Bước 2
        submit_solution(found_coords)
        
        # Bước 3
        draw_flag_image(found_coords)
    else:
        print("Không tìm thấy tọa độ nào. Quá trình kết thúc.")


if __name__ == "__main__":
    asyncio.run(main())