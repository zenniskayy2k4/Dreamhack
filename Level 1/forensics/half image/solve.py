from PIL import Image
import os

flag_image_path = "flag.png"

try:
    # 1. Mở flag.png. PIL sẽ chỉ đọc phần PNG hợp lệ (nửa bên trái)
    # và bỏ qua dữ liệu thừa ở cuối.
    left_img = Image.open(flag_image_path)
    left_width, height = left_img.size
    
    # 2. Đọc toàn bộ byte của file flag.png
    with open(flag_image_path, "rb") as f:
        flag_data = f.read()

    # 3. Lấy kích thước của phần PNG hợp lệ (nửa bên trái)
    # Chúng ta có thể lưu lại ảnh trái vào bộ nhớ để lấy kích thước chính xác của nó.
    from io import BytesIO
    left_bytes_io = BytesIO()
    left_img.save(left_bytes_io, format='PNG')
    left_png_size = left_bytes_io.tell()

    # 4. Dữ liệu thô của nửa bên phải bắt đầu ngay sau phần PNG của nửa bên trái.
    right_raw_data = flag_data[left_png_size:]

    # 5. Tính toán chiều rộng của nửa bên phải dựa trên kích thước dữ liệu thô.
    # Mỗi pixel RGB chiếm 3 byte.
    # Kích thước dữ liệu = right_width * height * 3
    # => right_width = Kích thước dữ liệu / (height * 3)
    # Sử dụng phép chia số nguyên // để đảm bảo kết quả là số nguyên.
    right_width = len(right_raw_data) // (height * 3)
    
    # 6. Tạo ảnh cho nửa bên phải từ dữ liệu thô.
    # Chế độ màu là 'RGB' và kích thước là (right_width, height).
    # Ta cần chỉ định stride (số byte trên mỗi dòng) để tránh ảnh bị nghiêng.
    # Stride = tổng số byte / chiều cao.
    stride = len(right_raw_data) // height
    right_img = Image.frombytes('RGB', (right_width, height), right_raw_data, 'raw', 'RGB', stride)

    # 7. Tạo một ảnh mới với chiều rộng gấp đôi để ghép hai nửa lại.
    total_width = left_width + right_width
    full_img = Image.new('RGB', (total_width, height))

    # 8. Dán nửa bên trái và nửa bên phải vào ảnh mới.
    full_img.paste(left_img, (0, 0))
    full_img.paste(right_img, (left_width, 0))

    # 9. Lưu và hiển thị ảnh kết quả.
    solved_path = "flag_solved.png"
    full_img.save(solved_path)
    
    print(f"Đã khôi phục ảnh thành công! Lưu tại: {solved_path}")
    
    # Mở ảnh đã giải (chỉ hoạt động trên Windows)
    os.startfile(solved_path)

except FileNotFoundError:
    print(f"Lỗi: Không tìm thấy tệp '{flag_image_path}'.")
    print("Hãy chắc chắn rằng bạn đã chạy script 'flag.py' để tạo ra 'flag.png' trước.")
except Exception as e:
    print(f"Đã xảy ra lỗi: {e}")
    print("Có thể chiều rộng của ảnh gốc là số lẻ. Hãy thử điều chỉnh lại script.")