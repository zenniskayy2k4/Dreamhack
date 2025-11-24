#!/usr/bin/env python3
from pwn import *
from collections import deque

HOST = "host8.dreamhack.games"
PORT = 22645

# ==============================================================================
# PHẦN 1: TỰ ĐỘNG GIẢI CÂU ĐỐ
# ==============================================================================

def solve_puzzle():
    """
    Sử dụng thuật toán tìm kiếm BFS (Breadth-First Search) để tìm ra con đường
    ngắn nhất từ trạng thái ban đầu đến trạng thái mục tiêu.
    """
    log.info("Bắt đầu giải câu đố để tìm 46 nước đi...")

    # Phân tích lại từ C code để có trạng thái chính xác 100%
    # B (0x42): 0,1,2,5,6,7,10,11
    # W (0x57): 13,14,17,18,19,22,23,24
    # . (0x2e): 12
    # * (0x2a): 3,4,8,9,15,16,20,21
    initial_state = "BBB**BBB**BB.WW**WWW**WWW"
    target_state = "WWW**WWW**WW.BB**BBB**BBB"

    # Hàng đợi cho BFS, mỗi phần tử là (trạng thái bàn cờ, danh sách các nước đi đã thực hiện)
    queue = deque([(initial_state, [])])
    
    # Set để lưu các trạng thái đã đi qua, tránh lặp lại
    visited = {initial_state}

    while queue:
        current_state, path = queue.popleft()

        # Nếu tìm thấy đích, trả về chuỗi nước đi
        if current_state == target_state:
            if len(path) == 46:
                log.success(f"Đã tìm thấy lời giải với đúng {len(path)} nước đi!")
                return path
            else:
                # Bỏ qua nếu tìm thấy đường đi nhưng không đủ 46 bước
                continue
        
        # Giới hạn độ sâu tìm kiếm để không bị quá tải
        if len(path) >= 46:
            continue

        # Tìm vị trí ô trống '.'
        empty_idx = current_state.find('.')
        empty_y, empty_x = divmod(empty_idx, 5)

        # Thử di chuyển các quân cờ xung quanh vào ô trống
        # Vector di chuyển: [lên, xuống, phải, trái]
        directions = [(-1, 0), (1, 0), (0, 1), (0, -1)]
        distances = [1, 2]

        for dy, dx in directions:
            for dist in distances:
                # Tọa độ của quân cờ có thể di chuyển vào ô trống
                src_y, src_x = empty_y - dy * dist, empty_x - dx * dist

                # Kiểm tra xem tọa độ có hợp lệ không
                if 0 <= src_y < 5 and 0 <= src_x < 5:
                    src_idx = src_y * 5 + src_x
                    piece = current_state[src_idx]

                    # Luật chơi: chỉ được di chuyển 'W' hoặc 'B'
                    if piece in ('W', 'B'):
                        # Tạo trạng thái bàn cờ mới
                        board_list = list(current_state)
                        board_list[empty_idx], board_list[src_idx] = board_list[src_idx], board_list[empty_idx]
                        new_state = "".join(board_list)

                        if new_state not in visited:
                            visited.add(new_state)
                            move_str = f"{src_y} {src_x} {empty_y} {empty_x}"
                            new_path = path + [move_str]
                            queue.append((new_state, new_path))
    
    log.error("Không tìm thấy lời giải!")
    return None

# ==============================================================================
# PHẦN 2: KẾT NỐI VÀ GỬI LỜI GIẢI
# ==============================================================================

# Bước 1: Gọi hàm để máy tính tự giải
solution_moves = solve_puzzle()

if not solution_moves:
    exit()

# Bước 2: Kết nối và gửi các nước đi đã tìm được
log.info("Kết nối tới server và gửi lời giải...")
io = remote(HOST, PORT)

io.recvuntil(b"Can you solve it?\n")
io.recvuntil(b"* - - - - - *\n")

for i, move in enumerate(solution_moves):
    log.info(f"Sending move {i+1}/{len(solution_moves)}: {move}")
    io.recvuntil(b"Move ")
    io.recvuntil(b" : ")
    io.sendline(move.encode())
    io.recvuntil(b"* - - - - - *\n")

io.recvuntil(b"Congratulations! You win!\n")
flag_line = io.recvline().decode().strip()
log.success(f"FLAG: {flag_line}")
io.close()