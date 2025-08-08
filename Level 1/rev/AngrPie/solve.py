import angr
import claripy
import sys
import logging

logging.getLogger('angr').setLevel('ERROR')

BINARY_NAME = './chall'

try:
    project = angr.Project(BINARY_NAME, auto_load_libs=False)
except Exception as e:
    print(f"Lỗi khi tải file: {e}")
    sys.exit(1)

# Sử dụng entry_state vì chúng ta cần một stack hợp lệ
# Thêm các option để tránh một số vấn đề với stack không xác định
state = project.factory.entry_state(
    add_options={
        angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
        angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
    }
)

# Tạo 16 byte tượng trưng cho mật khẩu và ghi vào một vùng nhớ trên stack
password_len = 16
password_bvs = claripy.BVS('password', password_len * 8)
# Ghi vào stack, rsp-0x20 là nơi buffer được tạo trong hàm main (cần kiểm tra lại bằng disassembler)
# Giả sử rsp-0x30 là một nơi an toàn trên stack
password_addr = state.regs.rsp - 0x30
state.memory.store(password_addr, password_bvs)

# Lấy địa chỉ của complex_function
try:
    complex_function_addr = project.loader.find_symbol('complex_function').rebased_addr
    print(f"Đã tìm thấy 'complex_function' tại địa chỉ: {hex(complex_function_addr)}")
except Exception:
    print("Không tìm thấy symbol 'complex_function'.")
    sys.exit(1)

# Thiết lập PC để bắt đầu chạy từ hàm complex_function
state.regs.pc = complex_function_addr
# Thiết lập tham số (rdi) trỏ tới mật khẩu trên stack
state.regs.rdi = password_addr

# Tạo simulation manager
simgr = project.factory.simulation_manager(state)

print("Bắt đầu dò dẫm có kiểm soát...")

# Con đường đúng sẽ đi sâu nhất vào hàm
# Các con đường sai sẽ thoát ra sớm
# Chúng ta sẽ lặp và luôn chọn path có địa chỉ lớn hơn (heuristic)
# vì code đi tuần tự từ trên xuống dưới
while len(simgr.active) == 1:
    current_state = simgr.active[0]
    print(f"Đang ở địa chỉ: {hex(current_state.addr)}")
    
    # Thực thi một khối lệnh
    simgr.step()
    
    # Nếu có 2 nhánh, chọn nhánh đi "tiến"
    if len(simgr.active) == 2:
        state_0 = simgr.active[0]
        state_1 = simgr.active[1]
        
        # Heuristic: con đường đúng thường có địa chỉ tiếp theo lớn hơn
        if state_0.addr > state_1.addr:
            print(f"  Rẽ nhánh: Chọn {hex(state_0.addr)} thay vì {hex(state_1.addr)}")
            simgr.active = [state_0]
        else:
            print(f"  Rẽ nhánh: Chọn {hex(state_1.addr)} thay vì {hex(state_0.addr)}")
            simgr.active = [state_1]
            
    # Nếu có nhiều hơn 2 nhánh hoặc không còn nhánh nào, dừng lại
    elif len(simgr.active) != 1:
        break

# Sau khi thoát vòng lặp, chúng ta hy vọng có 1 state cuối cùng
if len(simgr.active) == 1:
    final_state = simgr.active[0]
    print("\nĐã đi hết con đường đúng! Bắt đầu giải...")

    # Thêm ràng buộc cấu trúc flag để tăng tốc độ giải
    final_state.solver.add(password_bvs.get_byte(0) == ord('D'))
    final_state.solver.add(password_bvs.get_byte(1) == ord('H'))
    final_state.solver.add(password_bvs.get_byte(2) == ord('{'))
    final_state.solver.add(password_bvs.get_byte(15) == ord('}'))

    if final_state.solver.satisfiable():
        print("Yeah! Đã tìm thấy một lời giải!")
        password_solution = final_state.solver.eval(password_bvs, cast_to=bytes)

        final_flag = "".join(chr(b) if 32 <= b <= 126 else f'\\x{b:02x}' for b in password_solution)
        print(f"\nFLAG LÀ: {final_flag}")
    else:
        print("Không thể giải được các ràng buộc trên state cuối cùng.")
else:
    print(f"Dò dẫm thất bại. Số state còn lại: {len(simgr.active)}")