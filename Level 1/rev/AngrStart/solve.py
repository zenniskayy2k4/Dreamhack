import angr
import claripy
import sys

BINARY_NAME = './chall' 

try:
    project = angr.Project(BINARY_NAME, auto_load_libs=False)
except Exception as e:
    print(f"Lỗi khi tải file: {e}")
    sys.exit(1)

state = project.factory.blank_state()

password_len = 16
password_bvs = claripy.BVS('password', password_len * 8)

password_addr = 0x600000 
state.memory.store(password_addr, password_bvs)

try:
    complex_function_addr = project.loader.find_symbol('complex_function').rebased_addr
except:
    print("Không tìm thấy symbol 'complex_function'.")
    sys.exit(1)

prototype = angr.sim_type.SimTypeFunction([angr.sim_type.SimTypePointer(angr.sim_type.SimTypeChar())], angr.sim_type.SimTypeInt())
complex_callable = project.factory.callable(complex_function_addr, prototype=prototype)
complex_callable.set_base_state(state)

print("Bắt đầu phân tích (áp dụng ràng buộc cấu trúc)...")

result = complex_callable(password_addr)

# --- PHẦN LOGIC ĐÚNG ---

# 1. Ràng buộc chính: kết quả phải bằng 0
state.solver.add(result == 0)

# 2. Ràng buộc cấu trúc flag: DH{...}
print("Thêm ràng buộc cấu trúc: DH{...}")
state.solver.add(password_bvs.get_byte(0) == ord('D'))
state.solver.add(password_bvs.get_byte(1) == ord('H'))
state.solver.add(password_bvs.get_byte(2) == ord('{'))
state.solver.add(password_bvs.get_byte(15) == ord('}'))

# Không thêm ràng buộc cho các ký tự ở giữa
# -----------------------------

print("Đang giải phương trình với các ràng buộc chính xác...")

if state.solver.satisfiable():
    print("Yeah! Đã tìm thấy một lời giải!")
    
    password_solution = state.solver.eval(password_bvs, cast_to=bytes)
    
    # In kết quả một cách an toàn
    print(f"\nKết quả (dạng bytes): {password_solution}")
    print(f"Kết quả (dạng hex):   {password_solution.hex()}")
    
    # Tạo ra một chuỗi có thể copy-paste được
    final_flag = ""
    try:
        final_flag = password_solution.decode('utf-8')
    except UnicodeDecodeError:
        # Nếu có lỗi, chỉ những ký tự không in được mới bị thay thế
        final_flag = "".join(chr(b) if 32 <= b <= 126 else f'\\x{b:02x}' for b in password_solution)

    print(f"FLAG CUỐI CÙNG LÀ: {final_flag}")

else:
    print("Rất tiếc, không tìm thấy lời giải với các ràng buộc hiện tại.")