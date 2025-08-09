def reverse_add(char_byte, key_byte):
    """Phép toán ngược của opcode 1: trừ"""
    return (char_byte - key_byte) & 0xFF

def reverse_xor(char_byte, key_byte):
    """Phép toán ngược của opcode 2: XOR"""
    return char_byte ^ key_byte

def reverse_ror(char_byte, key_byte):
    """Phép toán ngược của opcode 3: xoay trái (ROL)"""
    shift = key_byte & 7
    if shift == 0:
        return char_byte
    # ROL: (char << shift) | (char >> (8 - shift))
    return ((char_byte << shift) | (char_byte >> (8 - shift))) & 0xFF

# Ánh xạ opcode tới hàm ngược của nó
reverse_operations = {
    1: reverse_add,
    2: reverse_xor,
    3: reverse_ror,
}

# 1. Đọc các file bin
try:
    with open("output.bin", "rb") as f:
        data = bytearray(f.read())

    with open("program.bin", "rb") as f:
        program_code = f.read()
except FileNotFoundError as e:
    print(f"Error: {e}. Make sure 'output.bin' and 'program.bin' are in the same directory.")
    exit(1)

# 2. Phân tích program.bin thành các lệnh
instructions = []
# Lặp qua program_code, mỗi bước 2 byte
for i in range(0, len(program_code), 2):
    opcode = program_code[i]
    operand = program_code[i+1]
    instructions.append((opcode, operand))
    
print(f"[*] Found {len(instructions)} instructions.")

# Lệnh đầu tiên phải là INPUT (opcode 4), chúng ta bỏ qua nó trong quá trình đảo ngược.
# Chúng ta sẽ xử lý các lệnh còn lại theo thứ tự ngược.
# `instructions[1:]` để bỏ qua lệnh INPUT, `reversed()` để đảo ngược.
for opcode, operand in reversed(instructions[1:]):
    if opcode in reverse_operations:
        # Lấy hàm ngược tương ứng
        reverse_func = reverse_operations[opcode]
        # Áp dụng phép toán ngược cho từng byte trong dữ liệu
        for i in range(len(data)):
            data[i] = reverse_func(data[i], operand)
    else:
        print(f"[!] Warning: Unknown opcode {opcode} encountered. Skipping.")

# 5. In ra kết quả
try:
    flag = data.decode('utf-8')
    print("\n[+] Found Flag:")
    print(flag)
except UnicodeDecodeError:
    print("\n[!] Failed to decode the result as UTF-8. Here is the raw byte data:")
    print(data)