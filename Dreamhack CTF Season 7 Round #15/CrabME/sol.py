def shuffle_byte_from_asm(b):
    """
    Mô phỏng lại phép biến đổi bit từ mã assembly một cách cẩn thận.
    Chúng ta sẽ không dùng phép cộng mà chỉ dùng phép OR bit,
    vì phân tích lại cho thấy không có sự chồng chéo bit gây ra carry.
    """
    out = 0
    # out_bit_0 (0x1)  <- in_bit_1 (0x2)
    if b & 0b00000010: out |= 0b00000001
    
    # out_bit_1 (0x2)  <- in_bit_3 (0x8)
    if b & 0b00001000: out |= 0b00000010

    # out_bit_2 (0x4)  <- in_bit_6 (0x40)
    if b & 0b01000000: out |= 0b00000100

    # out_bit_3 (0x8)  <- in_bit_0 (0x1)
    if b & 0b00000001: out |= 0b00001000

    # out_bit_4 (0x10) <- in_bit_2 (0x4)
    if b & 0b00000100: out |= 0b00010000

    # out_bit_5 (0x20) <- in_bit_7 (0x80)
    if b & 0b10000000: out |= 0b00100000

    # out_bit_6 (0x40) <- in_bit_5 (0x20)
    if b & 0b00100000: out |= 0b01000000

    # out_bit_7 (0x80) <- in_bit_4 (0x10)
    if b & 0b00010000: out |= 0b10000000

    return out

def solve_final():
    """
    Hàm giải quyết cuối cùng, sử dụng bảng tra cứu ngược.
    """
    # 1. Tạo bảng tra cứu xuôi
    transform_map = {i: shuffle_byte_from_asm(i) for i in range(256)}
    
    # 2. Tạo bảng tra cứu ngược
    reverse_transform_map = {value: key for key, value in transform_map.items()}

    # 3. Mảng "đáp án" từ mã dịch ngược
    correct_array = [
        0xae, 0x6d, 0x9b, 0x92, 0x13, 0x2b, 0xc6, 0xc9, 0xe5, 0xfa,
        0x96, 0xb0, 0x64, 0x31, 0xb8, 0x80, 0xc8, 0x48, 0xd2, 0x30,
        0x60, 0x40, 0xfa, 0x7b, 0x88, 0xb0, 0x2f, 0x7c, 0xb3, 0xb3,
        0x58, 0x61
    ]

    flag_bytes = []
    for correct_byte in correct_array:
        # a. Đảo ngược các phép toán số học: (kết quả - 0x22) XOR 0x63
        shuffled_target = ((correct_byte - 0x22) & 0xff) ^ 0x63
        
        # b. Dùng bảng tra cứu ngược để tìm byte gốc
        original_byte = reverse_transform_map[shuffled_target]
        
        flag_bytes.append(original_byte)

    # Chuyển đổi các byte thành chuỗi hex
    hex_flag = "".join(f"{byte:02x}" for byte in flag_bytes)
    
    # In ra flag theo định dạng chính xác
    print(f"DH{{{hex_flag}}}")

# Chạy hàm giải
solve_final()