def reverse_shuffle_from_asm(shuffled_b):
    original_b = 0
    if (shuffled_b & 0b00001000): original_b |= 0b00000001
    if (shuffled_b & 0b00000001): original_b |= 0b00000010
    if (shuffled_b & 0b00010000): original_b |= 0b00000100
    if (shuffled_b & 0b00000010): original_b |= 0b00001000
    if (shuffled_b & 0b10000000): original_b |= 0b00010000
    if (shuffled_b & 0b01000000): original_b |= 0b00100000
    if (shuffled_b & 0b00000100): original_b |= 0b01000000
    if (shuffled_b & 0b00100000): original_b |= 0b10000000
    return original_b

def solve_the_hex_flag():
    correct_array = [
        0xae, 0x6d, 0x9b, 0x92, 0x13, 0x2b, 0xc6, 0xc9, 0xe5, 0xfa,
        0x96, 0xb0, 0x64, 0x31, 0xb8, 0x80, 0xc8, 0x48, 0xd2, 0x30,
        0x60, 0x40, 0xfa, 0x7b, 0x88, 0xb0, 0x2f, 0x7c, 0xb3, 0xb3,
        0x58, 0x61
    ]
    flag_bytes = []
    for correct_byte in correct_array:
        shuffled_target = ((correct_byte - 0x22) & 0xff) ^ 0x63
        original_byte = reverse_shuffle_from_asm(shuffled_target)
        flag_bytes.append(original_byte)
    hex_flag = "".join(f"{byte:02x}" for byte in flag_bytes)
    print(f"DH{{{hex_flag}}}")

solve_the_hex_flag()