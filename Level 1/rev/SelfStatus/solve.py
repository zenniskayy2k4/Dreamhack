def emulate_vm():
    """
    Emulates the custom VM from the binary to reconstruct the flag.
    """
    # BƯỚC 1: Dữ liệu bytecode đã được trích xuất và chèn vào đây.
    bytecode_hex = (
        "eeefee2fee11a106a342f0ee3eeea2ee6da10aa342f0ee1deeffa139a342f0eec7eec4eed6"
        "a111a342f0ee24ee70a171a342f0ee22ee59a12ea342f0eeb2ee96ee7ba124a342f0ee7eee"
        "3ca111a342f0ee5fa136a342f0ee0ceefca176a342f0ee8aee54a136a342f0ee9aee08eed7"
        "a137a342f0eed7a131a342f0ee36a11da342f0ee48a114a342f0ee3cee52a10fa342f0ee10"
        "ee2eee34a11da342f0eeffee01ee02a100a342f0ee0ba13ba342f0ee3dee88ee65a175a342"
        "f0ee3fee22a127a342f0ee90eeeaee47a121a342f0eee3ee04eecca172a342f0ee09ee39ee"
        "78a126a342f0ee1cee06ee42a171a342f0ee7ba13fa342f0ff"
    )
    bytecode = bytes.fromhex(bytecode_hex)

    # BƯỚC 2: Thiết lập môi trường máy ảo
    stack = []
    output_flag = []
    ip = 0  # Instruction Pointer

    print("Bắt đầu mô phỏng máy ảo...")

    # BƯỚC 3: Vòng lặp thông dịch
    while ip < len(bytecode):
        opcode = bytecode[ip]

        # Lệnh PUSH: 0xA1
        if opcode == 0xa1:
            value = bytecode[ip + 1]
            stack.append(value)
            ip += 2
        
        # Lệnh POP: 0xA2
        elif opcode == 0xa2:
            if stack:
                stack.pop()
            ip += 1

        # Lệnh XOR: 0xA3
        elif opcode == 0xa3:
            if stack:
                value_to_xor = bytecode[ip + 1]
                stack[-1] ^= value_to_xor
            ip += 2

        # Lệnh ADD: 0xA4
        elif opcode == 0xa4:
            if stack:
                value_to_add = bytecode[ip + 1]
                stack[-1] = (stack[-1] + value_to_add) % 256
            ip += 2

        # Lệnh NOP (No Operation): 0xA5, 0xEE
        elif opcode in [0xa5, 0xee]:
            ip += 2

        # Lệnh OUT: 0xF0
        elif opcode == 0xf0:
            if stack:
                char_code = stack.pop()
                output_flag.append(char_code)
            ip += 1

        # Lệnh HALT: 0xFF
        elif opcode == 0xff:
            print(f"Gặp lệnh HALT tại vị trí {ip}. Dừng thực thi.")
            break
        
        else:
            print(f"Cảnh báo: Gặp opcode không xác định {hex(opcode)} tại vị trí {ip}. Bỏ qua.")
            ip += 1

    # BƯỚC 4: Xử lý và in kết quả
    if output_flag:
        flag = "".join([chr(c) for c in output_flag])
        print("\n" + "="*40)
        print(f"Mô phỏng hoàn tất!")
        print(f"FLAG: {flag}")
        print("="*40)
    else:
        print("Mô phỏng hoàn tất nhưng không có output nào được tạo ra.")

if __name__ == "__main__":
    emulate_vm()