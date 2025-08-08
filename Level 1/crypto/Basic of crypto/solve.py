from itertools import permutations

def generate_keystream(H, M, length):
    """Tạo keystream với độ dài cho trước"""
    h, m = 0, 0
    keystream = []
    for _ in range(length):
        keystream.append(8 * H[h] + M[m])
        m += 1
        if m >= 8:
            h += 1
            h %= 8
            m = 0
    return keystream

def is_valid_flag_char(byte_val):
    """Kiểm tra xem byte có hợp lệ trong flag không"""
    return ((0x41 <= byte_val <= 0x5a) or  # A-Z
            (0x61 <= byte_val <= 0x7a) or  # a-z
            (byte_val == 0x5f))             # _

def find_possible_hm_pairs(target_value):
    """Tìm tất cả cặp (h, m) sao cho 8*h + m = target_value"""
    pairs = []
    for h in range(8):
        for m in range(8):
            if 8 * h + m == target_value:
                pairs.append((h, m))
    return pairs

def solve_optimized():
    # Đọc ciphertext
    with open("flag.txt.enc", "rb") as f:
        ciphertext = f.read()
    
    print(f"Ciphertext length: {len(ciphertext)}")
    print(f"Ciphertext (hex): {ciphertext.hex()}")
    
    # Biết rằng plaintext bắt đầu bằng "DH{" và kết thúc bằng "}"
    known_start = b"DH{"
    known_end = ord('}')
    
    # Tính keystream cần thiết
    target_keystream = []
    for i in range(3):
        target_keystream.append(ciphertext[i] ^ known_start[i])
    target_keystream.append(ciphertext[-1] ^ known_end)  # Byte cuối cùng
    
    print(f"Target keystream positions [0,1,2,{len(ciphertext)-1}]: {target_keystream}")
    
    # Tìm các cặp (h,m) có thể cho từng vị trí keystream
    possible_pairs = []
    for i, target in enumerate(target_keystream[:3]):
        pairs = find_possible_hm_pairs(target)
        possible_pairs.append(pairs)
        print(f"Position {i}: target={target}, possible (h,m) pairs: {pairs}")
    
    # Phân tích vị trí trong clock cho 3 byte đầu
    # Position 0: h=0, m=0 -> cần H[0], M[0]
    # Position 1: h=0, m=1 -> cần H[0], M[1] 
    # Position 2: h=0, m=2 -> cần H[0], M[2]
    
    print("\nAnalyzing constraints...")
    
    # Lấy tất cả combinations có thể cho 3 vị trí đầu
    valid_combinations = []
    
    for pair0 in possible_pairs[0]:  # (H[0], M[0])
        for pair1 in possible_pairs[1]:  # (H[0], M[1])
            for pair2 in possible_pairs[2]:  # (H[0], M[2])
                h0_from_pos0, m0 = pair0
                h0_from_pos1, m1 = pair1
                h0_from_pos2, m2 = pair2
                
                # H[0] phải giống nhau ở cả 3 vị trí
                if h0_from_pos0 == h0_from_pos1 == h0_from_pos2:
                    h0 = h0_from_pos0
                    # Kiểm tra xem M[0], M[1], M[2] có khác nhau không (vì M là permutation)
                    if len(set([m0, m1, m2])) == 3:
                        valid_combinations.append((h0, m0, m1, m2))
    
    print(f"Found {len(valid_combinations)} valid combinations for first 3 positions")
    
    # Với mỗi combination hợp lệ, thử tạo các permutation phù hợp
    for combo in valid_combinations:
        h0, m0, m1, m2 = combo
        print(f"\nTrying combination: H[0]={h0}, M[0]={m0}, M[1]={m1}, M[2]={m2}")
        
        # Tạo danh sách các giá trị còn lại cho M
        remaining_m = [x for x in range(8) if x not in [m0, m1, m2]]
        
        # Thử tất cả permutations của H với H[0] cố định
        remaining_h = [x for x in range(8) if x != h0]
        
        for h_perm in permutations(remaining_h):
            H = [h0] + list(h_perm)
            
            for m_perm in permutations(remaining_m):
                M = [m0, m1, m2] + list(m_perm)
                
                # Kiểm tra với keystream được tạo
                keystream = generate_keystream(H, M, len(ciphertext))
                
                # Kiểm tra 4 vị trí đã biết
                if (keystream[0] != target_keystream[0] or 
                    keystream[1] != target_keystream[1] or 
                    keystream[2] != target_keystream[2] or
                    keystream[-1] != target_keystream[3]):
                    continue
                
                # Giải mã và kiểm tra tính hợp lệ
                plaintext = []
                valid = True
                
                for i in range(len(ciphertext)):
                    decrypted_byte = ciphertext[i] ^ keystream[i]
                    
                    # Kiểm tra format flag
                    if i == 0 and decrypted_byte != ord('D'):
                        valid = False
                        break
                    elif i == 1 and decrypted_byte != ord('H'):
                        valid = False
                        break
                    elif i == 2 and decrypted_byte != ord('{'):
                        valid = False
                        break
                    elif i == len(ciphertext) - 1 and decrypted_byte != ord('}'):
                        valid = False
                        break
                    elif 3 <= i <= len(ciphertext) - 2 and not is_valid_flag_char(decrypted_byte):
                        valid = False
                        break
                    
                    plaintext.append(decrypted_byte)
                
                if valid:
                    flag = bytes(plaintext).decode('ascii')
                    print(f"\n🎉 FOUND FLAG! 🎉")
                    print(f"H permutation: {H}")
                    print(f"M permutation: {M}")
                    print(f"Flag: {flag}")
                    return flag
    
    print("No valid flag found with optimized method!")
    return None

def solve_bruteforce_backup():
    """Backup brute force method nếu optimized method không work"""
    print("\nFalling back to brute force method...")
    
    with open("flag.txt.enc", "rb") as f:
        ciphertext = f.read()
    
    known_plaintext = b"DH{"
    known_keystream = []
    for i in range(3):
        known_keystream.append(ciphertext[i] ^ known_plaintext[i])
    
    base_list = list(range(8))
    count = 0
    
    for H in permutations(base_list):
        for M in permutations(base_list):
            count += 1
            if count % 100000 == 0:
                print(f"Tried {count} combinations...")
            
            keystream = generate_keystream(H, M, len(ciphertext))
            
            if keystream[:3] != known_keystream:
                continue
            
            # Giải mã và kiểm tra
            plaintext = []
            valid = True
            
            for i in range(len(ciphertext)):
                decrypted_byte = ciphertext[i] ^ keystream[i]
                
                if i == 0 and decrypted_byte != ord('D'):
                    valid = False
                    break
                elif i == 1 and decrypted_byte != ord('H'):
                    valid = False
                    break
                elif i == 2 and decrypted_byte != ord('{'):
                    valid = False
                    break
                elif i == len(ciphertext) - 1 and decrypted_byte != ord('}'):
                    valid = False
                    break
                elif 3 <= i <= len(ciphertext) - 2 and not is_valid_flag_char(decrypted_byte):
                    valid = False
                    break
                
                plaintext.append(decrypted_byte)
            
            if valid:
                flag = bytes(plaintext).decode('ascii')
                print(f"\n🎉 FOUND FLAG! 🎉")
                print(f"H permutation: {H}")
                print(f"M permutation: {M}")
                print(f"Flag: {flag}")
                return flag
            
            # Thoát sớm nếu đã thử quá nhiều
            if count > 10000000:  # Giới hạn 10M combinations
                print("Reached limit, stopping...")
                break
        else:
            continue
        break
    
    return None

if __name__ == "__main__":
    # Thử method tối ưu trước
    result = solve_optimized()
    
    # Nếu không tìm thấy, dùng brute force
    if result is None:
        result = solve_bruteforce_backup()
    
    if result is None:
        print("Could not find the flag!")