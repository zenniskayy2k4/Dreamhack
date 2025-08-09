import socket
from custom_random_2048 import CustomRandom2048

HOST = "host8.dreamhack.games"
PORT = 11080

MASK_64 = (1 << 64) - 1
C1 = 0xCAFEBABE12345678
C2 = 0x1337DEADBEEF

# Các hàm phụ trợ
def get_bit(n, k):
    return (n >> k) & 1

def set_bit(n, k, v):
    if v == 1:
        return n | (1 << k)
    else:
        return n & ~(1 << k)

# Hàm kết nối và lấy answer giữ nguyên từ phiên bản trước (đã chạy tốt)
def connect_and_get_answer(session_id_to_check):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        all_data_received = b""
        s.settimeout(12)
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk: break
                all_data_received += chunk
        except socket.timeout: pass
        response_text = all_data_received.decode(errors='ignore')
        current_session_id = -1
        for line in response_text.split('\n'):
            if "You are session #" in line:
                current_session_id = int(line.split('#')[1].strip())
                break
        if current_session_id != session_id_to_check:
            print(f"[!] Lỗi: Yêu cầu session #{session_id_to_check} nhưng server trả về #{current_session_id}.")
            return None
        print(f"[+] Đã ở session #{current_session_id}. Đang trích xuất answer...")
        answer_str_list = response_text.split("The answer was:\n")
        if len(answer_str_list) > 1:
            answer_str = answer_str_list[-1].strip()
            try:
                answer = int(answer_str)
                if answer.bit_length() > 2000:
                    print(f"[+] Lấy được answer cho session #{current_session_id}")
                    return answer
                else: return None
            except: return None
        else: return None

def split_to_blocks(n, nbits=2048, block_size=64):
    blocks = []
    for i in range(nbits // block_size):
        block = (n >> (64 * (31 - i))) & MASK_64
        blocks.append(block)
    return blocks

# HÀM KHÔI PHỤC STATE ĐÚNG
def recover_states_from_outputs(outs):
    """
    Khôi phục lại toàn bộ 2048 bit state gốc từ 2048 bit output.
    Đây là thuật toán lặp bit-by-bit chính xác.
    """
    S = [0] * 32  # Mảng chứa các state gốc S_i

    # Vòng lặp khôi phục từng bit một, từ k=0 đến 63
    for k in range(64):
        # 1. Tính bit thứ k cho S_0 đến S_30
        # Phương trình: S_i[k] = out_i[k] ^ S_{i+1}[k-13]
        # Chúng ta phải tính ngược từ i=30 về 0 để đảm bảo S_{i+1} đã được tính.
        for i in range(30, -1, -1):
            out_i_k = get_bit(outs[i], k)
            
            new_s_i_k = 0
            if k < 13:
                new_s_i_k = out_i_k
            else:
                s_i_plus_1_k_minus_13 = get_bit(S[(i + 1)], k - 13)
                new_s_i_k = out_i_k ^ s_i_plus_1_k_minus_13
            
            S[i] = set_bit(S[i], k, new_s_i_k)

        # 2. Tính bit thứ k cho S_31
        # Phương trình: S_{31}[k] = out_{31}[k] ^ S'_{0}[k-13]
        # Ta cần tính S'_0[k-13]
        out_31_k = get_bit(outs[31], k)
        
        new_s_31_k = 0
        if k < 13:
            new_s_31_k = out_31_k
        else:
            # Tính S'_0 = ((S_0 + S_1 + C1) ^ C2)
            # Chúng ta chỉ cần các bit <= k-13 của S_0 và S_1 (đã được tính)
            # để tính được bit k-13 của S'_0
            s_prime_0 = ((S[0] + S[1] + C1) ^ C2) & MASK_64
            s_prime_0_k_minus_13 = get_bit(s_prime_0, k - 13)
            new_s_31_k = out_31_k ^ s_prime_0_k_minus_13

        S[31] = set_bit(S[31], k, new_s_31_k)
    
    return S

# Hàm get_flag giữ nguyên từ phiên bản trước
def get_flag(init_seed):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        initial_data = b""
        s.settimeout(5)
        try:
            while b"Guess the 2048-bit number: " not in initial_data:
                chunk = s.recv(4096)
                if not chunk: break
                initial_data += chunk
        except socket.timeout:
            print("[!] Lỗi: Timeout khi đang chờ banner trong lần kết nối cuối cùng.")
            return
        resp_text = initial_data.decode(errors='ignore')
        session_id = -1
        for line in resp_text.split('\n'):
            if "You are session #" in line:
                session_id = int(line.split('#')[1].strip())
                break
        if session_id == -1:
            print("[!] Không thể lấy được session_id cuối cùng.")
            return
        print(f"[+] Kết nối lần cuối, session_id của chúng ta là: #{session_id}")
        current_seed = init_seed + session_id
        rng = CustomRandom2048(current_seed)
        my_answer = rng.getrandbits(2048)
        print(f"[*] Gửi đáp án đã tính...")
        s.sendall(f"{my_answer}\n".encode())
        flag_resp = s.recv(4096).decode(errors='ignore')
        print("\n" + "="*20 + " SERVER RESPONSE " + "="*20)
        print(flag_resp)
        print("="*57)

# --- Chương trình chính ---
if __name__ == "__main__":
    print("[*] Thử reset server để đảm bảo bắt đầu từ session 0...")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.sendall(b'reset\n')
            s.recv(4096)
            print("[+] Server đã được reset.")
    except:
        print("[!] Không reset được server hoặc không cần thiết.")

    answer0 = connect_and_get_answer(0)
    if answer0 is None:
        print("[!] Không thể lấy được answer cho session 0. Dừng lại.")
        exit()

    outs0 = split_to_blocks(answer0)
    
    print("[*] Bắt đầu khôi phục state từ answer của session 0...")
    recovered_states = recover_states_from_outputs(outs0)
    
    init_seed = 0
    for s in recovered_states:
        init_seed = (init_seed << 64) | s
    
    print(f"\n[SUCCESS] Đã khôi phục INIT_SEED: {init_seed}\n")
    
    # Kiểm tra lại xem seed đã khôi phục có đúng không
    print("[*] Đang kiểm tra lại INIT_SEED đã khôi phục...")
    rng_check = CustomRandom2048(init_seed)
    answer_check = rng_check.getrandbits(2048)
    if answer_check == answer0:
        print("[+] Kiểm tra thành công! INIT_SEED là chính xác.")
        get_flag(init_seed)
    else:
        print("\n[!!!] Tấn công thất bại. Seed khôi phục không tạo ra answer đúng. Logic vẫn còn lỗi.")