# EZ-Random

## I. Giới thiệu và Phân tích ban đầu (Initial Analysis)

Bài challenge có tên "EZ-Random" với mô tả "Uh.. Is this a brute force problem?". Đề bài cung cấp hai file mã nguồn: `server.py` và `custom_random_2048.py`. Mục tiêu là kết nối đến server, đoán đúng một số ngẫu nhiên 2048-bit để nhận được flag.

**Phân tích `server.py`:**
1.  **Luồng hoạt động:** Server tạo một `INIT_SEED` 2048-bit ngẫu nhiên khi khởi động. Mỗi khi một client kết nối, nó sẽ nhận một `session_id` tăng dần (0, 1, 2,...).
2.  **Tạo số ngẫu nhiên:** Seed thực tế để tạo số ngẫu nhiên cho client được tính bằng `current_seed = INIT_SEED + session_id`.
3.  **Lộ thông tin:** Server gửi `session_id` cho client. Nếu client chờ timeout hoặc gõ `giveup`, server sẽ tiết lộ `answer` (số ngẫu nhiên 2048-bit) của session đó.
4.  **Mục tiêu:** Nhiệm vụ của chúng ta là tìm ra `INIT_SEED`. Nếu có nó, ta có thể kết nối, nhận `session_id`, tự tính `answer` và gửi lại để lấy flag.

**Phân tích `custom_random_2048.py`:**
1.  **`__init__(seed)`:** Hàm khởi tạo chia `seed` 2048-bit thành 32 "trạng thái" (state) con, mỗi state 64-bit, lưu trong `self.state`. `state[0]` là 64 bit cao nhất, `state[31]` là 64 bit thấp nhất.
2.  **`next()`:** Hàm này tạo ra một số 64-bit.
    *   `out = state[p] ^ (state[p+1] << 13)`
    *   Sau đó, nó cập nhật `state[p]` bằng một công thức phức tạp hơn: `state[p] = ((state[p] + state[p+1] + C1) ^ C2)`.
3.  **`getrandbits()`:** Gọi `next()` 32 lần và ghép 32 kết quả 64-bit lại để tạo thành `answer` 2048-bit.

## II. Các hướng tiếp cận sai lầm và tại sao chúng thất bại

Quá trình giải quyết bài toán này là một chuỗi các giả định và sửa lỗi.

**Lập luận sai lầm #1: So sánh hai session và brute-force state cuối cùng**

*   **Giả định:** Chúng ta có thể kết nối 2 lần liên tiếp để lấy `answer_0` (từ `seed_0 = INIT_SEED`) và `answer_1` (từ `seed_1 = INIT_SEED + 1`). Vì `seed_0` và `seed_1` chỉ khác nhau ở 64 bit cuối, nên `state_0[31]` và `state_1[31]` chỉ khác nhau 1 đơn vị, còn 31 state đầu tiên là giống hệt nhau.
*   **Kế hoạch:**
    1.  Giả định rằng có thể tái tạo lại toàn bộ `state` nếu biết `state[31]` và các `output`.
    2.  Brute-force `state_0[31]` (giả sử nó là một số nhỏ).
    3.  Với mỗi giá trị thử, tính ngược lại `state_0` và `state_1`.
    4.  Kiểm tra xem 31 state đầu của chúng có khớp nhau không. Nếu khớp, ta đã tìm thấy `state_0[31]` đúng và suy ra được `INIT_SEED`.
*   **Tại sao thất bại:** Giả định ở bước 1 đã sai. Phép toán `out = s0 ^ (s1 << 13)` **không thể đảo ngược một cách đơn giản** để tìm `s1` từ `s0` và `out`. Phép dịch phải `>> 13` để tìm `s1` sẽ làm mất thông tin. Do đó, hàm `reconstruct_state` ban đầu đã sai, dẫn đến việc brute-force không bao giờ tìm thấy kết quả đúng.

**Lập luận sai lầm #2: Brute-force trực tiếp `INIT_SEED`**

*   **Giả định:** Sau khi nhận ra logic tái tạo state bị sai, chúng ta quay về hướng đơn giản nhất: brute-force `INIT_SEED`. Giả định rằng `INIT_SEED` có thể là một số nhỏ (ví dụ, nằm trong khoảng 2^32).
*   **Kế hoạch:**
    1.  Lấy `answer_0` và `answer_1`.
    2.  Lặp qua các giá trị `seed_guess` từ 0.
    3.  Với mỗi `seed_guess`, tính `answer_guess_0 = F(seed_guess)` và `answer_guess_1 = F(seed_guess + 1)`.
    4.  Nếu cả hai `answer` giả định khớp với `answer` thực tế, ta đã tìm thấy `INIT_SEED`.
*   **Tại sao thất bại:** Thời gian chạy quá lâu. `INIT_SEED` được tạo bởi `os.urandom(256)`, nó thực sự là một số 2048-bit ngẫu nhiên và không có lý do gì để tin rằng nó là một số nhỏ. Việc brute-force, ngay cả với 32 bit, cũng quá chậm và không khả thi trong thời gian của một cuộc thi CTF.

## III. Hướng đi đúng: Phân tích cấu trúc Bit và Khôi phục lặp

Sau khi các phương pháp trên thất bại, chúng ta cần phải xem xét lại bản chất của thuật toán PRNG. Điểm yếu thực sự nằm trong cấu trúc của phép toán tạo output.

**Bước đột phá trong suy luận:**

1.  **Phân tích phương trình `next()`:**
    *   `out_i = S_i ^ (S_{i+1} << 13)` (với `S` là state gốc).
    *   Khi xem xét ở cấp độ bit, ta có:
        *   Nếu `k < 13`: `S_i[k] = out_i[k]`.
        *   Nếu `k >= 13`: `S_i[k] = out_i[k] ^ S_{i+1}[k-13]`.

2.  **Khôi phục có thứ tự:**
    *   Từ `S_i[k] = out_i[k]` (với `k < 13`), chúng ta có thể biết ngay lập tức **13 bit thấp nhất** của tất cả 32 state gốc (`S_0` đến `S_31`) chỉ bằng cách nhìn vào 13 bit thấp nhất của 32 `output` tương ứng.
    *   Bây giờ, hãy xét bit thứ 13 (`k=13`). Phương trình là `S_i[13] = out_i[13] ^ S_{i+1}[0]`. Vì chúng ta đã biết tất cả các bit 0 (từ bước trên), chúng ta có thể tính được tất cả các bit 13.
    *   Tiếp tục với bit 14 (`k=14`): `S_i[14] = out_i[14] ^ S_{i+1}[1]`. Chúng ta cũng đã biết tất cả các bit 1, nên ta có thể tính được tất cả các bit 14.
    *   Cứ lặp lại như vậy, để tính bit thứ `k`, chúng ta chỉ cần các bit `k-13` mà chúng ta đã tính ở các vòng lặp trước đó.

3.  **Xử lý trường hợp đặc biệt `out_31`:**
    *   Phương trình cho `out_31` phức tạp hơn: `out_31 = S_{31} ^ (S'_{0} << 13)`, trong đó `S'_{0} = ((S_0 + S_1 + C1) ^ C2)`.
    *   Tuy nhiên, khi chúng ta đang tính bit thứ `k` của `S_{31}`, chúng ta chỉ cần bit `k-13` của `S'_{0}`.
    *   Để tính được bit `k-13` của `S'_{0}`, chúng ta chỉ cần các bit `< k-13` của `S_0` và `S_1` (để xử lý phép cộng và bit nhớ). Tất cả các bit này đều đã được tính ở các vòng lặp trước đó.

4.  **Kết luận cuối cùng:** Chúng ta có thể xây dựng một thuật toán lặp, bắt đầu từ bit 0 và đi lên đến bit 63, để khôi phục lại hoàn toàn 2048 bit của `INIT_SEED` từ `answer` của chỉ một session duy nhất. Thuật toán này không cần brute-force và chạy gần như tức thì.

## IV. Các bước giải quyết cuối cùng

1.  **Kết nối lần 1:** Reset server, sau đó kết nối và chờ timeout để lấy `answer` của `session_id=0`.
2.  **Tách `answer`:** Chia `answer` 2048-bit thành một danh sách 32 `output` 64-bit.
3.  **Chạy thuật toán khôi phục:** Sử dụng hàm `recover_states_from_outputs` (được xây dựng dựa trên logic ở mục III) để tính lại 32 state gốc.
4.  **Ghép `INIT_SEED`:** Nối 32 state gốc lại với nhau để có được `INIT_SEED` 2048-bit.
5.  **(Tùy chọn nhưng nên làm) Kiểm tra:** Tự tạo một đối tượng `CustomRandom2048` với `INIT_SEED` vừa tìm được, gọi `getrandbits()` và so sánh kết quả với `answer` ban đầu để chắc chắn logic là đúng.
6.  **Kết nối lần cuối và lấy Flag:** Kết nối lại server, nhận `session_id` mới (ví dụ là `#1` hoặc `#2`), tính `current_seed = INIT_SEED + session_id`, tự tính `answer` chính xác, gửi nó cho server và nhận flag.

## V. Script
```python
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
```