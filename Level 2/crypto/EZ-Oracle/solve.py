# File: solve.py
import socket
from Crypto.Util.number import inverse, long_to_bytes

# --- Các hàm tiện ích để giao tiếp với server ---
def recv_until(s, delim):
    buf = b""
    while not buf.endswith(delim):
        buf += s.recv(1)
    return buf

def get_server_params(s):
    n_line = recv_until(s, b'\n').decode().strip()
    e_line = recv_until(s, b'\n').decode().strip()
    c_line = recv_until(s, b'\n').decode().strip()
    
    n = int(n_line.split(' : ')[1])
    e = int(e_line.split(' : ')[1])
    ciphertext = int(c_line.split(' : ')[1])
    
    # Đọc phần còn lại cho đến khi thấy prompt "> "
    recv_until(s, b'> ')
    
    return n, e, ciphertext

# --- Script chính ---
HOST, PORT = "host1.dreamhack.games", 18262

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    print(f"[*] Connecting to {HOST}:{PORT}...")
    s.connect((HOST, PORT))
    print("[*] Connected!")

    # BƯỚC 1: Lấy các tham số từ server local
    n, e, ciphertext = get_server_params(s)
    print(f"n = {n}")
    print(f"e = {e}")
    print(f"c = {ciphertext}")

    # BƯỚC 2: Phân tích n ra thừa số nguyên tố
    # Bạn cần chạy server.py, copy giá trị n in ra, dán vào FactorDB
    # Sau đó copy kết quả p, q vào đây.
    # LƯU Ý: Mỗi lần chạy lại server.py, n, p, q sẽ thay đổi!
    # Bạn sẽ phải làm lại bước này mỗi khi test.
    p_str = input("Enter p: ")
    q_str = input("Enter q: ")
    p = int(p_str)
    q = int(q_str)

    if p * q != n:
        print("[!] ERROR: p * q does not equal n. Please check your factors.")
        exit()
    
    print("[+] Factorization correct!")

    # BƯỚC 3: Tính khóa bí mật d
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    print(f"[*] Private key d calculated.")

    # BƯỚC 4: Giải mã và lấy flag
    padded_message_int = pow(ciphertext, d, n)
    k = (n.bit_length() + 7) // 8
    padded_message_bytes = long_to_bytes(padded_message_int, k)
    
    # Tách flag ra khỏi padding
    separator_index = padded_message_bytes.find(b'\x00', 2)
    flag = padded_message_bytes[separator_index + 1:]
    
    print(f"[*] Found Flag: {flag.decode()}")
    
    # BƯỚC 5: Gửi flag để xác nhận
    print("[*] Submitting the flag to the local server...")
    submit_command = f"submit {flag.hex()}\n".encode()
    s.sendall(submit_command)
    
    response = recv_until(s, b'\n').decode().strip()
    print(f"[*] Server response: {response}")

    if "Correct" in response:
        print("\n[SUCCESS] The script works correctly!")
    else:
        print("\n[FAILURE] Something went wrong.")