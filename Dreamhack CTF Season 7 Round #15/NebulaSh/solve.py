#!/usr/bin/env python3

from pwn import *
from Crypto.Util.number import long_to_bytes, isPrime
from sympy.ntheory.residue_ntheory import discrete_log
from sympy.ntheory.modular import crt
from sympy import factorint

# Thư viện mới cho tấn công LLL
from fpylll import IntegerMatrix, LLL

def manual_pohlig_hellman_dlog(n, base, value, order):
    factors = factorint(order)
    residues, moduli = [], []
    for p, e in factors.items():
        pe = p**e
        order_subgroup = order // pe
        base_sub = pow(base, order_subgroup, n)
        value_sub = pow(value, order_subgroup, n)
        res = discrete_log(n, value_sub, base_sub, order=pe)
        residues.append(res); moduli.append(pe)
    log_result, _ = crt(moduli, residues)
    return log_result

def solve_subset_sum_lll(weights, target, modulus):
    """
    Giải bài toán ba lô tổng dạng module bằng thuật toán LLL.
    Tìm m_i in {0, 1} sao cho: sum(weights[i] * m_i) == target (mod modulus)
    """
    n = len(weights)
    print(f"[+] Solving subset sum for {n} items using LLL...")

    # 1. Xây dựng ma trận cơ sở cho dàn (lattice)
    # Đây là một cấu trúc kinh điển để giải bài toán ba lô bằng LLL
    # Kích thước ma trận: (n + 1) x (n + 1)
    B = IntegerMatrix(n + 1, n + 1)

    # Điền các giá trị vào ma trận
    for i in range(n):
        B[i, i] = 1  # Ma trận đơn vị ở góc trên bên trái
        B[i, n] = weights[i] # Cột cuối cùng là các trọng số
    
    B[n, n] = -modulus # Phần tử cuối cùng là giá trị âm của module

    # 2. Áp dụng thuật toán LLL
    print("[+] Applying LLL reduction to the basis matrix...")
    lll_B = LLL.reduction(B)

    # 3. Tìm vector lời giải
    # Lời giải là một vector ngắn trong dàn có dạng (m_0, m_1, ..., m_{n-1}, target')
    # Chúng ta tìm vector có cột cuối cùng bằng `target` hoặc `-target`
    print("[+] Searching for the solution vector in the reduced basis...")
    for i in range(n + 1):
        # Lấy một vector ngắn từ cơ sở đã được rút gọn
        solution_candidate = lll_B[i]
        
        # Kiểm tra xem nó có phải là lời giải không
        # Điều kiện: cột cuối cùng phải bằng target và các cột khác phải là 0 hoặc 1
        if abs(solution_candidate[n]) == target:
            potential_solution = [abs(solution_candidate[j]) for j in range(n)]
            if all(b in [0, 1] for b in potential_solution):
                print(f"[+] Found solution vector!")
                # Nếu cột cuối là -target, ta cần đảo dấu các bit
                if solution_candidate[n] == -target:
                    return [(1 - b) for b in potential_solution]
                else:
                    return potential_solution
    
    # Một cách tiếp cận khác nếu cách trên không thành công
    # Thử kết hợp tuyến tính các vector ngắn nhất
    for i in range(min(n + 1, 5)): # Chỉ cần xét vài vector ngắn nhất
        for j in range(i, min(n + 1, 5)):
             # v = lll_B[i] +/- lll_B[j]
            for sign in [-1, 1]:
                v = [lll_B[i][k] + sign * lll_B[j][k] for k in range(n+1)]
                if v[n] == target:
                    m = v[:n]
                    if all(b in [0, 1] for b in m):
                        print("[+] Found solution vector (through combination)!")
                        return m

    print("[-] LLL attack failed to find a valid solution vector.")
    return None

def get_solution_indices(solution_bits):
    """Chuyển danh sách các bit giải pháp thành danh sách các chỉ số."""
    indices = []
    for i, bit in enumerate(solution_bits):
        if bit == 1:
            indices.append(i)
    return indices

# --- Hàm solve chính ---
def solve():
    HOST, PORT = "host8.dreamhack.games", 18258
    n = 99549868083198389895697057645039736426037119047457594639088314374717361178856457819384412240064545431452883745055663857843039974753923419031060219487911562119186818110618756882394220955486743953455949647223354563118127375678332286016414894157282108976366200312985153577707154058259579908092108005545567019427
    q = 6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941405973284973216824503168947
    R = 14849536718210520059933571362116753841823690772808664609337546508274987243311356654927024434963181713981880881863152417864508264921285792894824084433401558
    conn = remote(HOST, PORT)
    conn.sendlineafter(b"Give me n: ", str(n).encode())
    conn.sendlineafter(b"Give me a large prime factor of n - 1: ", str(q).encode())
    conn.recvuntil(b"Pubkey: ("); conn.recvuntil(b", ")
    v_str = conn.recvuntil(b"])", drop=True).decode().strip()[1:]
    v = [int(x) for x in v_str.split(", ")]
    conn.recvuntil(b"Encrypted result: "); c_flag = int(conn.recvline().strip().decode())
    c_prime = pow(c_flag, q, n)
    v_prime = [pow(vi, q, n) for vi in v]
    g_subgroup = pow(2, q, n)
    print("[+] Calculating discrete logs using manual Pohlig-Hellman...")
    target_log = manual_pohlig_hellman_dlog(n, g_subgroup, c_prime, R)
    weights_log = [manual_pohlig_hellman_dlog(n, g_subgroup, vi, R) for vi in v_prime]

    # === THAY THẾ MITM BẰNG LLL ===
    solution_bits = solve_subset_sum_lll(weights_log, target_log, R)
    if solution_bits is None:
        print("[-] LLL attack failed."); conn.close(); return

    solution_indices = get_solution_indices(solution_bits)
    # ============================
    
    m = 0
    for i in solution_indices:
        m |= (1 << i)
    plaintext = long_to_bytes(m)
    expected_len = len(v) // 8
    plaintext_padded = plaintext.rjust(expected_len, b'\x00')
    print(f"[+] Reconstructed plaintext (hex): {plaintext_padded.hex()}")
    conn.sendlineafter(b"pt? ", plaintext_padded.hex().encode())
    print("\n[+] Final response from server:")
    flag = conn.recvall(timeout=3).decode()
    print(flag)
    conn.close()

if __name__ == "__main__":
    solve()