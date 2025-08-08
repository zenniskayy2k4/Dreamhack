# File: generate_prime.py
import random
import sys
from Crypto.Util.number import isPrime
from sympy import sieve

def generate_special_prime_robust(n_bits, q_bits, smoothness_bound, max_attempts_per_r=100000):
    """
    Tìm kiếm một cách mạnh mẽ bộ ba số nguyên tố (n, q, R) thỏa mãn:
    - n là số nguyên tố n_bits
    - q là số nguyên tố q_bits
    - n - 1 = q * R
    - R là một số B-trơn (B = smoothness_bound)
    """
    print(f"[+] Bắt đầu tìm kiếm (n_bits={n_bits}, q_bits={q_bits})...")
    print(f"[i] Việc này có thể mất vài phút. Hãy kiên nhẫn.")
    
    target_R_bits = n_bits - q_bits
    # Tạo một danh sách các số nguyên tố nhỏ để xây dựng R
    primes = list(sieve.primerange(2, smoothness_bound))

    # Vòng lặp ngoài: Tạo R mới nếu R cũ không may mắn
    while True:
        # 1. Tạo số trơn R
        R = 1
        while R.bit_length() < target_R_bits:
            R *= random.choice(primes)

        # 2. Tính toán điểm bắt đầu hợp lý cho k (ứng cử viên của q)
        k_start = (1 << (n_bits - 1)) // R
        if k_start.bit_length() < q_bits:
            k_start = 1 << (q_bits - 1)
        if k_start % 2 == 0:
            k_start += 1
        
        k = k_start
        print(f"\n[+] Đã tạo R mới. Bắt đầu tìm kiếm k từ {hex(k)}...")

        # 3. Vòng lặp trong: Tìm kiếm k với giới hạn số lần thử
        for attempt in range(max_attempts_per_r):
            # In ra chỉ báo tiến trình để biết chương trình không bị treo
            if attempt % 5000 == 0:
                sys.stdout.write(f"\r[.] Đã thử {attempt}/{max_attempts_per_r} lần cho R này...")
                sys.stdout.flush()

            n = k * R + 1
            if n.bit_length() > n_bits:
                break # k đã quá lớn, R này không tốt.

            # Kiểm tra isPrime(k) trước vì nó nhỏ hơn và nhanh hơn
            if k.bit_length() == q_bits and isPrime(k):
                # Nếu k là số nguyên tố, mới kiểm tra n
                if isPrime(n):
                    print(f"\n\n[SUCCESS] Tìm thấy bộ ba hợp lệ sau {attempt} lần thử!")
                    return n, k, R
            
            k += 2 # Chỉ kiểm tra các số lẻ
            
        print(f"\n[!] Không tìm thấy sau {max_attempts_per_r} lần thử. Tạo R mới.")

if __name__ == "__main__":
    N_BITS = 1024
    Q_BITS = 512
    SMOOTHNESS_BOUND = 2**14 # Giới hạn cho các thừa số nguyên tố của R

    n, q, R = generate_special_prime_robust(N_BITS, Q_BITS, SMOOTHNESS_BOUND)

    print("\n" + "="*50)
    print("COPY CÁC GIÁ TRỊ SAU VÀO SCRIPT solve.py CỦA BẠN:")
    print("="*50 + "\n")
    print(f"n = {n}\n")
    print(f"q = {q}\n")
    print(f"R = {R}\n")
    print("="*50)