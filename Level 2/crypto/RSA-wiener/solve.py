from Crypto.Util.number import long_to_bytes, isPrime
from Crypto.PublicKey import RSA
import gmpy2 # Cần cài đặt thư viện gmpy2: pip install gmpy2

def continued_fraction_convergents(n, d):
    """
    Tính các hội tụ của liên phân số cho n/d.
    Trả về một generator cho các cặp (tử số, mẫu số).
    """
    a_list = []
    while d != 0:
        a = n // d
        n, d = d, n % d
        a_list.append(a)

    numerator_p, denominator_q = 1, 0
    prev_p, prev_q = 0, 1
    
    for a in a_list:
        p = a * numerator_p + prev_p
        q = a * denominator_q + prev_q
        prev_p, prev_q = numerator_p, denominator_q
        numerator_p, denominator_q = p, q
        yield (p, q)

def wiener_attack(e, N, c):
    """
    Thực hiện Wiener's Attack với phương pháp kiểm tra mạnh mẽ hơn.
    e: public exponent
    N: modulus
    c: ciphertext
    """
    print("[*] Starting Wiener's Attack...")
    
    # Tính các hội tụ của e/N
    convergents = continued_fraction_convergents(e, N)
    
    for k, d in convergents:
        # Bỏ qua trường hợp d = 0 hoặc k = 0
        if d == 0 or k == 0:
            continue
            
        # 1. Kiểm tra xem (e*d - 1) có chia hết cho k không
        if (e * d - 1) % k != 0:
            continue
            
        # 2. Tính phi(N) ứng viên
        phi_N = (e * d - 1) // k
        
        # 3. Giải phương trình bậc hai: x^2 - (N - phi_N + 1)x + N = 0
        # S = p + q = N - phi_N + 1
        S = N - phi_N + 1
        
        # Delta = S^2 - 4N
        delta = S*S - 4*N
        
        # 4. Kiểm tra xem delta có phải là số chính phương không
        if delta >= 0:
            # Dùng gmpy2.is_square() để kiểm tra hiệu quả
            is_sq, root_delta = gmpy2.isqrt_rem(delta)
            if root_delta == 0:
                # Nếu là số chính phương, ta đã tìm thấy d
                print(f"\n[+] Attack successful! Found a valid d.")
                print(f"    Found private key d = {d}")
                
                # Giải mã flag với d vừa tìm được
                m = pow(c, d, N)
                flag = long_to_bytes(m)
                print(f"    Flag: {flag.decode(errors='ignore')}")
                return flag

    print("\n[-] Attack failed. The private key 'd' may not be small enough.")
    return None

if __name__ == '__main__':
    # Cài đặt thư viện gmpy2 nếu chưa có
    try:
        import gmpy2
    except ImportError:
        print("[-] gmpy2 is not installed. Please run: pip install gmpy2")
        exit()

    # Đọc khóa công khai từ file PEM
    try:
        with open('public_key.pem', 'r') as f:
            key_pem = f.read()
        
        pub_key = RSA.import_key(key_pem)
        N = pub_key.n
        e = pub_key.e
    except FileNotFoundError:
        print("[-] Error: public_key.pem not found in the current directory.")
        exit()

    # Đọc ciphertext từ file flag.txt
    try:
        with open('flag.txt', 'r') as f:
            c = int(f.read().strip(), 16)
    except FileNotFoundError:
        print("[-] Error: flag.txt not found in the current directory.")
        exit()

    print(f"N = {N}")
    print(f"e = {e}")
    print(f"c = {hex(c)}")
    
    wiener_attack(e, N, c)