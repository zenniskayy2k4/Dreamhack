# --- Bước 1: Thiết lập môi trường và dữ liệu ---

p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
Zp = Zmod(p)

# Chuyển đổi các tham số đường cong sang Zp
E_a = Zp(0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc)
E_b = Zp(0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b)

# Bộ dữ liệu 1
a1 = Zp(27714350255388021111232531170591641212949833102971307193980499863801255688154)
b1 = Zp(46284378768605864622170543556599427573485337746700029009471119922484581943469)
c1 = Zp(60647595877197062890203383385574231236668829536178956561727275653380079298295)
d1 = Zp(82566598899232397169905495928712993370226968781169912617729109115055982292654)

# Bộ dữ liệu 2
a2 = Zp(66685775596410543041483496379768749621617386544202895231662933335573761066984)
b2 = Zp(24293856516706702970952028821050887716345151887846419189741989582569242079317)
c2 = Zp(5544069395933034652167871260816830292182111986234313654127458493687089162323)
d2 = Zp(35676905401837729400864551915248562488714964484188718193693644401814797799759)

# --- Bước 2: Xây dựng phương trình đa thức (Không thay đổi) ---

P.<k1> = PolynomialRing(Zp)

xp1 = a1 * k1 + b1
xp2 = a2 * k1 + b2

def num(x):
    return (3*x^2 + E_a)^2

def den(x):
    return 4 * (x^3 + E_a*x + E_b)

LHS = c2 * (num(xp1) - (2*xp1 + d1)*den(xp1)) * den(xp2)
RHS = c1 * (num(xp2) - (2*xp2 + d2)*den(xp2)) * den(xp1)

final_poly = LHS - RHS

# --- Bước 3: Giải phương trình và tìm flag (Không thay đổi) ---

solutions = final_poly.roots(multiplicities=False)
print(f"[*] Đã tìm thấy các nghiệm cho key1: {solutions}")

for key1_sol in solutions:
    # key1_sol đã là một phần tử của Zp, không cần ép kiểu nữa
    
    xp_val = a1 * key1_sol + b1
    # Bây giờ tất cả các phép toán đều là modulo p
    xq_val = num(xp_val) * den(xp_val)^-1 - 2*xp_val
    key2_sol = (xq_val - d1) * c1^-1
    
    print(f"\n[+] Thử nghiệm key1 = {int(key1_sol)}")
    print(f"    => Tính được key2 = {int(key2_sol)}")
    
    flag_key = int(key1_sol) ^^ int(key2_sol)
    
    print("\n--- FLAG ---")
    print(f"Flag is DH{{{flag_key:064x}}}")