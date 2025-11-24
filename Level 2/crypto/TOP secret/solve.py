from Crypto.Util.number import long_to_bytes
import gmpy2

e = 5
N = 24778450034785355796150191255487074823099958164427517612668815658468206009158475774203229828058652831641389747402272728790787685762568229069520469756247804941312947307153713830371750706901868389560472732254665749033734649996443767231968425511092244591774647092925931126950380935008196052393893271837275626174525444417778170526468251066473481105512939105882134615031671691748551289394109269703632798650982887859648332846094423809290782207835604174269463315884480062803289020119565250762542625596177768616201281918850432872639983965071018579891448754659608103400036049016809640134053891855019010729470727777892901808607
enc1 = 25889043021335548821260878832004378483521260681242675042883194031946048423533693101234288009087668042920762024679407711250775447692855635834947612028253548739678779
# Nối chuỗi enc2 bị ngắt dòng
enc2_str = "332075826660041992234163956636404156206918624"
enc2 = int(enc2_str)

# --- Bước 1: Khôi phục khóa Vigenère từ enc2 ---
# Vì m_key^e < N, nên enc2 = m_key^e. Ta chỉ cần tính căn bậc e.
# Sử dụng gmpy2.iroot(n, k) để tính căn bậc k của n
m_key, is_perfect_root = gmpy2.iroot(enc2, e)

if not is_perfect_root:
    print("[-] Không thể tìm thấy căn bậc 5 hoàn hảo. Tấn công thất bại.")
else:
    print("[+] Tìm thấy giá trị số nguyên của khóa (m_key):", m_key)
    
    # Chuyển m_key về dạng bytes
    # Phải chỉ định độ dài (4 bytes) để đảm bảo không mất byte 0 ở đầu nếu có
    vigenere_key = long_to_bytes(int(m_key))
    print(f"[+] Khóa Vigenère đã khôi phục (dạng bytes): {vigenere_key}")
    print(f"[+] Độ dài khóa: {len(vigenere_key)} bytes")

    # --- Bước 2: Giải mã Vigenère để tìm FLAG ---
    # Chuyển enc1 về dạng bytes
    vigenere_ciphertext = long_to_bytes(enc1)
    
    def vigenere_decrypt(ciphertext, key):
        decrypted_msg = b""
        key_len = len(key)
        for i in range(len(ciphertext)):
            # Phép giải mã là phép trừ modulo 256
            dec_char = (ciphertext[i] - key[i % key_len]) % 256
            decrypted_msg += bytes([dec_char])
        return decrypted_msg

    # Giải mã
    flag = vigenere_decrypt(vigenere_ciphertext, vigenere_key)
    
    print("\n[+] FLAG:", flag.decode())