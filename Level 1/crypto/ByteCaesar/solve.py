class Caesar:
    def __init__(self, key):
        self._key = key

    def decrypt(self, msg):
        msg_dec = b""
        for b in msg:
            msg_dec = msg_dec + bytes([(b - self._key) % 256])
        return msg_dec

def main():
    ciphertext_hex = "061a17d2252720d2251e21291e2bd225172625d221281724d2261a17d215131e1fded2132c272417d22115171320ded2151325261b2019d213d2281b1424132026d2261322172526242bd22118d215211e212425d2131524212525d2261a17d2251d2be0d205171319271e1e25d225211324d2192413151718271e1e2bd2212817241a171316ded2261a171b24d215131e1e25d217151a211b2019d21b20d2261a17d225131e262bd2142417172c17e0d2f325d2261a17d22913281725d2191720261e2bd21e1322d21319131b202526d2261a17d2251320162bd2251a212417ded213d22517202517d22118d22624132023271b1e1b262bd22913251a1725d221281724d21f17e0d2fbd2181b2016d225211e131517d21b20d2261a1b25d21f211f172026ded213d2221713151718271ed224172624171326d21824211fd2261a17d2142725261e1b2019d22921241e16e0d2001326272417d925d214171327262bd2172028171e212225d21f17ded224171f1b20161b2019d21f17d22118d2261a17d229212016172425d2261a1326d21e1b17d214172b212016d2212724d216131b1e2bd2242127261b201725e0d2fb20d2261a1b25d2251724172017d2251726261b2019ded2fbd2171f1424131517d2261a17d21a13241f21202bd22118d2261a17d222241725172026d2132016d21e1726d21f2bd2292124241b1725d216241b1826d21329132bd2291b261ad2261a17d2261b1617e0d2f81b20131e1e2bded2fbd2181b2016d21f2b25171e18d2251e1717221b2019d2291b261ad2261a17d2181e1319ded2f6fa2de5e914161815eae4e5e7e4e516171513e8e8e515e9e5e913e815e817e4e61815e7e8e31613e61616e7e3e718e2ebe91518ea13e6ea16e6e3e913e51814e615132f"
    
    ciphertext = bytes.fromhex(ciphertext_hex)
    
    print("Trying all possible keys (1-255)...")
    print("="*50)
    
    # Thử tất cả các key từ 1 đến 255
    for key in range(1, 256):
        cipher = Caesar(key)
        decrypted = cipher.decrypt(ciphertext)
        
        try:
            # Thử decode thành text
            decrypted_text = decrypted.decode('utf-8', errors='ignore')
            
            # Kiểm tra xem có chứa flag không (DH{...})
            if 'DH{' in decrypted_text:
                print(f"Key {key}: FOUND FLAG!")
                print(f"Decrypted: {decrypted_text}")
        except:
            continue

if __name__ == "__main__":
    main()
    
"""
Flag: DH{37bdfc823523deca663c737a6c6e24fc561da4dd515f097cf8a48d417a3fb4ca}
Output:
Key 178: FOUND FLAG!
Decrypted: The sun slowly sets over the calm, azure ocean, casting a vibrant tapestry of colors across the sky. Seagulls soar gracefully overhead, their calls echoing in the salty breeze. As the waves gently lap against the sandy shore, a sense of tranquility washes over me. I find solace in this moment, a peaceful retreat from the bustling world. Nature's beauty envelops me, reminding me of the wonders that lie beyond our daily routines. In this serene setting, I embrace the harmony of the present and let my worries drift away with the tide. Finally, I find myself sleeping with the flag, DH{37bdfc823523deca663c737a6c6e24fc561da4dd515f097cf8a48d417a3fb4ca}
"""