import itertools

# Bảng leet-speak
leet_map = {
    't': ['t','7','+',"']['",'†','"|"' ,'~|~'],
    'h': ['h','#','/-/','[-',']-[',')-(','(-',':-:','|~|','|-|',']~[','}{','!-!','1-1','\\-/','I+I','/-\\'],
    'e': ['e','3','&','£','€','ë','[-','|=-'],
    'i': ['i','1','[]','|','!','eye','3y3',']['],
    's': ['s','5','$','z','§','ehs','es','2'],
    'k': ['k','>|','|<','/<','1<','|c','|(','|{'],
    'y': ['y','j','`/','Ч','7','\\|/','¥','\\//']
}

def all_leet(word):
    sets = [leet_map[ch.lower()] for ch in word]
    return [''.join(p) for p in itertools.product(*sets)]

# Sinh các biến thể của "the" và "iskey"
the_variants = all_leet("the")
iskey_variants = all_leet("iskey")

# Dữ liệu puzzle
puzzle = "4448175452265f0367565e360a6c583670214532507c252f63155f2c671c2f59046d10525a344e0623734f517a2f55641877355f386a06063875564369085f016034535b2467614e0f73131604163b5845314f17620346375a7b11162d6146261f633029617c583d7e7c586b24690c54041f4f016126505e2629566e6a3c4f57"

# Giải XOR lần 1 để lấy dream
puzzle_numeric = int(puzzle, 16)
dream_key = "DH{}"
extended_dream_key = dream_key * 32
extended_dream_key_numeric = int.from_bytes(extended_dream_key.encode(), 'big')
xor_for_dream = puzzle_numeric ^ extended_dream_key_numeric
dream = ''.join(chr(byte) for byte in xor_for_dream.to_bytes((xor_for_dream.bit_length() + 7) // 8, 'big'))

print("[*] DREAM:\n", dream, "\n")

# Tìm biến thể xuất hiện trong dream
start_found = None
end_found = None

for start in the_variants:
    if start in dream:
        start_found = start
        print(f"[+] Found LEET_START_STRING: {start}")
        break

for end in iskey_variants:
    if end in dream:
        end_found = end
        print(f"[+] Found LEET_END_STRING: {end}")
        break

# Hàm giải password
def find_password(puzzle, LEET_START_STRING, LEET_END_STRING):
    puzzle_numeric = int(puzzle, 16)
    dream_key = "DH{}"
    extended_dream_key = dream_key * 32
    extended_dream_key_numeric = int.from_bytes(extended_dream_key.encode(), 'big')
    xor_for_dream = puzzle_numeric ^ extended_dream_key_numeric
    dream = ''.join(chr(byte) for byte in xor_for_dream.to_bytes((xor_for_dream.bit_length() + 7) // 8, 'big'))
    pw_key = dream.split(LEET_START_STRING, 1)[-1].split(LEET_END_STRING, 1)[0]
    extended_pw_key = pw_key * 32
    extended_pw_key_numeric = int.from_bytes(extended_pw_key.encode(), 'big')
    xor_for_password = puzzle_numeric ^ extended_pw_key_numeric
    password_raw = ''.join(chr(byte) for byte in xor_for_password.to_bytes((xor_for_password.bit_length() + 7) // 8, 'big'))
    password = ''.join(char for char in password_raw if char.isalnum())
    return password

# Giải flag
if start_found and end_found:
    password = find_password(puzzle, start_found, end_found)
    print(f"[FLAG] DH{{{password}}}")
else:
    print("[-] Không tìm thấy biến thể phù hợp!")