Dùng `tshark` để lọc ra data cần thiết
```bash
tshark -r My_PPT.pcapng -Y "usbhid.data" -T fields -e frame.time_epoch -e usbhid.data > data.txt
```

Sau đó chạy code python để tìm ra flag, đây là dạng bài mà flag được mã hóa dưới dạng Morse Code vì đơn giản là khi Wireshark đọc gói tin thì nó ghi nhận các phím được gõ dưới dạng Morse Code.

```python
INPUT_FILE = "data.txt"
TIME_THRESHOLD = 1.0  # Ngưỡng thời gian để ngắt chữ cái (1 giây)

HID_TO_MORSE_MAP = {
    '52': '-',  # Up Arrow -> R -> Gạch
    '51': '.',  # Down Arrow -> Q -> Chấm
}

MORSE_CODE_DICT = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
    '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
    '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
    '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
    '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
    '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
    '...--': '3', '....-': '4', '.....': '5', '-....': '6',
    '--...': '7', '---..': '8', '----.': '9'
}

# --- HÀM GIẢI MÃ ---
def solve():
    print(f"[+] Đang đọc file dữ liệu: {INPUT_FILE}")
    try:
        with open(INPUT_FILE, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"[!] Lỗi: Không tìm thấy file '{INPUT_FILE}'. Hãy chắc chắn bạn đã chạy lệnh tshark ở Bước 1.")
        return

    keypresses = []
    
    # 1. Trích xuất thời gian và mã phím từ file text
    for line in lines:
        parts = line.strip().split('\t')
        if len(parts) != 2:
            continue
        
        timestamp_str, hid_data_str = parts
        
        # Lấy mã phím (byte thứ 3, tức là ký tự thứ 5 và 6)
        keycode = hid_data_str[4:6]
        
        # Chỉ quan tâm đến phím Up/Down và bỏ qua sự kiện "thả phím" (keycode là 00)
        if keycode in HID_TO_MORSE_MAP:
            keypresses.append({
                'time': float(timestamp_str),
                'keycode': keycode
            })

    if not keypresses:
        print("[!] Không tìm thấy dữ liệu phím bấm Up/Down trong file.")
        return

    print(f"[+] Tìm thấy {len(keypresses)} lần bấm phím Up/Down.")

    # 2. Xây dựng chuỗi Morse dựa trên thời gian trễ
    morse_letters = []
    current_morse_letter = ""
    
    if not keypresses:
        return

    last_time = keypresses[0]['time']

    for press in keypresses:
        delta = press['time'] - last_time
        
        if delta > TIME_THRESHOLD and current_morse_letter:
            morse_letters.append(current_morse_letter)
            current_morse_letter = ""
        
        current_morse_letter += HID_TO_MORSE_MAP[press['keycode']]
        last_time = press['time']
        
    if current_morse_letter:
        morse_letters.append(current_morse_letter)

    print(f"[+] Chuỗi Morse đã phân tách: {' '.join(morse_letters)}")

    # 3. Dịch chuỗi Morse sang văn bản
    decoded_text = ""
    for letter in morse_letters:
        if letter in MORSE_CODE_DICT:
            decoded_text += MORSE_CODE_DICT[letter]
        else:
            decoded_text += '?'

    print("\n" + "="*40)
    print(f"[*] KẾT QUẢ GIẢI MÃ: {decoded_text}")
    print("="*40)

# --- CHẠY CHƯƠNG TRÌNH CHÍNH ---
if __name__ == "__main__":
    solve()
```

Flag: `KHK{LOOK_AT_MY_PPT}`