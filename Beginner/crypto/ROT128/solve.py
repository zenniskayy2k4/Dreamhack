hex_list = [(hex(i)[2:].zfill(2).upper()) for i in range(256)]

with open('encfile', 'r', encoding='utf-8') as f:
    enc_data = f.read()
    
enc_chunks = [enc_data[i:i+2] for i in range(0, len(enc_data), 2)]

dec_list = []
for hex_val in enc_chunks:
    index = hex_list.index(hex_val)
    dec_list.append(hex_list[(index - 128) % len(hex_list)])
    
dec_bytes = bytes.fromhex(''.join(dec_list))

with open('flag.png', 'wb') as f:
    f.write(dec_bytes)