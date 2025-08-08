from PIL import Image
import zlib
import base64

im = Image.open("flag.png")
pixels = im.load()
width, height = im.size

# Extract the LSB (Least Significant Bit) from each color channel (R,G,B).
binary_string = ""
for y in range(height):
    for x in range(width):
        r, g, b = pixels[x, y]
        binary_string += str(r & 1)
        binary_string += str(g & 1)
        binary_string += str(b & 1)

# Convert the binary string back to bytes.
all_bytes = bytearray()

for i in range(0, len(binary_string), 8):
    byte_chunk = binary_string[i:i+8]
    if len(byte_chunk) == 8:
        all_bytes.append(int(byte_chunk, 2))
    else:
        break

# Decode from Base64
xor_encrypted_data = base64.b64decode(zlib.decompress(all_bytes))

# Decrypt with the XOR key
key = 0x55
decrypted_flag = bytes([b ^ key for b in xor_encrypted_data])

print(f"The flag is: {decrypted_flag.decode()}")