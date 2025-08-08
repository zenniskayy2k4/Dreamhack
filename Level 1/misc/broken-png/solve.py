with open('image.png', 'rb') as f:
    data = bytearray(f.read())

# In PNG, width is at position 16 (4 bytes), height is at position 20 (4 bytes)
# Get the width value...
width_bytes = data[16:20]
# ...and overwrite the height position with it
data[20:24] = width_bytes

with open('flag.png', 'wb') as f:
    f.write(data)

print(f"Done! Open file 'flag.png' to see the result.")