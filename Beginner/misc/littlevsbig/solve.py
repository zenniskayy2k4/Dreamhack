import struct

# The target integer values
val1 = 0x64726d68
val2 = 0x636b3a29

# Pack the integers into a byte string.
# '<' specifies little-endian byte order.
# 'I' specifies a 4-byte unsigned integer.
payload = struct.pack('<II', val1, val2)

# The payload will be b'hmrd):kc'
print(payload.decode('ascii'))

# Flag: DH{8feeeb676d552cca414e944e0b5c916913934af5917309a3282a9e1d3422dda8}