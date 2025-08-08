def solve():
    """
    Replicates the logic of the flag checker binary to extract the flag.
    """
    # The hardcoded key from the binary
    key = bytes([
        0x2a, 0x22, 0xa4, 0x7f, 0x25, 0x11, 0x6b, 0x77, 
        0x69, 0xf2, 0x70, 0x6b, 0x7c, 0x69, 0x7c
    ])

    binary_path = "./prob"

    try:
        with open(binary_path, "rb") as f:
            # Step 1: Read 1024 bytes from offset 0x539
            f.seek(0x539)
            data = bytearray(f.read(0x400)) # Use bytearray to allow modification
    except FileNotFoundError:
        print(f"Error: Binary file not found at '{binary_path}'")
        print("Please download the challenge file and place it in the correct directory.")
        return

    # Step 2: Find the indices of the first 15 non-zero bytes
    nonzero_indices = []
    for i, byte_val in enumerate(data):
        if byte_val != 0:
            nonzero_indices.append(i)
        if len(nonzero_indices) == 15:
            break
    
    if len(nonzero_indices) < 15:
        print("Error: Could not find 15 non-zero bytes in the specified data block.")
        return

    print(f"Found 15 non-zero byte indices: {nonzero_indices}")

    # Step 4: First decryption loop (XORing the data)
    for i in range(15):
        idx_to_modify = nonzero_indices[i]
        original_byte = data[idx_to_modify]
        key_byte = key[i]
        
        # data[pos] = data[pos] ^ key[i]
        data[idx_to_modify] = original_byte ^ key_byte

    # Step 5: Second loop (Constructing the flag)
    flag_bytes = bytearray()
    for i in range(15):
        flag_byte = data[nonzero_indices[i]]
        flag_bytes.append(flag_byte)

    # The result is the magic string
    flag = flag_bytes.decode('ascii')

    print("\n" + "="*40)
    print(f"Magic String (Flag): {flag}")
    print("="*40)

if __name__ == "__main__":
    solve()