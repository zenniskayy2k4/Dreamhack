# Dữ liệu tĩnh B (Encrypted Stub) từ section .bind của bạn
encrypted_stub = bytes.fromhex("d1a63b9177205e4fc8129ae3450b6df02c8e7359ab14de0731c24a88e9165b3f")

# Key giải mã A
key = 0xab

# Giải mã
plaintext_stub = bytes([b ^ key for b in encrypted_stub])

print(f"Plaintext Stub (Mã máy): {plaintext_stub.hex()}")