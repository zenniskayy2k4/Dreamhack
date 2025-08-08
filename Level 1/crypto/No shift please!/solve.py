from pwn import *

HOST = "host8.dreamhack.games"
PORT = 13496

p = remote(HOST, PORT)

# Receive the first output line containing enc(secret)
initial_output = p.recvline().decode().strip()
# Extract the hex part of secret_enc
secret_enc_hex = initial_output.split(" = ")[1]
secret_enc = bytes.fromhex(secret_enc_hex)

log.info(f"Received secret_enc: {secret_enc.hex()}")

# Initialize empty secret
secret = bytearray(16)

# Attack each column
for i in range(4):
    log.info(f"Attacking column {i}...")
    
    # Create a forged ciphertext
    # Only keep column `i` of secret_enc, other columns are 0
    crafted_ct = bytearray(16)
    start_index = i * 4
    end_index = start_index + 4
    crafted_ct[start_index:end_index] = secret_enc[start_index:end_index]
    
    log.info(f"  - Sending crafted ciphertext: {crafted_ct.hex()}")
    
    # Send decryption request (option 2)
    p.sendlineafter(b"[1] encrypt, [2] decrypt: ", b"2")
    p.sendlineafter(b"Input ciphertext to decrypt in hex: ", crafted_ct.hex().encode())
    
    # Receive decryption result
    dec_output = p.recvline().decode().strip()
    dec_plaintext_hex = dec_output.split(" = ")[1]
    dec_plaintext = bytes.fromhex(dec_plaintext_hex)
    
    log.info(f"  - Received decrypted plaintext: {dec_plaintext.hex()}")
    
    # Get column `i` from the result and put it into our secret
    secret_column = dec_plaintext[start_index:end_index]
    secret[start_index:end_index] = secret_column
    log.success(f"  - Recovered secret column {i}: {secret_column.hex()}")

log.success(f"Full secret recovered: {bytes(secret).hex()}")

# Send the recovered secret to get the flag (option 1)
log.info("Sending the recovered secret to get the flag...")
p.sendlineafter(b"[1] encrypt, [2] decrypt: ", b"1")
p.sendlineafter(b"Input plaintext to encrypt in hex: ", bytes(secret).hex().encode())

# Receive and print flag
p.recvline() # Line with enc(plaintext)
flag = p.recvline().decode().strip()
log.success(f"FLAG: {flag}")

p.close()