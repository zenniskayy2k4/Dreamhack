from pwn import *
import time

# --- Config ---
HOST = "host8.dreamhack.games"
PORT = 17207

# --- Constants ---
FLAG_BLOCK = b'FAKEFLAG'
if len(FLAG_BLOCK) < 8:
    FLAG_BLOCK = FLAG_BLOCK.ljust(8, b'\x00')

DUMMY_BLOCK = b'\x00' * 8
assert DUMMY_BLOCK != FLAG_BLOCK

def get_ciphertext(p, oracle, pt_hex):
    """Helper to query an oracle and parse the response."""
    p.sendlineafter(b"> ", f"{oracle} {pt_hex}".encode())
    p.recvuntil(b"Ciphertext: ")
    return p.recvline().strip().decode()

def solve():
    p = remote(HOST, PORT)

    # Nhận banner chào mừng
    p.recvuntil(b"-------------------------------------------------------------------\n")
    log.info("Connected to the server.")

    # --- Bước 1: Tìm DELTA_P bằng Meet-in-the-Middle ---
    log.info("Starting Meet-in-the-Middle attack for DELTA_P...")

    # 1.1: Tạo từ điển từ oracle1
    log.info("Building dictionary from oracle1...")
    cipher_to_b1 = {}
    for b1 in range(256):
        p1 = bytes([0x00, b1]) + b'\x00' * 6
        pt_oracle1 = (p1 + DUMMY_BLOCK).hex()
        c1_hex = get_ciphertext(p, 'oracle1', pt_oracle1)[:16]
        cipher_to_b1[c1_hex] = b1
    log.success(f"Dictionary built with {len(cipher_to_b1)} entries.")

    # 1.2: Tìm va chạm bằng oracle2
    log.info("Searching for collision using oracle2...")
    delta0 = -1
    delta1 = -1
    for d0_guess in range(256):
        p2 = bytes([d0_guess, 0x00]) + b'\x00' * 6
        pt_oracle2 = (p2 + DUMMY_BLOCK).hex()
        c2_hex = get_ciphertext(p, 'oracle2', pt_oracle2)[:16]

        if c2_hex in cipher_to_b1:
            delta0 = d0_guess
            delta1 = cipher_to_b1[c2_hex]
            log.success(f"Collision found! delta0 = {hex(delta0)}, delta1 = {hex(delta1)}")
            break
    
    if delta0 == -1 or delta1 == -1:
        log.error("Could not find DELTA_P. Exiting.")
        p.close()
        return

    DELTA_P = bytes([delta0, delta1]) + b'\x00' * 6
    log.info(f"Found DELTA_P: {DELTA_P.hex()}")

    # --- Bước 2: Tính P' = FLAG_BLOCK XOR DELTA_P ---
    p_prime = bytes([FLAG_BLOCK[i] ^ DELTA_P[i] for i in range(8)])
    log.info(f"Calculated P' = FLAG_BLOCK ^ DELTA_P: {p_prime.hex()}")

    # --- Bước 3: Kích hoạt triggers và lấy ciphertext của FLAG_BLOCK ---
    
    # 3.1: Kích hoạt Trigger B và lấy E_k(FLAG_BLOCK)
    log.info("Triggering B and getting target ciphertext...")
    pt_trigger_b = (p_prime + FLAG_BLOCK).hex()
    response_b = get_ciphertext(p, 'oracle2', pt_trigger_b)
    target_ciphertext = response_b[:16]
    log.success(f"Target ciphertext E_k(FLAG_BLOCK) is: {target_ciphertext}")

    # 3.2: Kích hoạt Trigger A
    log.info("Triggering A...")
    pt_trigger_a = (p_prime + DUMMY_BLOCK).hex()
    get_ciphertext(p, 'oracle1', pt_trigger_a)
    log.success("Trigger A activated.")

    # --- Bước 4: Gửi flag ---
    log.info("Submitting the final ciphertext to get the flag...")
    p.sendlineafter(b"> ", f"flag {target_ciphertext}".encode())

    # In ra kết quả
    p.interactive()

if __name__ == "__main__":
    solve()