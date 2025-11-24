from utils import *
import os

sbox = (
    (0xC, 0x4, 0x6, 0x2, 0xA, 0x5, 0xB, 0x9, 0xE, 0x8, 0xD, 0x7, 0x0, 0x3, 0xF, 0x1),
    (0x6, 0x8, 0x2, 0x3, 0x9, 0xA, 0x5, 0xC, 0x1, 0xE, 0x4, 0x7, 0xB, 0xD, 0x0, 0xF),
    (0xB, 0x3, 0x5, 0x8, 0x2, 0xF, 0xA, 0xD, 0xE, 0x1, 0x7, 0x4, 0xC, 0x9, 0x6, 0x0),
    (0xC, 0x8, 0x2, 0x1, 0xD, 0x4, 0xF, 0x6, 0x7, 0x0, 0xA, 0x5, 0x3, 0xE, 0x9, 0xB),
    (0x7, 0xF, 0x5, 0xA, 0x8, 0x1, 0x6, 0xD, 0x0, 0x9, 0x3, 0xE, 0xB, 0x4, 0x2, 0xC),
    (0x5, 0xD, 0xF, 0x6, 0x9, 0x2, 0xC, 0xA, 0xB, 0x7, 0x8, 0x1, 0x4, 0x3, 0xE, 0x0),
    (0x8, 0xE, 0x2, 0x5, 0x6, 0x9, 0x1, 0xC, 0xF, 0x4, 0xB, 0x0, 0xD, 0xA, 0x3, 0x7),
    (0x1, 0x7, 0xE, 0xD, 0x0, 0x5, 0x8, 0x3, 0x4, 0xF, 0xA, 0x6, 0x9, 0xC, 0xB, 0x2)
)

isbox = (
    (12, 15, 3, 13, 1, 5, 2, 11, 9, 7, 4, 6, 0, 10, 8, 14),
    (14, 8, 2, 3, 10, 6, 0, 11, 1, 4, 5, 12, 7, 13, 9, 15),
    (15, 9, 4, 1, 11, 2, 14, 10, 3, 13, 6, 0, 12, 7, 8, 5),
    (9, 3, 2, 12, 5, 11, 7, 8, 1, 14, 10, 15, 0, 4, 13, 6),
    (8, 5, 14, 10, 13, 2, 6, 0, 4, 9, 3, 12, 15, 7, 11, 1),
    (15, 11, 5, 13, 12, 0, 3, 9, 10, 4, 7, 8, 6, 1, 14, 2),
    (11, 6, 2, 14, 9, 3, 4, 15, 0, 5, 13, 10, 7, 12, 1, 8),
    (4, 0, 15, 7, 8, 5, 11, 1, 6, 12, 10, 14, 13, 3, 2, 9)
)

def _substitution(bit32: list[int]) -> list[int]:
    res: list[int] = []
    for i,j in enumerate(range(0,32,4)):
        res += int_to_bits(sbox[7-i][bits_to_int(bit32[j:j+4])], 4)
    return res

def isub(bit32: list[int]) -> list[int]:
    res: list[int] = []
    for i,j in enumerate(range(0,32,4)):
        res += int_to_bits(isbox[7-i][bits_to_int(bit32[j:j+4])], 4)
    return res

def F(key, state, swap):
    key = bytes_to_bits(key)
    state_hi = bytes_to_bits(state[:4])
    state_lo = bytes_to_bits(state[4:])
    state = state_hi[:]+state_lo[:]

    state_lo = add_mod_2_32(state_lo, key)
    state_lo = _substitution(state_lo)
    state_lo = rol11(state_lo)
    state_lo = xor_lst(state_lo, state_hi)

    if swap:
        state[:32] = state_lo
    else:
        state[:32] = state[32:]
        state[32:] = state_lo
    return bits_to_bytes(state)

class GHOST:
    sbox = (
        (0xC, 0x4, 0x6, 0x2, 0xA, 0x5, 0xB, 0x9, 0xE, 0x8, 0xD, 0x7, 0x0, 0x3, 0xF, 0x1),
        (0x6, 0x8, 0x2, 0x3, 0x9, 0xA, 0x5, 0xC, 0x1, 0xE, 0x4, 0x7, 0xB, 0xD, 0x0, 0xF),
        (0xB, 0x3, 0x5, 0x8, 0x2, 0xF, 0xA, 0xD, 0xE, 0x1, 0x7, 0x4, 0xC, 0x9, 0x6, 0x0),
        (0xC, 0x8, 0x2, 0x1, 0xD, 0x4, 0xF, 0x6, 0x7, 0x0, 0xA, 0x5, 0x3, 0xE, 0x9, 0xB),
        (0x7, 0xF, 0x5, 0xA, 0x8, 0x1, 0x6, 0xD, 0x0, 0x9, 0x3, 0xE, 0xB, 0x4, 0x2, 0xC),
        (0x5, 0xD, 0xF, 0x6, 0x9, 0x2, 0xC, 0xA, 0xB, 0x7, 0x8, 0x1, 0x4, 0x3, 0xE, 0x0),
        (0x8, 0xE, 0x2, 0x5, 0x6, 0x9, 0x1, 0xC, 0xF, 0x4, 0xB, 0x0, 0xD, 0xA, 0x3, 0x7),
        (0x1, 0x7, 0xE, 0xD, 0x0, 0x5, 0x8, 0x3, 0x4, 0xF, 0xA, 0x6, 0x9, 0xC, 0xB, 0x2)
    )

    def __init__(self, key: bytes, feedback: int) -> None:
        self._block_size = 8
        self._round_keys = self._expand_key(key,feedback)
        self._state = []

    def _expand_key(self, key: bytes, feedback: int) -> list[list[int]]:
        assert len(key) == 6
        assert feedback.bit_length() == 48
        rk_list = []
        key = int.from_bytes(key,"little")
        os.system(f"./key {feedback} {key} > rk.txt")
        with open("rk.txt","r") as f:
            for line in f.readlines():
                rk_list.append(int_to_bits(int(line.strip()),32))
        return rk_list

    def _substitution(self, bit32: list[int]) -> list[int]:
        res: list[int] = []
        for i,j in enumerate(range(0,32,4)):
            res += int_to_bits(self.sbox[7-i][bits_to_int(bit32[j:j+4])], 4)
        return res

    def _round_function(self, round_n: int, is_enc: bool) -> None:
        state_hi = self._state[:32]
        state_lo = self._state[32:]

        state_lo = add_mod_2_32(state_lo, self._round_keys[round_n])
        state_lo = self._substitution(state_lo)
        state_lo = rol11(state_lo)
        state_lo = xor_lst(state_lo, state_hi)

        if (is_enc and round_n == 31) or (not is_enc and round_n == 0):
            self._state[:32] = state_lo
        else:
            self._state[:32] = self._state[32:]
            self._state[32:] = state_lo  

    def _encrypt(self, plaintext: bytes) -> bytes:
        self._state = bytes_to_bits(plaintext)
        for i in range(32):
            self._round_function(i, is_enc=True)
        return bits_to_bytes(self._state)

    def _decrypt(self, ciphertext: bytes) -> bytes:
        self._state = bytes_to_bits(ciphertext)
        for i in range(31, -1, -1):
            self._round_function(i, is_enc=False)
        return bits_to_bytes(self._state)

    def encrypt(self, plaintext: bytes) -> bytes:
        assert len(plaintext)%self._block_size == 0
        ciphertext  = b''
        for i in range(0, len(plaintext), self._block_size):
            ciphertext += self._encrypt(plaintext[i:i + self._block_size])
        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        assert len(ciphertext)%self._block_size == 0
        plaintext  = b''
        for i in range(0, len(ciphertext), self._block_size):
            plaintext += self._decrypt(ciphertext[i:i + self._block_size])
        return plaintext

def test():
    import os
    from tqdm import trange
    trial = 0x1000
    rep = 0x8
    for _ in range(rep):
        key = os.urandom(6)
        feedback = int.from_bytes(os.urandom(6),"big")|(1<<47)
        g = GHOST(key,feedback)
        for _ in trange(trial):
            plain = os.urandom(8)
            cipher = g.encrypt(plain)
            assert plain == g.decrypt(cipher)

if __name__ == '__main__':
    test()