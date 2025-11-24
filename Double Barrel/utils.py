def xor_lst(a: list[int], b: list[int]) -> list[int]:
    return [x^y for x,y in zip(a,b)]

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes([x^y for x,y in zip(a,b)])

def int_to_bits(d: int, bits_len:int = 8) -> list[int]:
    return [int(x) for x in bin(d)[2:].zfill(bits_len)]

def bits_to_int(bits: list[int]) -> int:
    return int(''.join([str(x) for x in bits]),2)

def bytes_to_bits(m: bytes) -> list[int]:
    bits = []
    for b in m:
        bits += [int(x) for x in bin(b)[2:].zfill(8)]
    return bits

def bits_to_bytes(bits: list[int]) -> bytes:
    return bits_to_int(bits).to_bytes(len(bits)//8, 'big')

def add_mod_2_32(bit32: list[int], key32: list[int]) -> list[int]:
    return int_to_bits((bits_to_int(bit32) + bits_to_int(key32)) % (2**32), 32)

def sub_mod_2_32(bit32: list[int], key32: list[int]) -> list[int]:
    return int_to_bits((bits_to_int(bit32) - bits_to_int(key32)) % (2**32), 32)

def rol11(bit32: list[int]) -> list[int]:
    return bit32[11:]+bit32[:11]

def ror11(bit32: list[int]) -> list[int]:
    return bit32[-11:]+bit32[:-11]