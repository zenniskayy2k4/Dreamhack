#!/usr/bin/env python3
import argparse, math
from collections import defaultdict

def parse_segment(seq):
    """
    Parse sequence of bytes -> yield (index, nibble)
    """
    out = []
    i = 0
    while i < len(seq):
        if not (2 <= seq[i] <= 254):
            i += 1
            continue

        # collect digits
        digits = []
        j = i
        while j < len(seq) and (2 <= seq[j] <= 254):
            digits.append(seq[j] - 2)
            j += 1
        if not digits or j >= len(seq) or seq[j] != 0xFF:
            i += 1
            continue
        j += 1

        ones = 0
        while j < len(seq) and seq[j] == 1:
            ones += 1
            j += 1
        if ones == 0 or j >= len(seq) or seq[j] != 0xFF:
            i += 1
            continue

        # decode index (little endian base 253)
        val = 0
        mul = 1
        for d in digits:
            val += d * mul
            mul *= 253
        index = val - 1
        nibble = ones - 1
        if 0 <= nibble <= 15 and index >= 0:
            out.append((index, nibble))

        i = j + 1
    return out

def decode_crossing(fname):
    data = open(fname, "rb").read()
    N = int(math.isqrt(len(data)))
    if N * N != len(data):
        raise ValueError("Not a square file")
    grid = [data[i*N:(i+1)*N] for i in range(N)]

    nibbles = {}
    # rows
    for row in grid:
        for idx, nib in parse_segment(row):
            nibbles[idx] = nib
    # cols
    for c in range(N):
        col = bytes(grid[r][c] for r in range(N))
        for idx, nib in parse_segment(col):
            nibbles[idx] = nib

    max_idx = max(nibbles.keys())
    out = bytearray((max_idx//2)+1)
    for i in range(0, max_idx+1, 2):
        hi = nibbles.get(i, 0)
        lo = nibbles.get(i+1, 0)
        out[i//2] = (hi<<4)|lo
    return out

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python decode_crossing.py input.crossing output")
        exit(1)
    out = decode_crossing(sys.argv[1])
    open(sys.argv[2], "wb").write(out)
    print(f"[+] Wrote {len(out)} bytes to {sys.argv[2]}")
