class CustomRandom2048:
    def __init__(self, seed):
        mask = (1 << 64) - 1
        self.state = []
        for i in range(32):
            s = (seed >> (64 * (31-i))) & mask
            self.state.append(s)
        self.p = 0

    def next(self):
        mask = (1 << 64) - 1
        s0 = self.state[self.p]
        s1 = self.state[(self.p+1) % 32]
        out = (s0 ^ ((s1 << 13) & mask)) & mask
        self.state[self.p] = ((s0 + s1 + 0xCAFEBABE12345678) ^ 0x1337DEADBEEF) & mask
        self.p = (self.p + 1) % 32
        return out

    def getrandbits(self, nbits=2048):
        output = 0
        for _ in range(nbits // 64):
            output = (output << 64) | self.next()
        return output