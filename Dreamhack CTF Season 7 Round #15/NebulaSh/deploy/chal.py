from Crypto.Util.number import isPrime, getPrime, GCD, long_to_bytes, bytes_to_long
import secrets

random = secrets.SystemRandom()

class NaccacheStern:
    def __init__(self, n: int | None = None):
        if n is None:
            n = getPrime(1024)
        assert isPrime(n)

        while True:
            s = random.randint(1, n - 2)
            if GCD(s, n - 1) == 1:
                break
        
        p, mult = [], 1
        for p_i in range(2, n):
            if isPrime(p_i):
                if mult * p_i >= n:
                    break
                mult *= p_i
                p.append(p_i)
        
        inv_s = pow(s, -1, n - 1)
        v = [pow(p_i, inv_s, n) for p_i in p]

        # pubkey
        self.n, self.v = n, v
        # privkey
        self.p, self.s = p, s
    
    def pubkey(self):
        return self.n, self.v
    
    def privkey(self):
        return self.p, self.s
    
    def max_bit_length(self):
        return len(self.v)
    
    def encrypt(self, msg: bytes) -> int:
        assert len(msg) * 8 <= self.max_bit_length()

        m = bytes_to_long(msg)
        c = 1
        for v_i in self.v:
            if m % 2:
                c = c * v_i % self.n
            m >>= 1
        
        return c

    def decrypt(self, c: int) -> bytes:
        t = pow(c, self.s, self.n)
        m = 0

        for i, p_i in enumerate(self.p):
            m += 2 ** i * (GCD(p_i, t) - 1) // (p_i - 1)
        
        return long_to_bytes(m)


def print_flag():
    with open("./flag", "r") as f:
        print(f"Here is the flag: {f.read()}")


def main():
    try:
        n = int(input("Give me n: ").strip())
        assert isPrime(n) and n.bit_length() == 1024

        print("I want to assure that the prime number is strong enough")
        factor = int(input("Give me a large prime factor of n - 1: ").strip())
        assert isPrime(factor) and (n - 1) % factor == 0 and factor.bit_length() >= 512
        
        print("Ok, now it's safe to go")
    except:
        print(":(")
        n = None

    cipher = NaccacheStern(n)

    print(f"Pubkey: {cipher.pubkey()}")

    max_byte_length = cipher.max_bit_length() // 8
    random_pt = random.randbytes(max_byte_length)
    print(f"Plaintext len: {len(random_pt)}")
    print(f"Encrypted result: {cipher.encrypt(random_pt)}")

    guess = bytes.fromhex(input("pt? ").strip())
    if cipher.encrypt(guess) == cipher.encrypt(random_pt):
        print_flag()
    else:
        print(":(")


if __name__ == "__main__":
    main()
