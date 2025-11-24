import random
from Crypto.Util.number import getPrime, bytes_to_long, inverse

class RSA_Cipher:
    def __init__(self):
        self.p = getPrime(1024)
        self.q = getPrime(1024)
        self.N = self.p * self.q
        self.e = 5
        self.d = inverse(self.e, self.N - self.p - self.q + 1)

    def encrypt(self, pt):
        return pow(pt, self.e, self.N)

class Vigenere_Cipher:
    def __init__(self, key):
        self._key = key

    def encrypt(self, msg):
        enc = b""
        for i in range(len(msg)):
            enc += bytes([(msg[i] + self._key[i % len(self._key)]) % 256])
        return enc

def main():
    FLAG = open("flag", "rb").read()
    key = random.randbytes(4)

    while(1):
        try:
            vgn = Vigenere_Cipher(key)
            rsa = RSA_Cipher()
            break
        except Exception as e:
            continue

    print("Hi, this is Amo, I'll send you my public key.")
    print("e:", rsa.e)
    print("N:", rsa.N)
    print()

    enc1 = bytes_to_long(vgn.encrypt(FLAG))
    enc2 = rsa.encrypt(bytes_to_long(key))

    print("Hello, this is Boko! I'll send you ciphertexts!")
    print("enc1:", enc1)
    print("enc2:", enc2)


if __name__ == "__main__":
    main()