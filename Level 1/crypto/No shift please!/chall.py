from AES import AES_implemented
import os

# For real AES without modification, this challenge is unsolvable with modern technology.
# But let's remove a step.
ret = lambda x: None
AES_implemented._shift_rows = ret
AES_implemented._shift_rows_inv = ret
# Will it make a difference?

secret = os.urandom(16)
key = os.urandom(16)

flag = open("flag.txt", "r").read()

cipher = AES_implemented(key)

secret_enc = cipher.encrypt(secret)
assert cipher.decrypt(secret_enc) == secret
print(f"enc(secret) = {bytes.hex(secret_enc)}")

while True:
	option = int(input("[1] encrypt, [2] decrypt: "))

	if option == 1: # Encryption
		plaintext = bytes.fromhex(input("Input plaintext to encrypt in hex: "))
		assert len(plaintext) == 16

		ciphertext = cipher.encrypt(plaintext)
		print(f"enc(plaintext) = {bytes.hex(ciphertext)}")

		if plaintext == secret:
			print(flag)
			exit()

	elif option == 2: # Decryption
		ciphertext = bytes.fromhex(input("Input ciphertext to decrypt in hex: "))
		assert len(ciphertext) == 16
		
		if ciphertext == secret_enc:
			print("No way!")
			continue
			
		plaintext = cipher.decrypt(ciphertext)
		print(f"dec(ciphertext) = {bytes.hex(plaintext)}")