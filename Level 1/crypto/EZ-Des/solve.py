from Crypto.Cipher import DES
import random

# The seed obtained from the 'X-Used-Seed' response header when downloading the ciphertext.
used_seed = 1754705649 

KEY_FILE = 'keys.txt'
CIPHER_FILE = 'ciphertext.txt'
BLOCK_SIZE = 8
NUM_BLOCKS = 50

# 1. Read the keys from the provided file.
with open(KEY_FILE, 'r') as f:
    lines = f.readlines()
keys = [bytes.fromhex(line.strip()) for line in lines if line.strip()]

# 2. Read the ciphertext and split it into blocks.
with open(CIPHER_FILE, 'rb') as f:
    ciphertext = f.read()
ciphertext_blocks = [ciphertext[i:i+BLOCK_SIZE] for i in range(0, len(ciphertext), BLOCK_SIZE)]

# 3. Recreate the shuffled order of key indices using the server's seed.
# This mimics the exact shuffling process that happened on the server.
shuffled_indices = list(range(NUM_BLOCKS))
random.seed(used_seed)
random.shuffle(shuffled_indices)

# 4. Iterate over the ciphertext blocks and decrypt each one.
plaintext_blocks = []
for i in range(NUM_BLOCKS):
    # Get the correct key for this block using the shuffled index.
    key_for_this_block = keys[shuffled_indices[i]]
    
    # Get the corresponding ciphertext block.
    cipher_block = ciphertext_blocks[i]
    
    # Create a DES object for decryption.
    cipher = DES.new(key_for_this_block, DES.MODE_ECB)
    
    # Decrypt the block. Only a single decryption is needed because the
    # server's 'triple_des_ede' function was flawed and acted like single DES.
    plain_block = cipher.decrypt(cipher_block)
    plaintext_blocks.append(plain_block)
    
# 5. Join the decrypted blocks to get the final flag.
flag = b''.join(plaintext_blocks)

# The .strip() removes any trailing padding characters (like 'A' or null bytes).
print("Flag:", flag.decode('utf-8', errors='ignore').strip())