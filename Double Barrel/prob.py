import os
from cipher import GHOST

def inp():
    return input(">> ")

def read_flag():
    with open("flag.txt","r") as f:
        print(f.read())

seeds = os.urandom(2048//8)
print(f"🌱 = {seeds.hex()}")
seeds = int.from_bytes(seeds,"big")
feedback_index = int(inp())
assert 0<=feedback_index<=2048-47
feedback = 2**47+((seeds>>(feedback_index))&(2**47-1))
key = os.urandom(6)

cipher = GHOST(key,feedback)

while True:
    c = int(inp())
    if c==1:
        pt = bytes.fromhex(inp())
        ct = cipher.encrypt(pt)
        print(ct.hex())
    if c==2:
        ct = bytes.fromhex(inp())
        pt = cipher.decrypt(ct)
        print(pt.hex())
    if c==3:
        pt = os.urandom(8)
        ct = cipher.encrypt(pt)
        print(ct.hex())
        guess = bytes.fromhex(inp())
        if guess == pt:
            read_flag()
        else:
            print("You failed")
        break