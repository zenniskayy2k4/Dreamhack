from pwn import *

p = remote('host1.dreamhack.games', 9747)
# p = process(['python3','-u','chal.py'])

while not p.recvline().strip().endswith(b'CTR'):
    p.sendlineafter(b'>> ', b'3')
    p.recvline()

p.sendlineafter(b'>> ', b'1')
p.sendlineafter(b'>> ', b'\x00'*0x1000)
key = bytes.fromhex(p.recvline().strip().split()[-1].decode())
p.sendlineafter(b'>> ', b'2')
x = bytes.fromhex(p.recvline().strip().split()[-1].decode())

print(xor(x,key)[:])

p.interactive()