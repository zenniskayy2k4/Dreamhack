#!/usr/bin/env python3
from pwn import *

def rotate_nibble(b):
    """Swaps the high 4 bits and low 4 bits of a byte."""
    return ((b << 4) | (b >> 4)) & 0xFF

def generate_state(name, initial_state):
    """
    This function will take the initial state of the array.
    """
    name_bytes = name.encode('ascii')
    name_len = len(name_bytes)
    
    # Start with the actual initial state, not a zero array
    state = bytearray(initial_state)

    for i in range(256):
        char_from_name = name_bytes[i % name_len]
        # XOR with current value
        state[i] ^= char_from_name
        # Swap nibbles
        state[i] = rotate_nibble(state[i])
        
    return state

# Initial data of DAT_00104020 extracted from Ghidra
initial_state_data = (
    b"\xa5\x90\x07\x7f\x0a\x10\xc9\xae\xa3\x86\x24\x16\x02\x97\x28\x51"
    b"\x54\xfb\x08\x1f\x27\x75\x09\xa7\xe2\xd5\xb4\xbb\x1b\xf8\x33\x50"
    b"\x81\x5f\xef\x0e\x6f\x2e\x55\xab\x4e\xe1\xee\x40\x8c\xd3\x9c\xc5"
    b"\x9b\xb7\xdc\x7d\x80\xc2\x45\x99\x30\x89\xdd\x04\x5d\x41\xe7\x21"
    b"\x67\x44\x69\x47\x32\x8b\x2c\xd1\xa0\x5b\xb9\xbd\x84\x78\xcb\x4f"
    b"\xb6\x13\x1d\xea\xbe\x15\x8f\x3a\x18\x98\x3c\xe4\xcc\xac\x4b\xdf"
    b"\x9d\x3d\x6e\x31\x06\x7a\xd8\x95\xb2\x38\x1c\x6b\xa9\x62\x7e\xf7"
    b"\x60\x5c\x36\x0c\xb0\x9a\xca\xd4\x35\x63\x52\xb1\xa4\x3e\x0b\x82"
    b"\x96\x68\xe5\x6a\xd6\xd2\xf4\xaa\xcd\x1a\x7b\x91\xe6\x6c\xda\x94"
    b"\xd0\x56\xf1\xbc\x4a\x2a\x19\x01\xc8\x43\xc4\x1e\x39\x3f\xe9\xfc"
    b"\x4d\xce\x00\xc7\xf5\xeb\xf9\x8e\x93\xc1\x9f\x22\x87\x70\x23\xb8"
    b"\xff\xa1\xd9\xdb\x46\xf0\xc6\x05\x57\x26\xa6\x17\x59\xc0\xfd\x88"
    b"\x53\x5a\x2b\xe8\x2f\x9e\x49\x11\xde\xb3\x4c\x66\xe0\x34\x8a\x0d"
    b"\x20\xad\xfe\x76\x6d\xed\x12\xba\x74\xc3\x64\xbf\x25\xf3\x29\x71"
    b"\xe3\xa2\xb5\x85\xf2\xaf\x58\xfa\x7c\x5e\x65\x61\x14\x92\xa8\x3b"
    b"\x03\x8d\x42\x2d\x72\x77\x83\x79\xd7\x73\xf6\x0f\x48\xec\xcf\x37"
)

HOST = "host1.dreamhack.games"
PORT = 14537

p = remote(HOST, PORT)

my_name = b"AAAA" 
name_len = len(my_name)

# Create the correct state array using initial data
state_array = generate_state(my_name.decode('ascii'), initial_state_data)

p.recvuntil(b"Enter name(4~20): ")
log.info(f"Sending name: {my_name.decode()}")
p.sendline(my_name)

# Loop 100 times
for i in range(100):
    p.recvuntil(b"me: ")

    index = (i * name_len) % 256
    val = state_array[index]
    computer_choice = val % 3
    my_move = (computer_choice + 1) % 3

    log.info(f"Round {i+1}/100: Computer will choose {computer_choice}. Sending {my_move} to win.")
    p.sendline(str(my_move).encode())
    
    # Read the "You win!" result line to clean the buffer for the next round
    p.recvline()

# Receive the flag
log.success("Finished 100 rounds. Receiving flag...")
print(p.recvall().decode(errors='ignore'))

p.close()