# SelfStatus Reverse Engineering Challenge

This is a classic Reverse Engineering challenge that involves a custom Virtual Machine (VM) and an anti-debugging mechanism. The goal is to understand the VM's instruction set, emulate its execution on a given bytecode, and retrieve the correct flag.

## 1. Main Function (`FUN_00101550`)

This is the entry point of the program. Its logic is straightforward:

- It first calls `FUN_001011a9()`, which is an anti-debugging check.
- If the check detects a debugger, the program exits immediately.
- If not, it prompts the user for the flag.
- It then calls the core VM interpreter function, `FUN_001012e5()`, to generate the correct flag.
- Finally, it compares the user's input with the generated flag and prints "Correct!" or "Wrong!".

## 2. Anti-Debugging (`FUN_001011a9`)

This function implements a common anti-debugging trick on Linux systems.

- It opens and reads the file `/proc/self/status`, which contains information about the current process.
- It searches for the string "TracerPid:".
- The TracerPid field shows the Process ID (PID) of any process that is tracing it (e.g., a debugger like GDB).
- If TracerPid is anything other than 0, it means a debugger is attached, and the function returns a non-zero value, causing the program to terminate.

This prevents us from easily debugging the program to see the flag being generated in memory.

## 3. The VM Interpreter (`FUN_001012e5`)

This is the heart of the challenge. It's a simple, stack-based virtual machine.

**Inputs:** It takes the bytecode, its length, and a buffer to write the output to.

**Components:**
- **Stack:** A region of memory (`local_98`) used for temporary storage.
- **Instruction Pointer (IP):** A counter (`local_a0`) that points to the current instruction in the bytecode.
- **Output Buffer:** A pointer (`param_3`) to where the final flag characters are written.

The interpreter loops through the bytecode, decodes each instruction (opcode), and performs an action. Here is the decoded instruction set:

| Opcode (Hex) | Mnemonic (Guess) | Description |
|:--------------:|:------------------:|:-------------:|
| 0xA1         | PUSH             | Pushes the next byte from the bytecode onto the stack. |
| 0xA2         | POP              | Pops the top value from the stack (discards it). |
| 0xA3         | XOR              | Pops the top value, XORs it with the next byte, and pushes the result. |
| 0xA4         | ADD              | Pops the top value, adds it to the next byte, and pushes the result. |
| 0xA5, 0xEE   | NOP              | No Operation. Skips the instruction and its argument. |
| 0xF0         | OUT              | Pops the top value from the stack and writes it to the output buffer. |
| 0xFF         | HALT             | Stops the execution of the VM. |

## Exploitation Strategy

Since we cannot debug the program directly, the best approach is to emulate the VM ourselves.

1. **Extract Bytecode:** Dump the 247 bytes of bytecode from the binary's data section, starting at address 0x102020.
2. **Write an Emulator:** Create a Python script that simulates the stack and processes each opcode exactly as the binary does.
3. **Generate the Flag:** Run the emulator on the extracted bytecode. The final content of the output buffer will be the flag.

## Solution Script

Here is the complete Python script to solve the challenge. It emulates the VM and prints the flag.

```python
def emulate_vm():
    """
    Emulates the custom VM from the binary to reconstruct the flag.
    """
    # STEP 1: The bytecode extracted from the binary's data section.
    bytecode_hex = (
        "eeefee2fee11a106a342f0ee3eeea2ee6da10aa342f0ee1deeffa139a342f0eec7eec4eed6"
        "a111a342f0ee24ee70a171a342f0ee22ee59a12ea342f0eeb2ee96ee7ba124a342f0ee7eee"
        "3ca111a342f0ee5fa136a342f0ee0ceefca176a342f0ee8aee54a136a342f0ee9aee08eed7"
        "a137a342f0eed7a131a342f0ee36a11da342f0ee48a114a342f0ee3cee52a10fa342f0ee10"
        "ee2eee34a11da342f0eeffee01ee02a100a342f0ee0ba13ba342f0ee3dee88ee65a175a342"
        "f0ee3fee22a127a342f0ee90eeeaee47a121a342f0eee3ee04eecca172a342f0ee09ee39ee"
        "78a126a342f0ee1cee06ee42a171a342f0ee7ba13fa342f0ff"
    )
    bytecode = bytes.fromhex(bytecode_hex)

    # STEP 2: Set up the virtual machine environment
    stack = []
    output_flag = []
    ip = 0  # Instruction Pointer

    print("Starting VM emulation...")

    # STEP 3: The main interpreter loop
    while ip < len(bytecode):
        opcode = bytecode[ip]

        # PUSH instruction: 0xA1
        if opcode == 0xa1:
            value = bytecode[ip + 1]
            stack.append(value)
            ip += 2
        
        # POP instruction: 0xA2
        elif opcode == 0xa2:
            if stack:
                stack.pop()
            ip += 1

        # XOR instruction: 0xA3
        elif opcode == 0xa3:
            if stack:
                value_to_xor = bytecode[ip + 1]
                # XOR the value at the top of the stack with the argument
                stack[-1] ^= value_to_xor
            ip += 2

        # ADD instruction: 0xA4
        elif opcode == 0xa4:
            if stack:
                value_to_add = bytecode[ip + 1]
                # Add the argument to the value at the top of the stack (with overflow)
                stack[-1] = (stack[-1] + value_to_add) % 256
            ip += 2

        # NOP (No Operation) instructions: 0xA5, 0xEE
        elif opcode in [0xa5, 0xee]:
            # These instructions do nothing but take an argument
            ip += 2

        # OUT instruction: 0xF0
        elif opcode == 0xf0:
            if stack:
                # Pop a character code from the stack and add it to the output
                char_code = stack.pop()
                output_flag.append(char_code)
            ip += 1

        # HALT instruction: 0xFF
        elif opcode == 0xff:
            print(f"HALT instruction encountered at ip={ip}. Terminating.")
            break
        
        # Handle any unknown opcodes
        else:
            print(f"Warning: Unknown opcode {hex(opcode)} at ip={ip}. Skipping.")
            ip += 1

    # STEP 4: Process and print the result
    if output_flag:
        # Convert the list of character codes into a readable string
        flag = "".join([chr(c) for c in output_flag])
        print("\n" + "="*40)
        print(f"Emulation finished successfully!")
        print(f"FLAG: {flag}")
        print("="*40)
    else:
        print("Emulation finished, but no output was generated.")

if __name__ == "__main__":
    emulate_vm()
```