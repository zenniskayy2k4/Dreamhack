# Ghidra Jython Script to solve func_rev challenge

from ghidra.program.model.listing import CodeUnit

currentProgram = getCurrentProgram()
functionManager = currentProgram.getFunctionManager()

flag_chars = {}

print("Starting extraction from func_0 to func_927...")

for i in range(928):
    func_name = "func_{}".format(i)
    
    functions = functionManager.getFunctions(True)
    target_func = None
    for func in functions:
        if func.getName() == func_name:
            target_func = func
            break
            
    if target_func is None:
        print("Could not find function: {}".format(func_name))
        continue

    listing = currentProgram.getListing()
    instructions = listing.getInstructions(target_func.getBody(), True)

    for instr in instructions:
        if instr.getMnemonicString() == "MOV":
            op2 = instr.getOpObjects(1)[0]
            
            if op2.toString().startswith("0x"):
                try:
                    char_val = int(op2.toString(), 16)
                    flag_chars[i] = chr(char_val)
                    break
                except ValueError:
                    continue

flag_string = ""
for i in range(928):
    if i in flag_chars:
        flag_string += flag_chars[i]

print("\nExtraction complete!")
print("=============================================")
print("Full extracted string:")
print(flag_string)

import re
flag_match = re.search(r'DH{.*?}', flag_string)
if flag_match:
    print("\nFLAG FOUND:")
    print(flag_match.group(0))
else:
    print("\nFlag not found in the extracted string.")

print("=============================================")