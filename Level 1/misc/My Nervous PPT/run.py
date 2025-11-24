with open("hid_data.txt", 'r') as f:
    lines = f.readlines()
    print("".join(chr(int(line.strip(), 16)) for line in lines))