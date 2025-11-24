import re

with open("output_og", "r", encoding="utf-8") as f:
    data = f.read()

matches = re.findall(r'WaRP\{[^}]+\}', data)
for match in matches:
    print("Flag:", match)