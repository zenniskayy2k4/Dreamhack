import re
table = eval(open('./table.txt', 'r').read())

ob_code = open('main.bundle.js', 'r').read()
res = ob_code

m = re.findall('_0x.{6}\(0x.{3}\)', ob_code)
for x in m:
    if '_0x95b830' in x:
        continue
    print(x)
    index = int(x.split('(')[1].split(')')[0], 16)
    res = res.replace(x, "'" + table[index] + "'")

open('deob_main.bundle.js', 'w').write(res)