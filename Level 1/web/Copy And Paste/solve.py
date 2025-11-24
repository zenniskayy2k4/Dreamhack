def caesar_decode(s, shift=3):
    result = ""
    for c in s:
        if 'A' <= c <= 'Z':
            if 'X' <= c <= 'Z':
                result += chr((ord(c) - ord('A') + shift*2) % 26 + ord('A'))
            else:
                result += chr((ord(c) - ord('A') + shift) % 26 + ord('A'))
        elif 'a' <= c <= 'z':
            if 'x' <= c <= 'z':
                result += chr((ord(c) - ord('a') + shift*2) % 26 + ord('a'))
            else:
                result += chr((ord(c) - ord('a') + shift) % 26 + ord('a'))
        else:
            result += c
    return result

fake_flag = "AE{xy5x5a08b9818z5336657zyz949399z9xbyz120465c7ab60ac9ybyzb99b9y4a85b886c1999yx0by9189357bx46ca0y32c072c24za951483797510b9x33b0az66c8x00257cx3y47zy816x30y4883747a44805ca3y6xcc65axxyzy2a427b4bab28186b931b41x7c04yz83z05804x88ab1bb17ca4bb4ba0bbyaa36071889c41cab2071xa4c631x044428cy66a150a411z7962y2byyby9a8a94c6zbc4a3x4xxab85zy06b25zazxc3y39z03b89x2yb1y475065594879c8103ay4x1xa82y442ac06750y886za0471y0599x}"
real_flag = caesar_decode(fake_flag)
print(real_flag)