def rot13_char(c):
    if 'a' <= c <= 'z':
        return chr((ord(c) - ord('a') + 13) % 26 + ord('a'))
    if 'A' <= c <= 'Z':
        return chr((ord(c) - ord('A') + 13) % 26 + ord('A'))
    return c

def rot13(text):
    return ''.join(rot13_char(c) for c in text)

cts = [238, 55, 26, 13, 30, 30, 21, 56, 58, 43, 60, 40, 52, 45, 6, 47, 48, 33, 53, 51, 62, 24, 37, 61, 5, 56, 7, 23, 83, 123, 44, 56, 52, 24, 7, 23, 15]

for key in range(256):
    chars = [cts[0] ^ key]
    for i in range(1, len(cts)):
        chars.append(cts[i] ^ chars[i - 1])

    flag = ''.join(chr(c) for c in chars)
    flag = rot13(flag)

    if flag.startswith('Alpaca{'):
        print(key)
        print(flag)
        break