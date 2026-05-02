import secrets

def rot13_char(c):
    if 'a' <= c <= 'z':
        return chr((ord(c) - ord('a') + 13) % 26 + ord('a'))
    if 'A' <= c <= 'Z':
        return chr((ord(c) - ord('A') + 13) % 26 + ord('A'))
    return c

def rot13(text):
    return ''.join(rot13_char(c) for c in text)

flag = "Alpaca{REDACTED}"

ct = rot13(flag)

key = secrets.randbelow(256)
cts = [ord(ct[0]) ^ key]
for i in range(1, len(ct)):
    cts.append(ord(ct[i]) ^ ord(ct[i - 1]))

print(cts)
