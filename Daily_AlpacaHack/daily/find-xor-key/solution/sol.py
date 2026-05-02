from pwn import xor

c_hex = open("../distfiles/output.txt").readline().strip()
c = bytes.fromhex(c_hex)

key_guess = xor(c, b"Alpaca{")[:7]
print(key_guess)

flag = xor(c, key_guess)
print(flag.decode())