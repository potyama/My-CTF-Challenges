from Crypto.Util.number import *


flag = bytes_to_long(b"Alpaca{DUMMY}")

p = getPrime(512)
q = getPrime(32) # what????????

n = p * q

e = 65537
c = pow(flag, e, n)

print(f"n = {n}")
print(f"e = {e}")
print(f"c = {c}")