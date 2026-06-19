import os
from Crypto.Util.number import *


FLAG = os.environ.get("FLAG", "Alpaca{dummy}")
assert len(FLAG) < 50

p = getPrime(1024)
q = getPrime(1024)

n = p * q

e = 5 # what????????

m = bytes_to_long(FLAG.encode())
c = pow(m, e, n)

print(f"n = {n}")
print(f"e = {e}")
print(f"c = {c}")
