import os
import secrets
from Crypto.Util.number import isPrime, getPrime, bytes_to_long

e = 65537
D = 3
bits = 1024
FLAG = os.environ.get("FLAG", "Alpaca{REDACTED}")

while True:
    V = secrets.randbelow(max(1 << (bits - 1), (1 << bits) - 1))
    if V % 2 == 0:
        V += 1
    p = (D * V**2 + 1) // 4
    if isPrime(p):
        break

q = getPrime(bits)
if q == p:
    q = getPrime(bits)
N = p * q

m = bytes_to_long(FLAG.encode())
assert m < N
c = pow(m, e, N)

print("N =", N)
print("e =", e)
print("c =", c)
