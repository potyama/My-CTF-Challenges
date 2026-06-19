from Crypto.Util.number import *
from sympy import factorint

with open("../distfiles/output.txt") as f:
    n = int(f.readline().removeprefix("n = "))
    e = int(f.readline().removeprefix("e = "))
    c = int(f.readline().removeprefix("c = "))

factors = list(factorint(n).keys())
p = factors[0]
q = factors[1]
phi = (p-1) * (q-1)
d = inverse(e, phi)
print(long_to_bytes(pow(c, d, n)).decode())