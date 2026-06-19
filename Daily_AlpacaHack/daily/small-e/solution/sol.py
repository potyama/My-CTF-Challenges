from sympy import root
from Crypto.Util.number import long_to_bytes

with open("../distfiles/output.txt") as f:
    n = int(f.readline().removeprefix("n = ").strip())
    e = int(f.readline().removeprefix("e = ").strip())
    c = int(f.readline().removeprefix("c = ").strip())

print(long_to_bytes(root(c, 5)).decode())
