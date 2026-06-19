from hashlib import sha256

from sage.all import *


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

with open("../distfiles/output.txt") as f:
    p = int(f.readline().removeprefix("p = ").strip())
    a = int(f.readline().removeprefix("a = ").strip())
    b = int(f.readline().removeprefix("b = ").strip())
    Gx, Gy = map(int, f.readline().removeprefix("Gx, Gy = (").removesuffix(")\n").split(", "))
    Qx, Qy = map(int, f.readline().removeprefix("Qx, Qy = (").removesuffix(")\n").split(", "))
    ct = bytes.fromhex(f.readline().removeprefix("ct = ").strip())

E = EllipticCurve(GF(p), [a, b])
G = E(Gx, Gy)
Q = E(Qx, Qy)

secret = Q.log(G)
key = sha256(str(secret).encode()).digest()
flag = xor(ct, (key * ((len(ct) + len(key) - 1) // len(key)))[: len(ct)])

print(flag.decode())
