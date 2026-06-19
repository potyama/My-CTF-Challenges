import os
from hashlib import sha256

from Crypto.Util.number import getPrime
from sage.all import EllipticCurve, GF, randint


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


flag = os.environ.get("FLAG", "Alpaca{REDACTED}").encode()

while True:
    p = getPrime(64)
    a = randint(1, p - 1)
    b = randint(1, p - 1)
    # Make sure y^2 = x^3 + ax + b is an elliptic curve over GF(p).
    if (4 * pow(a, 3, p) + 27 * pow(b, 2, p)) % p == 0:
        continue

    E = EllipticCurve(GF(p), [a, b])
    G = E.random_point()
    if G.order() >= 2**47:
        break

secret = randint(2**46, G.order() - 1)

# Can you recover secret from G and Q?
Q = secret * G

key = sha256(str(secret).encode()).digest()
ct = xor(flag, (key * ((len(flag) + len(key) - 1) // len(key)))[: len(flag)])

print(f"p = {p}")
print(f"a = {a}")
print(f"b = {b}")
print(f"Gx, Gy = {tuple(map(int, G.xy()))}")
print(f"Qx, Qy = {tuple(map(int, Q.xy()))}")
print(f"ct = {ct.hex()}")
