from Crypto.Util.number import bytes_to_long, getPrime, inverse
from math import gcd


flag = b"Alpaca{REDACTED}"

while True:
    p = getPrime(512)
    q = getPrime(512)
    n = p * q
    phi = (p - 1) * (q - 1)

    d = getPrime(275)  # n^0.25 < d < n^0.292
    if gcd(d, phi) == 1:
        break

e = inverse(d, phi)
c = pow(bytes_to_long(flag), e, n)

print(f"n = {n}")
print(f"e = {e}")
print(f"c = {c}")
