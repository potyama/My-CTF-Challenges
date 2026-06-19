from Crypto.Util.number import long_to_bytes
from math import isqrt


def continued_fraction(a, b):
    while b:
        q = a // b
        yield q
        a, b = b, a - q * b


def convergents(cf):
    n0, n1 = 0, 1
    d0, d1 = 1, 0
    for q in cf:
        n0, n1 = n1, q * n1 + n0
        d0, d1 = d1, q * d1 + d0
        yield n1, d1


def is_square(x):
    if x < 0:
        return False, 0
    y = isqrt(x)
    return y * y == x, y


def wiener_attack(e, n):
    for k, d in convergents(continued_fraction(e, n)):
        if k == 0:
            continue

        ed_minus_1 = e * d - 1
        if ed_minus_1 % k != 0:
            continue

        phi = ed_minus_1 // k
        s = n - phi + 1
        ok, t = is_square(s * s - 4 * n)
        if not ok:
            continue

        p = (s + t) // 2
        q = (s - t) // 2
        if p * q == n:
            return d

    raise ValueError("not found")


with open("../distfiles/output.txt") as f:
    n = int(f.readline().removeprefix("n = "))
    e = int(f.readline().removeprefix("e = "))
    c = int(f.readline().removeprefix("c = "))

d = wiener_attack(e, n)
m = pow(c, d, n)
print(long_to_bytes(m).decode())
